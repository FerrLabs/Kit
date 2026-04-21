//! Rate limiting.
//!
//! Two layers:
//!
//! 1. A coarse **global** limiter applied to every request. Keeps one abusive
//!    IP from nuking the whole API.
//! 2. **Keyed** limiters for specific auth endpoints — registration, email
//!    verification, resend. Each key (IP or email) gets its own
//!    `GovernorRateLimiter`, lazily created on first hit and kept in a
//!    `DashMap`. This is what actually stops signup-flooding.
//!
//! The keyed limiters are never garbage-collected. The key space is small in
//! practice (IPs + emails of people trying to sign up) and each entry is a
//! handful of bytes. If we ever need to bound it we can swap in
//! `moka`/`quick_cache` without changing callers.

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use dashmap::DashMap;
use governor::{
    Quota, RateLimiter as GovernorRateLimiter,
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
};
use std::{
    num::NonZeroU32,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{config::RateLimitConfig, error::ApiError};

/// Window over which failed-login attempts accrue before the per-email
/// lockout clears. Matches the governor window on `login_email` so an
/// attacker can't dodge the lockout by slow-rolling attempts.
const FAILED_LOGIN_WINDOW: Duration = Duration::from_secs(15 * 60);

type SingleLimiter = Arc<GovernorRateLimiter<NotKeyed, InMemoryState, DefaultClock>>;

/// A keyed limiter: one `GovernorRateLimiter` per distinct key, with a shared
/// quota. Entries are created lazily.
#[derive(Clone)]
pub struct KeyedLimiter {
    quota: Quota,
    map: Arc<DashMap<String, SingleLimiter>>,
}

impl KeyedLimiter {
    fn new(quota: Quota) -> Self {
        Self {
            quota,
            map: Arc::new(DashMap::new()),
        }
    }

    /// Check-and-consume one token for `key`. Returns `Err(RateLimitExceeded)`
    /// when the key is over quota.
    pub fn check(&self, key: &str) -> Result<(), ApiError> {
        let entry = self
            .map
            .entry(key.to_string())
            .or_insert_with(|| {
                Arc::new(GovernorRateLimiter::new(
                    self.quota,
                    InMemoryState::default(),
                    DefaultClock::default(),
                ))
            })
            .clone();

        if entry.check().is_err() {
            Err(ApiError::RateLimitExceeded)
        } else {
            Ok(())
        }
    }
}

/// Top-level rate-limiter bundle held on `AppState`.
pub struct RateLimiters {
    pub global: SingleLimiter,

    // Register: coarse IP + per-email.
    pub register_ip: KeyedLimiter,
    pub register_email: KeyedLimiter,

    // Verify: per-email (brute-force guard on the 6-digit code).
    pub verify_email: KeyedLimiter,

    // Resend: per-email (avoid email-bombing a victim).
    pub resend_email: KeyedLimiter,

    // Password reset request: per-email + per-IP. Per-email limits
    // email-bombing; per-IP covers scripted enumeration attempts.
    pub password_reset_email: KeyedLimiter,
    pub password_reset_ip: KeyedLimiter,

    // Password reset verify: per-token-hash-prefix (brute-force guard on the
    // token). 10 attempts in 10 minutes is generous for humans and useless
    // for brute-forcing 256 bits of entropy.
    pub password_reset_verify: KeyedLimiter,

    // CSP violation reports: per-IP. Browsers can emit these in tight bursts
    // (one per blocked subresource on a page) so the cap is generous enough
    // not to drop a legitimate violation wave, but tight enough that a
    // malicious origin can't flood our log pipeline through an iframe.
    pub csp_reports: KeyedLimiter,

    // Login: coarse IP + per-email. IP stops broad credential-stuffing
    // floods; per-email slows targeted brute force against a single
    // account. Both fire before the password verify.
    pub login_ip: KeyedLimiter,
    pub login_email: KeyedLimiter,

    // Per-email failed-attempts tally, separate from the governor limiter
    // so we can surface "temporarily locked" after N bad passwords and
    // clear the count on a successful login. Entries older than
    // `FAILED_LOGIN_WINDOW` are treated as expired (count = 0).
    failed_login_counter: Arc<DashMap<String, (u32, Instant)>>,
}

impl RateLimiters {
    pub fn new(config: &RateLimitConfig) -> Self {
        let per_hour = |n: u32| {
            Quota::with_period(Duration::from_secs(3600) / n)
                .expect("non-zero quota period")
                .allow_burst(NonZeroU32::new(n).expect("non-zero burst"))
        };
        let per_ten_min = |n: u32| {
            Quota::with_period(Duration::from_secs(600) / n)
                .expect("non-zero quota period")
                .allow_burst(NonZeroU32::new(n).expect("non-zero burst"))
        };
        let per_minute = |n: u32| {
            Quota::with_period(Duration::from_secs(60) / n)
                .expect("non-zero quota period")
                .allow_burst(NonZeroU32::new(n).expect("non-zero burst"))
        };
        let per_fifteen_min = |n: u32| {
            Quota::with_period(Duration::from_secs(15 * 60) / n)
                .expect("non-zero quota period")
                .allow_burst(NonZeroU32::new(n).expect("non-zero burst"))
        };

        // Compile-time defaults; env overrides (LOGIN_RATE_LIMIT_IP /
        // LOGIN_RATE_LIMIT_EMAIL) are honoured if set and parseable.
        let login_ip_burst = std::env::var("LOGIN_RATE_LIMIT_IP")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(20);
        let login_email_burst = std::env::var("LOGIN_RATE_LIMIT_EMAIL")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(10);

        Self {
            global: Arc::new(GovernorRateLimiter::new(
                Quota::per_minute(NonZeroU32::new(config.requests_per_minute).unwrap()),
                InMemoryState::default(),
                DefaultClock::default(),
            )),
            register_ip: KeyedLimiter::new(per_hour(5)),
            register_email: KeyedLimiter::new(per_hour(3)),
            verify_email: KeyedLimiter::new(per_ten_min(10)),
            resend_email: KeyedLimiter::new(per_hour(3)),
            password_reset_email: KeyedLimiter::new(per_hour(3)),
            password_reset_ip: KeyedLimiter::new(per_hour(10)),
            password_reset_verify: KeyedLimiter::new(per_ten_min(10)),
            csp_reports: KeyedLimiter::new(per_minute(50)),
            login_ip: KeyedLimiter::new(per_fifteen_min(login_ip_burst)),
            login_email: KeyedLimiter::new(per_fifteen_min(login_email_burst)),
            failed_login_counter: Arc::new(DashMap::new()),
        }
    }

    /// Increment the failed-login counter for `email`. If the existing
    /// entry is older than `FAILED_LOGIN_WINDOW` it's treated as a fresh
    /// window. Returns the new count within the current window.
    pub fn record_failed_login(&self, email: &str) -> u32 {
        let now = Instant::now();
        let mut entry = self
            .failed_login_counter
            .entry(email.to_string())
            .or_insert((0, now));
        if now.duration_since(entry.1) > FAILED_LOGIN_WINDOW {
            *entry = (1, now);
        } else {
            entry.0 += 1;
            entry.1 = now;
        }
        entry.0
    }

    /// Drop the failed-login entry for `email`. Called on successful login.
    pub fn reset_failed_login(&self, email: &str) {
        self.failed_login_counter.remove(email);
    }

    /// Current failed-login count for `email`. Returns 0 if no entry
    /// exists or the entry is older than the window.
    pub fn failed_login_count(&self, email: &str) -> u32 {
        match self.failed_login_counter.get(email) {
            Some(entry) => {
                if Instant::now().duration_since(entry.1) > FAILED_LOGIN_WINDOW {
                    0
                } else {
                    entry.0
                }
            }
            None => 0,
        }
    }
}

pub async fn rate_limit(
    State(rate_limiters): State<Arc<RateLimiters>>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if rate_limiters.global.check().is_err() {
        return Err(ApiError::RateLimitExceeded);
    }

    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_limiters() -> RateLimiters {
        RateLimiters::new(&RateLimitConfig {
            requests_per_minute: 1000,
        })
    }

    #[test]
    fn failed_login_counter_increments_and_resets() {
        let r = empty_limiters();
        assert_eq!(r.failed_login_count("a@b.com"), 0);
        assert_eq!(r.record_failed_login("a@b.com"), 1);
        assert_eq!(r.record_failed_login("a@b.com"), 2);
        assert_eq!(r.record_failed_login("a@b.com"), 3);
        assert_eq!(r.failed_login_count("a@b.com"), 3);

        // Different email = different bucket.
        assert_eq!(r.failed_login_count("other@b.com"), 0);

        r.reset_failed_login("a@b.com");
        assert_eq!(r.failed_login_count("a@b.com"), 0);
    }

    #[test]
    fn failed_login_counter_expires_entries_after_window() {
        let r = empty_limiters();
        r.record_failed_login("old@b.com");
        r.record_failed_login("old@b.com");
        assert_eq!(r.failed_login_count("old@b.com"), 2);

        // Backdate the entry past the window.
        {
            let mut entry = r.failed_login_counter.get_mut("old@b.com").unwrap();
            entry.1 = Instant::now() - (FAILED_LOGIN_WINDOW + Duration::from_secs(1));
        }

        // Read returns 0 once expired.
        assert_eq!(r.failed_login_count("old@b.com"), 0);

        // Next record resets to 1 rather than incrementing stale count.
        assert_eq!(r.record_failed_login("old@b.com"), 1);
    }

    #[test]
    fn keyed_limiter_separates_keys() {
        let limiter = KeyedLimiter::new(
            Quota::with_period(Duration::from_secs(3600))
                .unwrap()
                .allow_burst(NonZeroU32::new(2).unwrap()),
        );
        // Two allowed per key.
        assert!(limiter.check("a").is_ok());
        assert!(limiter.check("a").is_ok());
        assert!(limiter.check("a").is_err());
        // Different key gets its own bucket.
        assert!(limiter.check("b").is_ok());
    }
}
