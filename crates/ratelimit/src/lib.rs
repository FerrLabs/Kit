#![forbid(unsafe_code)]
//! Token-bucket rate limiting keyed by an opaque string, plus a trusted-proxy
//! client-IP extractor.
//!
//! The limiter is generic over a [`Clock`] so tests are fully deterministic —
//! never reaches for the wall clock implicitly. An in-memory backend is
//! provided; the [`RateLimiter`] trait leaves room for a Redis-backed
//! implementation later.
//!
//! The [`client_ip`] extractor implements the standard defence against
//! `X-Forwarded-For` spoofing: trust exactly the configured number of proxy
//! hops, and ignore the header entirely when none are configured.

pub mod ip;

pub use ip::{TrustedProxies, client_ip};

use std::net::IpAddr;

use dashmap::DashMap;

/// A monotonic source of time, in seconds. Injectable so tests don't depend on
/// wall-clock timing.
pub trait Clock: Send + Sync {
    /// Seconds elapsed on a monotonic timeline. Only deltas are meaningful.
    fn now_secs(&self) -> f64;
}

/// A [`Clock`] backed by [`std::time::Instant`].
pub struct MonotonicClock {
    origin: std::time::Instant,
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self {
            origin: std::time::Instant::now(),
        }
    }
}

impl Clock for MonotonicClock {
    fn now_secs(&self) -> f64 {
        self.origin.elapsed().as_secs_f64()
    }
}

/// Configuration for a token bucket.
#[derive(Debug, Clone, Copy)]
pub struct Quota {
    pub capacity: u32,
    pub refill_per_sec: f64,
}

impl Quota {
    /// `capacity` tokens, refilling `refill_per_sec` tokens each second.
    #[must_use]
    pub fn new(capacity: u32, refill_per_sec: f64) -> Self {
        Self {
            capacity,
            refill_per_sec,
        }
    }
}

/// Abstract rate limiter so backends (in-memory now, Redis later) are swappable.
pub trait RateLimiter: Send + Sync {
    /// Attempt to consume one token for `key`. Returns `true` if allowed.
    fn check(&self, key: &str) -> bool;
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last_refill: f64,
}

/// In-memory token-bucket limiter backed by a [`DashMap`].
pub struct InMemoryRateLimiter<C: Clock = MonotonicClock> {
    quota: Quota,
    clock: C,
    buckets: DashMap<String, Bucket>,
}

impl InMemoryRateLimiter<MonotonicClock> {
    /// Construct with the default monotonic clock.
    #[must_use]
    pub fn new(quota: Quota) -> Self {
        Self::with_clock(quota, MonotonicClock::default())
    }
}

impl<C: Clock> InMemoryRateLimiter<C> {
    /// Construct with an explicit clock (use in tests for determinism).
    pub fn with_clock(quota: Quota, clock: C) -> Self {
        Self {
            quota,
            clock,
            buckets: DashMap::new(),
        }
    }

    fn try_consume(&self, key: &str, cost: f64) -> bool {
        let now = self.clock.now_secs();
        let mut entry = self.buckets.entry(key.to_owned()).or_insert(Bucket {
            tokens: f64::from(self.quota.capacity),
            last_refill: now,
        });

        let elapsed = (now - entry.last_refill).max(0.0);
        let refilled = elapsed * self.quota.refill_per_sec;
        entry.tokens = (entry.tokens + refilled).min(f64::from(self.quota.capacity));
        entry.last_refill = now;

        if entry.tokens >= cost {
            entry.tokens -= cost;
            true
        } else {
            false
        }
    }
}

impl<C: Clock> RateLimiter for InMemoryRateLimiter<C> {
    fn check(&self, key: &str) -> bool {
        self.try_consume(key, 1.0)
    }
}

/// Best-effort key for a rate-limit bucket derived from a client IP.
#[must_use]
pub fn ip_key(ip: IpAddr) -> String {
    ip.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TestClock {
        now_bits: AtomicU64,
    }

    impl TestClock {
        fn new() -> Self {
            Self {
                now_bits: AtomicU64::new(0.0f64.to_bits()),
            }
        }

        fn advance(&self, secs: f64) {
            let current = f64::from_bits(self.now_bits.load(Ordering::SeqCst));
            self.now_bits
                .store((current + secs).to_bits(), Ordering::SeqCst);
        }
    }

    impl Clock for TestClock {
        fn now_secs(&self) -> f64 {
            f64::from_bits(self.now_bits.load(Ordering::SeqCst))
        }
    }

    #[test]
    fn allows_capacity_then_blocks() {
        let clock = TestClock::new();
        let rl = InMemoryRateLimiter::with_clock(Quota::new(3, 1.0), clock);

        assert!(rl.check("a"));
        assert!(rl.check("a"));
        assert!(rl.check("a"));
        assert!(!rl.check("a"));
    }

    #[test]
    fn refills_over_time() {
        let rl = InMemoryRateLimiter::with_clock(Quota::new(2, 1.0), TestClock::new());

        assert!(rl.check("k"));
        assert!(rl.check("k"));
        assert!(!rl.check("k"));

        rl.clock.advance(1.0);
        assert!(rl.check("k"));
        assert!(!rl.check("k"));
    }

    #[test]
    fn keys_are_independent() {
        let rl = InMemoryRateLimiter::with_clock(Quota::new(1, 0.0), TestClock::new());
        assert!(rl.check("x"));
        assert!(!rl.check("x"));
        assert!(rl.check("y"));
    }

    #[test]
    fn refill_caps_at_capacity() {
        let rl = InMemoryRateLimiter::with_clock(Quota::new(2, 100.0), TestClock::new());
        assert!(rl.check("z"));
        rl.clock.advance(10.0);
        assert!(rl.check("z"));
        assert!(rl.check("z"));
        assert!(!rl.check("z"));
    }
}
