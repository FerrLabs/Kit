//! Prometheus collectors for the API.
//!
//! Every collector is registered on a private [`REGISTRY`] (not the default
//! global one) so tests — and any other crate linked in-process — don't end up
//! double-registering the same metric. The HTTP endpoint at `/metrics` scrapes
//! this registry and renders the standard text exposition format.
//!
//! The [`record_login_failure`] helper is preserved from the pre-Prometheus
//! placeholder so existing call sites in `routes::auth` keep working without
//! a rewrite. It now routes through [`AUTH_LOGIN_ATTEMPTS_TOTAL`] with the
//! `outcome=failure, reason=<…>` label pair.

use once_cell::sync::Lazy;
use prometheus::{
    Encoder, HistogramVec, IntCounterVec, IntGauge, Registry, TextEncoder,
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry,
    register_int_gauge_with_registry,
};

/// Private registry so we don't leak into whatever the `prometheus` crate's
/// default global registry is in other test binaries.
pub static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);

/// HTTP request count. Labelled by method, matched route template, and status.
pub static HTTP_REQUESTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec_with_registry!(
        "http_requests_total",
        "Total HTTP requests processed by the API.",
        &["method", "route", "status"],
        REGISTRY
    )
    .expect("register http_requests_total")
});

/// Latency histogram. Buckets tuned for a typical JSON API (1 ms to 5 s).
pub static HTTP_REQUEST_DURATION_SECONDS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec_with_registry!(
        prometheus::HistogramOpts::new(
            "http_request_duration_seconds",
            "HTTP request latency in seconds, labelled by method and matched route.",
        )
        .buckets(vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
        ]),
        &["method", "route"],
        REGISTRY
    )
    .expect("register http_request_duration_seconds")
});

/// Login attempts. `outcome` is `success` or `failure`; `reason` is the
/// specific failure mode (or `ok` on success) so dashboards can split by cause.
pub static AUTH_LOGIN_ATTEMPTS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec_with_registry!(
        "auth_login_attempts_total",
        "Login attempts, labelled by outcome and — on failure — reason.",
        &["outcome", "reason"],
        REGISTRY
    )
    .expect("register auth_login_attempts_total")
});

#[allow(dead_code)] // reserved for session-tracking wiring; see issue #332
pub static AUTH_ACTIVE_SESSIONS: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge_with_registry!(
        "auth_active_sessions",
        "Rough count of in-flight authenticated sessions (best-effort).",
        REGISTRY
    )
    .expect("register auth_active_sessions")
});

pub static DB_POOL_IN_USE: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge_with_registry!(
        "db_pool_in_use",
        "PgPool connections currently checked out.",
        REGISTRY
    )
    .expect("register db_pool_in_use")
});

pub static DB_POOL_IDLE: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge_with_registry!(
        "db_pool_idle",
        "PgPool connections currently idle.",
        REGISTRY
    )
    .expect("register db_pool_idle")
});

/// Outgoing transactional emails. `backend` is `smtp` or `stdout`. `outcome`
/// is `enqueued` (SMTP: INSERT into outbox), `sent` (worker dispatched
/// successfully, or stdout logged), `failed` (transient failure, will retry),
/// or `permanently_failed` (max retries exhausted).
pub static EMAIL_SENT_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec_with_registry!(
        "email_sent_total",
        "Outgoing transactional emails, labelled by backend and outcome.",
        &["backend", "outcome"],
        REGISTRY
    )
    .expect("register email_sent_total")
});

/// Current pending-email depth. Refreshed by the outbox worker after each
/// tick. Zero in stdout mode (worker isn't started).
pub static EMAIL_OUTBOX_DEPTH: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge_with_registry!(
        "email_outbox_depth",
        "Number of pending emails in the outbox (not sent, not permanently failed).",
        REGISTRY
    )
    .expect("register email_outbox_depth")
});

#[allow(dead_code)] // incremented when rate_limit middleware is extended
pub static RATE_LIMIT_HITS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec_with_registry!(
        "rate_limit_hits_total",
        "Rate-limiter rejections, labelled by scope (e.g. ip, email, global).",
        &["scope"],
        REGISTRY
    )
    .expect("register rate_limit_hits_total")
});

/// Reasons a `POST /auth/login` can fail. Kept as an enum so call sites can't
/// typo the label value.
#[derive(Debug, Clone, Copy)]
pub enum LoginFailureReason {
    WrongPassword,
    UnknownEmail,
    Unverified,
    RateLimitedIp,
    RateLimitedEmail,
    Locked,
}

impl LoginFailureReason {
    fn as_str(self) -> &'static str {
        match self {
            LoginFailureReason::WrongPassword => "wrong_password",
            LoginFailureReason::UnknownEmail => "unknown_email",
            LoginFailureReason::Unverified => "unverified",
            LoginFailureReason::RateLimitedIp => "rate_limited_ip",
            LoginFailureReason::RateLimitedEmail => "rate_limited_email",
            LoginFailureReason::Locked => "locked",
        }
    }
}

/// Preserved from the old placeholder. Backed by the Prometheus counter now —
/// the label shape has changed (`outcome="failure", reason=<…>` instead of
/// a top-level `auth_login_failures_total{reason=…}`) but call sites don't
/// need to know.
pub fn record_login_failure(reason: LoginFailureReason) {
    AUTH_LOGIN_ATTEMPTS_TOTAL
        .with_label_values(&["failure", reason.as_str()])
        .inc();
}

#[allow(dead_code)] // pair of `record_login_failure`; call site to follow
pub fn record_login_success() {
    AUTH_LOGIN_ATTEMPTS_TOTAL
        .with_label_values(&["success", "ok"])
        .inc();
}

/// Encode the full registry as a Prometheus text-format document, ready to be
/// served on `GET /metrics`.
pub fn gather_metrics() -> String {
    let encoder = TextEncoder::new();
    let families = REGISTRY.gather();
    let mut buf = Vec::new();
    // `encode` only fails on IO errors against the writer; writing into a
    // Vec<u8> is infallible, so unwrapping is safe.
    encoder
        .encode(&families, &mut buf)
        .expect("prometheus text encode into Vec<u8> cannot fail");
    String::from_utf8(buf).expect("prometheus text encoder emits ASCII")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counter_value(outcome: &str, reason: &str) -> u64 {
        AUTH_LOGIN_ATTEMPTS_TOTAL
            .with_label_values(&[outcome, reason])
            .get()
    }

    #[test]
    fn login_failure_counter_increments() {
        let before = counter_value("failure", "wrong_password");
        record_login_failure(LoginFailureReason::WrongPassword);
        record_login_failure(LoginFailureReason::WrongPassword);
        let after = counter_value("failure", "wrong_password");
        assert_eq!(after - before, 2);
    }

    #[test]
    fn distinct_reasons_have_distinct_series() {
        let snap = |reason: &str| counter_value("failure", reason);
        let before = [
            snap("unknown_email"),
            snap("unverified"),
            snap("rate_limited_ip"),
            snap("rate_limited_email"),
            snap("locked"),
        ];

        record_login_failure(LoginFailureReason::UnknownEmail);
        record_login_failure(LoginFailureReason::Unverified);
        record_login_failure(LoginFailureReason::RateLimitedIp);
        record_login_failure(LoginFailureReason::RateLimitedEmail);
        record_login_failure(LoginFailureReason::Locked);

        let after = [
            snap("unknown_email"),
            snap("unverified"),
            snap("rate_limited_ip"),
            snap("rate_limited_email"),
            snap("locked"),
        ];

        for (b, a) in before.iter().zip(after.iter()) {
            assert_eq!(a - b, 1);
        }
    }

    #[test]
    fn gather_metrics_emits_text_exposition() {
        // Touch a couple of collectors so the output isn't empty.
        HTTP_REQUESTS_TOTAL
            .with_label_values(&["GET", "/livez", "200"])
            .inc();
        record_login_success();

        let text = gather_metrics();
        assert!(text.contains("# HELP http_requests_total"));
        assert!(text.contains("# TYPE http_requests_total counter"));
        assert!(text.contains("auth_login_attempts_total"));
    }
}
