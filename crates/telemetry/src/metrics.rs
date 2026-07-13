//! Prometheus HTTP metrics for FerrLabs APIs (`metrics` feature).
//!
//! A private [`Registry`] holds the request counter, latency histogram, and DB
//! pool gauges every FerrLabs service exposes. [`track`] is an axum middleware
//! that records the two HTTP series per request (labelled by method, matched
//! route template, and status); [`serve`] runs a self-contained `/metrics`
//! server on a separate listener so the endpoint is never routed through the
//! public API ingress. Services register their own extra collectors on
//! [`registry`].
//!
//! The `service="<name>"` label the dashboards select on is added by Prometheus
//! at scrape time (`relabel_configs`), not here — the same binary can run under
//! any service name without a rebuild.

use std::net::SocketAddr;
use std::sync::LazyLock;
use std::time::Instant;

use axum::{
    Router,
    extract::{MatchedPath, Request},
    http::{HeaderMap, HeaderValue, StatusCode, header::CONTENT_TYPE},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
};
use prometheus::{
    Encoder, HistogramVec, IntCounterVec, IntGauge, Registry, TextEncoder,
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry,
    register_int_gauge_with_registry,
};

/// Private registry — kept off the `prometheus` global so multiple in-process
/// consumers (and test binaries) don't double-register the same metric.
static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::new);

/// HTTP request count, labelled by method, matched route template, and status.
static HTTP_REQUESTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec_with_registry!(
        "http_requests_total",
        "Total HTTP requests processed by the API.",
        &["method", "route", "status"],
        REGISTRY
    )
    .expect("register http_requests_total")
});

/// Latency histogram, labelled by method and matched route. Buckets tuned for a
/// typical JSON API (1 ms to 5 s).
static HTTP_REQUEST_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
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

static DB_POOL_IN_USE: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge_with_registry!(
        "db_pool_in_use",
        "Database pool connections currently checked out.",
        REGISTRY
    )
    .expect("register db_pool_in_use")
});

static DB_POOL_IDLE: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge_with_registry!(
        "db_pool_idle",
        "Database pool connections currently idle.",
        REGISTRY
    )
    .expect("register db_pool_idle")
});

/// The private registry, so a service can register its own extra collectors
/// (e.g. `auth_login_attempts_total`) and have them appear on the same
/// `/metrics` output.
#[must_use]
pub fn registry() -> &'static Registry {
    &REGISTRY
}

/// Record one completed HTTP request against both HTTP series.
pub fn record_request(method: &str, route: &str, status: u16, duration_secs: f64) {
    let status = status.to_string();
    HTTP_REQUESTS_TOTAL
        .with_label_values(&[method, route, &status])
        .inc();
    HTTP_REQUEST_DURATION_SECONDS
        .with_label_values(&[method, route])
        .observe(duration_secs);
}

/// Publish the current DB pool utilisation. Call after acquiring/releasing, or
/// on a periodic tick, from the service's pool.
pub fn set_db_pool(in_use: i64, idle: i64) {
    DB_POOL_IN_USE.set(in_use);
    DB_POOL_IDLE.set(idle);
}

/// Encode the whole registry as a Prometheus text-exposition document.
pub fn gather() -> String {
    let encoder = TextEncoder::new();
    let families = REGISTRY.gather();
    let mut buf = Vec::new();
    // Encoding into a `Vec<u8>` is infallible (no IO), so the unwrap can't fire.
    encoder
        .encode(&families, &mut buf)
        .expect("prometheus text encode into Vec<u8> cannot fail");
    String::from_utf8(buf).expect("prometheus text exposition is valid UTF-8")
}

// --- axum integration ---

/// Prometheus text exposition media type, pinned to the version the
/// `prometheus` crate emits.
const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Global middleware: times each request and records the two HTTP series,
/// labelling by method, matched route template, and status. Add it to the
/// application router with `.layer(axum::middleware::from_fn(track))`.
pub async fn track(request: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = request.method().clone();
    // Prefer the matched route template (`/agents/{id}`) so metric cardinality
    // stays bounded; fall back to the raw path for unmatched requests (404s)
    // rather than collapsing them all into one empty bucket.
    let route = request.extensions().get::<MatchedPath>().map_or_else(
        || request.uri().path().to_string(),
        |mp| mp.as_str().to_string(),
    );

    let response = next.run(request).await;

    record_request(
        method.as_str(),
        &route,
        response.status().as_u16(),
        start.elapsed().as_secs_f64(),
    );
    response
}

/// A self-contained router exposing `GET /metrics`. When `token` is a non-empty
/// string, scrapers must send `Authorization: Bearer <token>`; otherwise the
/// endpoint is open (safe when bound to a private, non-ingress port).
pub fn metrics_router(token: Option<String>) -> Router {
    let token = token
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty());
    Router::new().route(
        "/metrics",
        get({
            let token = token.clone();
            move |headers: HeaderMap| {
                let token = token.clone();
                async move {
                    if let Some(expected) = token {
                        let authorized = headers
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|s| s.strip_prefix("Bearer "))
                            .is_some_and(|got| ct_eq(got.as_bytes(), expected.as_bytes()));
                        if !authorized {
                            return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
                        }
                    }
                    (
                        [(
                            CONTENT_TYPE,
                            HeaderValue::from_static(PROMETHEUS_CONTENT_TYPE),
                        )],
                        gather(),
                    )
                        .into_response()
                }
            }
        }),
    )
}

/// Bind `addr` and serve [`metrics_router`] on it. Run this on a dedicated,
/// non-ingress port (e.g. `0.0.0.0:9100`) so `/metrics` is only reachable by
/// the in-cluster Prometheus, never through the public API host.
pub async fn serve(addr: SocketAddr, token: Option<String>) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, metrics_router(token)).await
}

/// Constant-time byte comparison so a wrong bearer token can't be recovered by
/// timing the 401. Length is allowed to leak (standard for MAC/token compares).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_request_increments_the_counter_series() {
        // Unique route so the series is isolated from other (parallel) tests.
        record_request("GET", "/tdd-req-a", 200, 0.01);
        let text = gather();
        assert!(
            text.contains(r#"http_requests_total{method="GET",route="/tdd-req-a",status="200"} 1"#),
            "counter series missing/miscounted:\n{text}"
        );
    }

    #[test]
    fn record_request_feeds_the_duration_histogram() {
        record_request("POST", "/tdd-dur-a", 201, 0.2);
        let text = gather();
        assert!(
            text.contains(
                r#"http_request_duration_seconds_bucket{method="POST",route="/tdd-dur-a""#
            ),
            "duration histogram buckets missing for the route:\n{text}"
        );
    }

    #[test]
    fn gather_emits_help_and_type_headers() {
        record_request("GET", "/tdd-help-a", 200, 0.01);
        let text = gather();
        assert!(text.contains("# HELP http_requests_total"), "{text}");
        assert!(
            text.contains("# TYPE http_requests_total counter"),
            "{text}"
        );
        assert!(
            text.contains("# TYPE http_request_duration_seconds histogram"),
            "{text}"
        );
    }

    #[test]
    fn set_db_pool_is_reflected_in_gather() {
        // Only this test touches the db_pool gauges, so the absolute values are
        // deterministic even under parallel test execution.
        set_db_pool(7, 11);
        let text = gather();
        assert!(text.contains("db_pool_in_use 7"), "{text}");
        assert!(text.contains("db_pool_idle 11"), "{text}");
    }

    use axum::{
        body::{Body, to_bytes},
        http::{Request as HttpRequest, StatusCode},
        middleware::from_fn,
        routing::get,
    };
    use tower::ServiceExt as _;

    #[tokio::test]
    async fn track_records_the_matched_route_template_not_the_raw_path() {
        let app = Router::new()
            .route("/tdd-b/{id}", get(|| async { "ok" }))
            .layer(from_fn(track));

        app.oneshot(
            HttpRequest::builder()
                .uri("/tdd-b/42")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        let text = gather();
        assert!(
            text.contains(r#"route="/tdd-b/{id}""#),
            "expected the route template, got:\n{text}"
        );
        assert!(
            !text.contains(r#"route="/tdd-b/42""#),
            "raw path leaked as a label (cardinality bomb):\n{text}"
        );
    }

    #[tokio::test]
    async fn metrics_router_serves_the_exposition_on_get_metrics() {
        record_request("GET", "/tdd-router", 200, 0.01);
        let resp = metrics_router(None)
            .oneshot(
                HttpRequest::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.starts_with("text/plain"),
            "unexpected content-type: {ct}"
        );
        let body = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("http_requests_total"));
    }

    #[tokio::test]
    async fn metrics_router_with_token_requires_a_matching_bearer() {
        let router = || metrics_router(Some("s3cr3t".to_string()));

        let unauth = router()
            .oneshot(
                HttpRequest::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

        let ok = router()
            .oneshot(
                HttpRequest::builder()
                    .uri("/metrics")
                    .header("authorization", "Bearer s3cr3t")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
    }
}
