//! Request-level observability: structured access logs, Prometheus metrics,
//! and a `X-Request-Id` correlation id.
//!
//! Sits outside every other layer in `main.rs` so even panics / early errors
//! from downstream middleware get a log line and a metric increment. The
//! upstream `tower_http::trace::TraceLayer` is preserved alongside — this
//! module adds the bits we care about (matched-route label, request id,
//! histogram buckets) without taking on a full replacement of tower-http's
//! behaviour.

use std::time::Instant;

use axum::{
    extract::{MatchedPath, Request},
    http::{HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use tracing::Instrument;
use ulid::Ulid;

use crate::metrics::{HTTP_REQUEST_DURATION_SECONDS, HTTP_REQUESTS_TOTAL};

/// Header name we use for the per-request correlation id. The lowercase form
/// is canonical for HTTP/2; axum downcases on the wire anyway.
pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

/// Extract the matched route template (e.g. `/orgs/{org_slug}/projects`) from
/// the request extensions. Falls back to the raw URI path if axum couldn't
/// match the route — that way metrics for 404s land on their real path rather
/// than a single `""` bucket, but matched handlers still collapse by template.
fn extract_matched_path(request: &Request) -> String {
    if let Some(mp) = request.extensions().get::<MatchedPath>() {
        return mp.as_str().to_string();
    }
    request.uri().path().to_string()
}

/// Global middleware: assigns a request id, emits a tracing span + info log
/// for each request, and records the two HTTP Prometheus series.
pub async fn observe(mut request: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = request.method().clone();
    let route = extract_matched_path(&request);

    // Honour an incoming `X-Request-Id` if the client sent one (useful when
    // nginx or the edge load balancer already stamps one); otherwise generate
    // a fresh ULID.
    let request_id = request
        .headers()
        .get(&REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Ulid::new().to_string());

    // Stash the id on request extensions so downstream handlers / error
    // reporters can read it without reaching back into the header map.
    request
        .extensions_mut()
        .insert(RequestId(request_id.clone()));

    let span = tracing::info_span!(
        "http",
        method = %method,
        route = %route,
        request_id = %request_id,
        user_id = tracing::field::Empty,
        org_id = tracing::field::Empty,
    );

    let mut response = next.run(request).instrument(span).await;
    let status = response.status().as_u16();
    let dur = start.elapsed().as_secs_f64();

    HTTP_REQUESTS_TOTAL
        .with_label_values(&[method.as_str(), &route, &status.to_string()])
        .inc();
    HTTP_REQUEST_DURATION_SECONDS
        .with_label_values(&[method.as_str(), &route])
        .observe(dur);

    if let Ok(val) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(REQUEST_ID_HEADER, val);
    }

    tracing::info!(
        method = %method,
        route = %route,
        status = status,
        duration_ms = (dur * 1000.0) as u64,
        request_id = %request_id,
        "request"
    );

    response
}

/// Newtype carrying the per-request id through axum's extension map. Handlers
/// that want to emit a correlated log line can `Extension<RequestId>` it.
#[derive(Debug, Clone)]
#[allow(dead_code)] // field is read via `.0` by handlers that opt into it
pub struct RequestId(pub String);

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, http::Request, middleware as axum_middleware, routing::get};
    use tower::ServiceExt;

    fn app() -> Router {
        Router::new()
            .route("/ping", get(|| async { "pong" }))
            .layer(axum_middleware::from_fn(observe))
    }

    #[tokio::test]
    async fn request_id_set_on_response_header() {
        let resp = app()
            .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let id = resp
            .headers()
            .get(&REQUEST_ID_HEADER)
            .expect("response should carry x-request-id")
            .to_str()
            .unwrap();

        // ULIDs are 26 chars of Crockford base32.
        assert_eq!(id.len(), 26);
    }

    #[tokio::test]
    async fn incoming_request_id_is_preserved() {
        let resp = app()
            .oneshot(
                Request::builder()
                    .uri("/ping")
                    .header("x-request-id", "my-upstream-id-123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            resp.headers().get(&REQUEST_ID_HEADER).unwrap(),
            "my-upstream-id-123"
        );
    }
}
