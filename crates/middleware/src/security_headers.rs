//! Adds defence-in-depth security headers to every API response.
//!
//! These are belt-and-braces — the frontends (packages/app, admin, site) ship
//! their own CSP + security headers from nginx. Emitting them here as well
//! means direct API callers, embedded views, and any tooling that hits the
//! API without going through nginx still get the guarantees.
//!
//! HSTS is the one header we gate on config: sending
//! `Strict-Transport-Security` from a plain-HTTP origin pins the wrong scheme
//! in the browser for `max-age`, which bricks self-host installs that haven't
//! put a cert in front yet. Operators flip `APP_TLS_ENABLED=true` once
//! they're terminating TLS.

use axum::{
    extract::{Request, State},
    http::HeaderValue,
    middleware::Next,
    response::Response,
};

/// Input to the [`security_headers`] layer. A dedicated struct (rather than
/// reaching into [`crate::AppState`]) keeps the layer trivially unit-testable
/// and avoids a second `State<AppState>` on every request purely to read one
/// boolean.
#[derive(Clone, Copy, Debug)]
pub struct SecurityHeadersConfig {
    pub tls_enabled: bool,
}

pub async fn security_headers(
    State(config): State<SecurityHeadersConfig>,
    request: Request,
    next: Next,
) -> Response {
    let mut resp = next.run(request).await;
    let headers = resp.headers_mut();

    if config.tls_enabled {
        headers.insert(
            "Strict-Transport-Security",
            HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
        );
    }
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        "Referrer-Policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    headers.insert(
        "Permissions-Policy",
        HeaderValue::from_static("geolocation=(), microphone=(), camera=(), payment=()"),
    );
    headers.insert(
        "Cross-Origin-Opener-Policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "Cross-Origin-Resource-Policy",
        HeaderValue::from_static("same-origin"),
    );

    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, http::Request, middleware as axum_middleware, routing::get};
    use tower::ServiceExt;

    fn build_app(tls_enabled: bool) -> Router {
        let config = SecurityHeadersConfig { tls_enabled };
        Router::new()
            .route("/ping", get(|| async { "pong" }))
            .layer(axum_middleware::from_fn_with_state(
                config,
                security_headers,
            ))
    }

    #[tokio::test]
    async fn security_headers_applies_headers() {
        let resp = build_app(true)
            .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let h = resp.headers();
        assert_eq!(h.get("X-Content-Type-Options").unwrap(), "nosniff");
        assert_eq!(h.get("X-Frame-Options").unwrap(), "DENY");
        assert_eq!(
            h.get("Referrer-Policy").unwrap(),
            "strict-origin-when-cross-origin"
        );
        assert!(
            h.get("Permissions-Policy")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.contains("geolocation=()"))
        );
        assert_eq!(h.get("Cross-Origin-Opener-Policy").unwrap(), "same-origin");
        assert_eq!(
            h.get("Cross-Origin-Resource-Policy").unwrap(),
            "same-origin"
        );
    }

    #[tokio::test]
    async fn security_headers_gates_hsts_on_tls() {
        // TLS on: HSTS present.
        let resp = build_app(true)
            .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(
            resp.headers().contains_key("Strict-Transport-Security"),
            "expected HSTS when tls_enabled=true"
        );

        // TLS off: HSTS absent. Emitting HSTS over plain HTTP pins the wrong
        // scheme for `max-age` and bricks the origin in the browser.
        let resp = build_app(false)
            .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(
            !resp.headers().contains_key("Strict-Transport-Security"),
            "HSTS must not be emitted over plain HTTP"
        );
    }
}
