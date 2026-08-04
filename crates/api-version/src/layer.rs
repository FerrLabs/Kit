//! The middleware: resolve, then rewrite only when there is something to rewrite.

use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{HeaderMap, Method};
use serde_json::Value;

use crate::policy::{ApiVersionContext, PinnedApiVersion, VersionRejection, response_header};

/// Header naming the version actually served, on every answer.
///
/// A client that pinned nothing can read what it is being given without
/// guessing, which is what turns a silent contract drift into something
/// visible in a single `curl -i`.
pub const SERVED_HEADER: &str = "x-api-version-served";

/// Negotiate the contract version for one request.
///
/// Wire it in with axum's `from_fn_with_state`:
///
/// ```ignore
/// use axum::middleware::from_fn_with_state;
/// use ferrlabs_api_version::{negotiate, ApiVersionContext};
///
/// let router = router.layer(from_fn_with_state(ctx.clone(), negotiate));
/// ```
///
/// Place it *after* whatever inserts [`PinnedApiVersion`], so the pin is
/// visible here.
///
/// A caller already speaking the current contract — the overwhelmingly common
/// case — is passed straight through: no body is buffered and nothing is
/// deserialized. Only a caller in the past pays.
pub async fn negotiate(
    State(ctx): State<ApiVersionContext>,
    mut req: Request,
    next: Next,
) -> Response {
    let pinned = req.extensions().get::<PinnedApiVersion>().copied();
    let version = match ctx.resolve(req.headers(), pinned) {
        Ok(version) => version,
        Err(rejection) => return rejection.into_response(),
    };

    // The matched path template, so a transform can claim `/agents/{id}`
    // rather than pattern-match concrete ids. Falls back to the raw path for
    // requests that never reached a route.
    let route = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map_or_else(
            || req.uri().path().to_owned(),
            |matched| matched.as_str().to_owned(),
        );
    let method = req.method().clone();

    req.extensions_mut().insert(version);

    let rewrites = ctx.registry().touches(version, &route, &method);
    if !rewrites {
        let mut res = next.run(req).await;
        res.headers_mut()
            .insert(SERVED_HEADER, response_header(version));
        return res;
    }

    let req = match rewrite_request(&ctx, version, &route, &method, req).await {
        Ok(req) => req,
        Err(rejection) => return rejection.into_response(),
    };

    let res = next.run(req).await;
    let mut res = match rewrite_response(&ctx, version, &route, &method, res).await {
        Ok(res) => res,
        Err(rejection) => return rejection.into_response(),
    };
    res.headers_mut()
        .insert(SERVED_HEADER, response_header(version));
    res
}

async fn rewrite_request(
    ctx: &ApiVersionContext,
    version: crate::ApiVersion,
    route: &str,
    method: &Method,
    req: Request,
) -> Result<Request, VersionRejection> {
    if !is_json(req.headers()) {
        return Ok(req);
    }
    let (mut parts, body) = req.into_parts();
    let bytes = to_bytes(body, ctx.max_body_bytes())
        .await
        .map_err(|_| VersionRejection::NotTransformable)?;
    if bytes.is_empty() {
        return Ok(Request::from_parts(parts, Body::from(bytes)));
    }
    let Ok(mut value) = serde_json::from_slice::<Value>(&bytes) else {
        // Not our business to reject: the handler's own extractor will
        // produce a better error than we can from here.
        return Ok(Request::from_parts(parts, Body::from(bytes)));
    };
    ctx.registry()
        .upgrade_request(version, route, method, &mut value);
    let bytes = serde_json::to_vec(&value).map_err(|_| VersionRejection::NotTransformable)?;
    set_content_length(&mut parts.headers, bytes.len());
    Ok(Request::from_parts(parts, Body::from(bytes)))
}

async fn rewrite_response(
    ctx: &ApiVersionContext,
    version: crate::ApiVersion,
    route: &str,
    method: &Method,
    res: Response,
) -> Result<Response, VersionRejection> {
    // Streams are out of scope by construction: a transform rewrites a whole
    // document, and there is no whole document to rewrite. Server-sent events
    // and any other non-JSON payload pass through untouched, and the routes
    // that serve them are simply not versioned.
    if !is_json(res.headers()) {
        return Ok(res);
    }
    let (mut parts, body) = res.into_parts();
    let bytes = to_bytes(body, ctx.max_body_bytes())
        .await
        // Over the cap, or a body that failed mid-stream. Serving the current
        // shape to a client that asked for an older one would be a silent
        // contract violation, which is worse than an error it can see.
        .map_err(|_| VersionRejection::NotTransformable)?;
    if bytes.is_empty() {
        return Ok(Response::from_parts(parts, Body::from(bytes)));
    }
    let Ok(mut value) = serde_json::from_slice::<Value>(&bytes) else {
        return Ok(Response::from_parts(parts, Body::from(bytes)));
    };
    ctx.registry()
        .downgrade_response(version, route, method, &mut value);
    let bytes = serde_json::to_vec(&value).map_err(|_| VersionRejection::NotTransformable)?;
    set_content_length(&mut parts.headers, bytes.len());
    Ok(Response::from_parts(parts, Body::from(bytes)))
}

fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            let value = value.trim().to_ascii_lowercase();
            value.starts_with("application/json") || value.starts_with("application/problem+json")
        })
}

fn set_content_length(headers: &mut HeaderMap, len: usize) {
    // Rewriting changes the length; leaving the old one behind truncates the
    // body at the client.
    if let Ok(value) = http::HeaderValue::from_str(&len.to_string()) {
        headers.insert(CONTENT_LENGTH, value);
    } else {
        headers.remove(CONTENT_LENGTH);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ApiVersion, Transform, TransformRegistry};
    use axum::Router;
    use axum::routing::{get, post};
    use http::StatusCode;
    use serde_json::json;
    use tower::ServiceExt;

    fn version(raw: &str) -> ApiVersion {
        raw.parse().unwrap()
    }

    /// The change that landed on 2026-09-01: `label` replaced `name`.
    struct RenamedNameToLabel;

    impl Transform for RenamedNameToLabel {
        fn version(&self) -> ApiVersion {
            version("2026-09-01")
        }
        fn applies_to(&self, route: &str, _method: &Method) -> bool {
            route.starts_with("/agents")
        }
        fn downgrade_response(&self, body: &mut Value) {
            if let Some(label) = body.get("label").cloned() {
                body["name"] = label;
                body.as_object_mut().map(|map| map.remove("label"));
            }
        }
        fn upgrade_request(&self, body: &mut Value) {
            if let Some(name) = body.get("name").cloned() {
                body["label"] = name;
                body.as_object_mut().map(|map| map.remove("name"));
            }
        }
    }

    fn app() -> Router {
        let ctx = ApiVersionContext::new(
            "x-ferrfleet-api-version",
            version("2026-10-01"),
            version("2026-01-01"),
        )
        .unwrap()
        .with_registry(TransformRegistry::new().with(RenamedNameToLabel))
        .with_default(version("2026-01-01"));

        Router::new()
            .route(
                "/agents",
                get(|| async { axum::Json(json!({"label": "pr"})) }),
            )
            .route(
                "/agents/echo",
                post(|body: axum::Json<Value>| async move { axum::Json(body.0) }),
            )
            .route(
                "/stream",
                get(|| async {
                    (
                        [(CONTENT_TYPE, "text/event-stream")],
                        "data: {\"label\":\"pr\"}\n\n",
                    )
                }),
            )
            .layer(axum::middleware::from_fn_with_state(ctx, negotiate))
    }

    async fn body_json(res: Response) -> Value {
        let bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn get_request(version: Option<&str>) -> Request {
        let mut builder = Request::builder().uri("/agents");
        if let Some(version) = version {
            builder = builder.header("x-ferrfleet-api-version", version);
        }
        builder.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn a_current_client_gets_the_current_shape() {
        let res = app()
            .oneshot(get_request(Some("2026-10-01")))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers().get(SERVED_HEADER).unwrap(),
            &http::HeaderValue::from_static("2026-10-01")
        );
        assert_eq!(body_json(res).await, json!({"label": "pr"}));
    }

    #[tokio::test]
    async fn a_client_from_before_the_change_gets_the_old_shape() {
        let res = app()
            .oneshot(get_request(Some("2026-08-01")))
            .await
            .unwrap();
        assert_eq!(body_json(res).await, json!({"name": "pr"}));
    }

    /// The transform boundary is exclusive: a client pinned *at* the change
    /// already speaks the new shape.
    #[tokio::test]
    async fn the_pin_at_the_change_itself_is_current() {
        let res = app()
            .oneshot(get_request(Some("2026-09-01")))
            .await
            .unwrap();
        assert_eq!(body_json(res).await, json!({"label": "pr"}));
    }

    #[tokio::test]
    async fn a_caller_that_sends_nothing_gets_the_oldest_contract() {
        let res = app().oneshot(get_request(None)).await.unwrap();
        assert_eq!(body_json(res).await, json!({"name": "pr"}));
    }

    #[tokio::test]
    async fn request_bodies_are_carried_forward() {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/agents/echo")
            .header("x-ferrfleet-api-version", "2026-08-01")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"name":"pr"}"#))
            .unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        // Upgraded to `label` on the way in, handed back as `name` on the way
        // out: the old client never sees the new spelling in either direction.
        assert_eq!(body_json(res).await, json!({"name": "pr"}));
    }

    #[tokio::test]
    async fn streams_pass_through_untouched() {
        let req = Request::builder()
            .uri("/stream")
            .header("x-ferrfleet-api-version", "2026-08-01")
            .body(Body::empty())
            .unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
        assert_eq!(&bytes[..], b"data: {\"label\":\"pr\"}\n\n");
    }

    #[tokio::test]
    async fn a_malformed_version_is_refused_before_the_handler_runs() {
        let res = app().oneshot(get_request(Some("3.36.0"))).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(res).await["error"], "invalid_api_version");
    }

    #[tokio::test]
    async fn a_sunset_version_is_gone() {
        let res = app()
            .oneshot(get_request(Some("2025-06-01")))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::GONE);
        assert_eq!(body_json(res).await["error"], "sunset_api_version");
    }

    #[tokio::test]
    async fn a_future_version_is_refused() {
        let res = app()
            .oneshot(get_request(Some("2027-01-01")))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(res).await["error"], "unknown_api_version");
    }

    /// Rewriting changes the length; a stale `content-length` truncates the
    /// body at the client, which is the kind of bug that looks like corrupted
    /// JSON far from its cause.
    #[tokio::test]
    async fn content_length_follows_the_rewrite() {
        let res = app()
            .oneshot(get_request(Some("2026-08-01")))
            .await
            .unwrap();
        let declared: usize = res
            .headers()
            .get(CONTENT_LENGTH)
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
        assert_eq!(declared, bytes.len());
    }
}
