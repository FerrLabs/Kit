# ferrlabs-api-version

Date-based API contract versioning for [axum](https://github.com/tokio-rs/axum). A client says which
contract it speaks in a header, the server serves that contract, and the URL prefix never has to
become `/v2`.

```rust
use ferrlabs_api_version::{ApiVersion, ApiVersionContext, negotiate};
use axum::{Router, middleware};

let current = ApiVersion::from_ymd(2026, 8, 4).expect("calendar date");
let ctx = ApiVersionContext::new("x-acme-api-version", current, current)
    .expect("valid header name and bounds");

let app: Router = Router::new()
    // ... your routes ...
    .layer(middleware::from_fn_with_state(ctx, negotiate));
```

## Why a date rather than `/v1`

A path prefix versions the whole surface at once, so one changed response shape forces every route
to `/v2` and every client to migrate in a single step. A date versions the contract, so a client
pins the day it was written against and keeps working while the API moves on.

The header carries the version, `x-api-version-served` comes back on every response, and a caller
that sends nothing resolves to the oldest supported contract rather than the newest. That last part
is deliberate: a header-less caller must never be silently upgraded the day the current version
moves.

## Transforms

A contract change is expressed as a `Transform` registered for a version range and a route. Old
callers get the old shape, rendered on the way out:

```rust
use ferrlabs_api_version::{Transform, TransformRegistry};
use serde_json::Value;

struct LabelWasName;

impl Transform for LabelWasName {
    fn downgrade_response(&self, body: &mut Value) {
        if let Some(label) = body.get("label").cloned() {
            body["name"] = label;
            body.as_object_mut().map(|map| map.remove("label"));
        }
    }
}

let registry = TransformRegistry::new();
let ctx = ctx.with_registry(registry);
```

A request whose version needs no rewriting takes a fast path: nothing is buffered and nothing is
deserialized, so streaming responses and large bodies are untouched. Only a caller in the past pays.

## Rejections

- A version newer than the build serves gets refused rather than clamped down to the current one.
- A version older than the floor gets `410 Gone` rather than silently served as current.
- A value that is not a calendar date gets refused rather than falling back to a default.

## Status

Part of [FerrLabs Kit](https://github.com/FerrLabs/Kit), in production across six APIs. MPL-2.0.
