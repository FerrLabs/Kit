# _unmigrated/

Modules ported wholesale from FerrFlow-Cloud's `api/` that still reference Application-specific types and therefore don't compile standalone in the Kit workspace.

Files are kept with a `.rs.unmigrated` extension so `cargo` ignores them. They'll be promoted back to `src/*.rs` one at a time as part of [Kit#4 — parameterization](https://github.com/FerrLabs/Kit/issues/4):

- `cors.rs.unmigrated` — CORS layer (needs `CorsConfig` trait)
- `observability.rs.unmigrated` — trace/span layer (needs `AppState` decoupling)
- `rate_limit.rs.unmigrated` — rate limit + plan-aware tiers (needs `RateLimitConfig` trait)
- `security_headers.rs.unmigrated` — security header layer (needs `tls_enabled` getter trait)
