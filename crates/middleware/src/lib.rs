//! HTTP middleware layers for `FerrLabs` APIs.
//!
//! Stacked in every API's `main.rs` in this order:
//! request ID → trace → CORS → security headers → rate limit → timeout.
//!
//! ## Scaffolded
//!
//! - [`request_id`] — propagate a UUID per request (TODO)
//!
//! ## Unmigrated
//!
//! See `_unmigrated/` for the raw ports of `cors.rs`, `observability.rs`,
//! `rate_limit.rs`, `security_headers.rs` from FerrFlow-Cloud's api. They
//! still reference `crate::config::ServerConfig` / `AppState` and need to
//! be parameterized behind traits before they can be re-enabled — tracked
//! in [Kit#4](https://github.com/FerrLabs/Kit/issues/4).

pub mod request_id;
