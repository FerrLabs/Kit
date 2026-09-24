//! HTTP middleware layers for `FerrLabs` APIs.
//!
//! Stacked in every API's `main.rs` in this order:
//! request ID → trace → CORS → security headers → rate limit → timeout.
//!
//! ## Implemented
//!
//! - [`cors`] — CORS layer built from a decoupled [`cors::CorsConfig`]
//! - [`security_headers`] — defence-in-depth response headers, HSTS gated on
//!   [`security_headers::SecurityHeadersConfig::tls_enabled`]
//!
//! ## Scaffolded
//!
//! - [`request_id`] — propagate a UUID per request (TODO)
//!
//! ## Unmigrated
//!
//! The raw ports of `observability.rs` and `rate_limit.rs` from
//! FerrFlow-Cloud's api still reference `crate::config::ServerConfig` and
//! `AppState`, and need to be parameterized behind traits before they can be
//! re-enabled, tracked in [Kit#4](https://github.com/FerrLabs/Kit/issues/4).
//! They are in git history at `22f0575`, under
//! `crates/middleware/_unmigrated/`.

pub mod cors;
pub mod request_id;
pub mod security_headers;

pub use cors::{CorsConfig, CorsError, cors_layer};
pub use security_headers::{SecurityHeadersConfig, security_headers};
