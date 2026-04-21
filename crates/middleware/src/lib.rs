//! HTTP middleware layers for FerrLabs APIs.
//!
//! Stacked in every API's `main.rs` in this order:
//! request ID → trace → CORS → security headers → rate limit → timeout.
//!
//! ## Integration status
//!
//! Modules were ported wholesale from the FerrFlow-Cloud API. Most still
//! reference Application-specific config types (e.g. `ServerConfig`,
//! `RateLimitConfig`). A follow-up PR will generalize those via trait
//! boundaries so the middleware is genuinely reusable.

pub mod cors;
pub mod observability;
pub mod rate_limit;
pub mod request_id;
pub mod security_headers;
