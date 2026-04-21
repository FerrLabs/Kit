//! HTTP middleware layers for FerrLabs APIs.
//!
//! Each API mounts a standard stack: request ID → trace → CORS → security
//! headers → rate limit → timeout. This crate exposes the layers so every
//! API's `main.rs` applies the same defaults.

pub mod cors;
pub mod rate_limit;
pub mod request_id;
pub mod security_headers;

// TODO: compose_layers() fn returning a tower::Layer that stacks everything.
