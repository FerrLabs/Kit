//! Common error types for FerrLabs APIs.
//!
//! Every FerrLabs Rust backend converts its errors through [`ApiError`] so
//! responses have a consistent shape (JSON body, stable error codes per
//! domain, no leaked internals).
//!
//! ## Layout
//!
//! - [`error_code`] — the stable error-code constants (part of the public
//!   API contract). Adding is safe, renaming is breaking.
//! - [`error`] — the [`ApiError`] enum, its constructors, and the
//!   [`IntoResponse`](axum::response::IntoResponse) impl.

pub mod error;
pub mod error_code;

pub use error::{ApiError, ApiResult};
