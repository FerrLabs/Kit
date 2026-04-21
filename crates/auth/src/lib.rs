//! Authentication primitives for FerrLabs APIs.
//!
//! One login session covers all FerrLabs products — a JWT issued here is
//! accepted by FerrFlow-Cloud, FerrVault-Cloud, and any future product.
//!
//! ## Modules
//!
//! - [`password`] — argon2id hashing + verification (implemented)
//! - [`jwt`] — access token issuance / verification (scaffold — TODO)
//! - [`jwt_middleware`] — axum extractor ported from FerrFlow-Cloud
//! - [`hmac`] — HMAC-auth for internal / service-to-service calls
//! - [`session`] — long-lived refresh sessions in Postgres (TODO)
//! - [`oauth`] — OAuth providers (Google, GitHub) (TODO)
//! - [`totp`] — 2FA seed generation and verification (TODO)
//! - [`middleware`] — re-exports the axum extractor type
//!
//! ## Integration status
//!
//! `jwt_middleware` and `hmac` modules were ported wholesale from the
//! FerrFlow-Cloud API. They still reference Application-specific types
//! (`AppState`, `SharedKeyProvider`). A follow-up PR will parameterize
//! these via traits so the crate is genuinely reusable.

pub mod hmac;
pub mod jwt;
pub mod jwt_middleware;
pub mod middleware;
pub mod oauth;
pub mod password;
pub mod session;
pub mod totp;

pub use jwt::{Claims, JwtConfig, issue_token, verify_token};
