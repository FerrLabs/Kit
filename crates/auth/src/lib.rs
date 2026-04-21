//! Authentication primitives for FerrLabs APIs.
//!
//! One login session covers all FerrLabs products — a JWT issued here is
//! accepted by FerrFlow-Cloud, FerrVault-Cloud, and any future product.
//!
//! ## Modules
//!
//! - [`password`] — argon2id hashing + verification
//! - [`jwt`] — issuing and verifying signed access tokens
//! - [`session`] — long-lived refresh sessions stored in Postgres
//! - [`oauth`] — OAuth providers (Google, GitHub)
//! - [`totp`] — 2FA seed generation and verification
//! - [`middleware`] — axum extractor to pull the authenticated user

pub mod jwt;
pub mod middleware;
pub mod oauth;
pub mod password;
pub mod session;
pub mod totp;

pub use jwt::{Claims, JwtConfig, issue_token, verify_token};
