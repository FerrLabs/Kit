//! Authentication primitives for FerrLabs APIs.
//!
//! One login session covers all FerrLabs products — a JWT issued here is
//! accepted by FerrFlow-Cloud, FerrVault-Cloud, and any future product.
//!
//! ## Implemented
//!
//! - [`password`] — argon2id hashing + verification
//!
//! ## Scaffolded
//!
//! - [`jwt`] — access token issuance / verification (TODO)
//! - [`session`] — long-lived refresh sessions in Postgres (TODO)
//! - [`oauth`] — OAuth providers (Google, GitHub) (TODO)
//! - [`totp`] — 2FA seed generation and verification (TODO)
//! - [`middleware`] — axum extractor (TODO)
//!
//! ## Unmigrated
//!
//! See `_unmigrated/` for the raw ports of `jwt_middleware.rs` and `hmac.rs`
//! from FerrFlow-Cloud's api. They still reference `AppState` and need to
//! be parameterized behind traits before they can be re-enabled — tracked
//! in [Kit#4](https://github.com/FerrLabs/Kit/issues/4).

pub mod jwt;
pub mod middleware;
pub mod oauth;
pub mod password;
pub mod session;
pub mod totp;

pub use jwt::{Claims, JwtConfig, issue_token, verify_token};
