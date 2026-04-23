//! Authentication primitives for FerrLabs APIs.
//!
//! One login session covers all FerrLabs products — a JWT issued here is
//! accepted by every product API (ferrlabs-api feature-gated endpoints,
//! FerrVault, future FerrTrack, future FerrGrowth).
//!
//! ## Implemented (M1)
//!
//! - [`password`] — argon2id hashing + verification
//! - [`jwt`] — ed25519-signed access tokens (15 min TTL by default)
//! - [`session`] — refresh sessions persisted in Postgres, with rotation
//!   and reuse-based theft detection
//!
//! ## Scaffolded (later milestones)
//!
//! - [`oauth`] — OAuth providers (GitHub, Google) — M3
//! - [`totp`] — TOTP MFA — M3
//! - [`middleware`] — axum extractor for protected routes — M1
//!
//! ## Unmigrated
//!
//! See `_unmigrated/` for the raw ports of `jwt_middleware.rs` and `hmac.rs`
//! from the old FerrFlow-Cloud API. They still reference a concrete
//! `AppState` and need to be parameterised behind traits before they can
//! be re-enabled — tracked in [Kit#4](https://github.com/FerrLabs/Kit/issues/4).

pub mod jwt;
pub mod middleware;
pub mod oauth;
pub mod password;
pub mod session;
pub mod totp;

pub use jwt::{Claims, JwtConfig, JwtError, issue_token, verify_token};
pub use password::{hash as hash_password, verify as verify_password};
pub use session::{
    DEFAULT_REFRESH_TTL, IssuedSession, PgSessionStore, Session, SessionError, SessionStore,
    generate_refresh_token, hash_refresh_token,
};
