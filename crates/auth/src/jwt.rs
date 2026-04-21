//! JWT access tokens for FerrLabs APIs.
//!
//! Signed with HS256 for now (single-region, single-region secret). Switch
//! to RS256 with a rotating JWKS endpoint before going multi-region.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub secret: Vec<u8>,
    pub issuer: String,
    pub ttl_seconds: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject — the user ID.
    pub sub: Uuid,
    /// Issuer — always `"ferrlabs"`.
    pub iss: String,
    /// Expiration timestamp (unix seconds).
    pub exp: i64,
    /// Issued-at timestamp (unix seconds).
    pub iat: i64,
    /// Active organization ID, if the user is acting on behalf of an org.
    pub org: Option<Uuid>,
}

pub fn issue_token(
    _config: &JwtConfig,
    _user_id: Uuid,
    _org: Option<Uuid>,
) -> anyhow::Result<String> {
    // TODO: jsonwebtoken encode
    anyhow::bail!("issue_token not yet implemented")
}

pub fn verify_token(_config: &JwtConfig, _token: &str) -> anyhow::Result<Claims> {
    // TODO: jsonwebtoken decode + validate
    anyhow::bail!("verify_token not yet implemented")
}
