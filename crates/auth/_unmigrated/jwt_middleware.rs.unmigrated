//! Authentication middleware.
//!
//! Despite the filename, this middleware accepts **two** kinds of bearer
//! tokens:
//!
//! 1. A JWT produced by `routes::auth::login` and backed by a row in the
//!    `sessions` table. Gives the user full access (no scope restrictions).
//! 2. An API token prefixed with `fft_`, matched against the `api_tokens`
//!    table. Restricted to the scopes stored on the token row.
//!
//! The middleware puts a unified `AuthUser` into request extensions. Handlers
//! that need to enforce a specific scope can call `AuthUser::require_scope`.

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use uuid::Uuid;

use crate::AppState;
use crate::error::ApiError;
use crate::models::api_token;

/// How the current request was authenticated.
#[derive(Debug, Clone)]
pub enum AuthSource {
    /// Interactive user session (browser). Full access.
    Session { session_id: Uuid },
    /// Programmatic API token. Access is restricted to `scopes`.
    ApiToken {
        /// Kept on the enum so handlers can include it in audit log entries
        /// when they need to attribute an action to a specific token. The
        /// current code doesn't read it directly yet.
        #[allow(dead_code)]
        token_id: Uuid,
        scopes: Vec<String>,
    },
}

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub source: AuthSource,
}

impl AuthUser {
    /// Return Ok if the current auth grants the given scope. Sessions always
    /// pass. API tokens pass when their scope list contains the exact scope
    /// or the `*` wildcard.
    pub fn require_scope(&self, scope: &str) -> Result<(), ApiError> {
        match &self.source {
            AuthSource::Session { .. } => Ok(()),
            AuthSource::ApiToken { scopes, .. } => {
                if scopes.iter().any(|s| s == scope || s == "*") {
                    Ok(())
                } else {
                    Err(ApiError::Forbidden(format!(
                        "API token is missing required scope: {scope}"
                    )))
                }
            }
        }
    }

    pub fn is_session(&self) -> bool {
        matches!(self.source, AuthSource::Session { .. })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub session_id: String,
    pub exp: usize,
}

pub fn create_token(
    user_id: Uuid,
    session_id: Uuid,
    secret: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::days(7))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_string(),
        session_id: session_id.to_string(),
        exp: expiration,
    };

    jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
    )
}

pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Auth principal for **cluster identities** — an `ffclust_...` token backed
/// by a row in `clusters`. Lives alongside [`AuthUser`] rather than merged
/// into it so that the existing user-centric endpoints can keep an
/// `AuthUser` extractor that naturally refuses cluster callers. Endpoints
/// that want to opt into cluster auth extract both as `Option<AuthUser>` +
/// `Option<ClusterAuth>` and branch.
#[derive(Debug, Clone)]
pub struct ClusterAuth {
    pub cluster_id: Uuid,
    pub org_id: Uuid,
}

pub async fn jwt_auth(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());

    if let Some(stripped) = token.strip_prefix("ffclust_") {
        // Dedicated branch — never populates AuthUser. Endpoints that want to
        // accept cluster auth extract `ClusterAuth`; user-only endpoints keep
        // failing-closed on `AuthUser`.
        let _ = stripped; // silence unused in debug builds
        let cluster = authenticate_cluster_identity(&state, token, ip).await?;
        req.extensions_mut().insert(cluster);
    } else if token.starts_with("fft_") {
        let auth_user = authenticate_api_token(&state, token, ip).await?;
        req.extensions_mut().insert(auth_user);
    } else {
        let auth_user = authenticate_jwt(&state, token).await?;
        req.extensions_mut().insert(auth_user);
    };

    Ok(next.run(req).await)
}

async fn authenticate_cluster_identity(
    state: &AppState,
    token: &str,
    ip: Option<std::net::IpAddr>,
) -> Result<ClusterAuth, StatusCode> {
    let hash = crate::models::cluster::hash_identity(token);
    // Check long-lived identity_hash first (the most common path). Fall back
    // to short-lived bearer tokens (minted by the OIDC exchange) so the
    // auth middleware stays callback-free — same Bearer header, same
    // AuthSource on the request context, regardless of how the token was
    // obtained.
    let cluster = match crate::models::cluster::find_active_by_hash(&state.db_pool, &hash).await {
        Ok(Some(c)) => c,
        Ok(None) => crate::models::cluster::find_active_bearer(&state.db_pool, &hash)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .ok_or(StatusCode::UNAUTHORIZED)?,
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    // Best-effort usage recording.
    let _ = crate::models::cluster::record_usage(&state.db_pool, cluster.id, ip).await;

    Ok(ClusterAuth {
        cluster_id: cluster.id,
        org_id: cluster.org_id,
    })
}

async fn authenticate_jwt(state: &AppState, token: &str) -> Result<AuthUser, StatusCode> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let user_id: Uuid = token_data
        .claims
        .sub
        .parse()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let session_id: Uuid = token_data
        .claims
        .session_id
        .parse()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let token_hash = hash_token(token);
    let session_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sessions WHERE id = $1 AND token_hash = $2 AND expires_at > NOW())",
    )
    .bind(session_id)
    .bind(&token_hash)
    .fetch_one(&state.db_pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if !session_exists {
        return Err(StatusCode::UNAUTHORIZED);
    }

    sqlx::query("UPDATE sessions SET last_active_at = NOW() WHERE id = $1")
        .bind(session_id)
        .execute(&state.db_pool)
        .await
        .ok();

    Ok(AuthUser {
        user_id,
        source: AuthSource::Session { session_id },
    })
}

async fn authenticate_api_token(
    state: &AppState,
    token: &str,
    ip: Option<std::net::IpAddr>,
) -> Result<AuthUser, StatusCode> {
    let token_hash = api_token::hash_token(token);
    let row = api_token::find_active_by_hash(&state.db_pool, &token_hash)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Best-effort usage tracking. Failure to update is non-fatal — we don't
    // want a transient DB hiccup on the audit write to block the request.
    let _ = api_token::record_usage(&state.db_pool, row.id, ip).await;

    Ok(AuthUser {
        user_id: row.user_id,
        source: AuthSource::ApiToken {
            token_id: row.id,
            scopes: row.scopes.0,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_auth_bypasses_scope_checks() {
        let user = AuthUser {
            user_id: Uuid::new_v4(),
            source: AuthSource::Session {
                session_id: Uuid::new_v4(),
            },
        };
        assert!(user.require_scope("secrets:read").is_ok());
        assert!(user.require_scope("anything:at-all").is_ok());
    }

    #[test]
    fn api_token_enforces_exact_scope() {
        let user = AuthUser {
            user_id: Uuid::new_v4(),
            source: AuthSource::ApiToken {
                token_id: Uuid::new_v4(),
                scopes: vec!["secrets:read".into()],
            },
        };
        assert!(user.require_scope("secrets:read").is_ok());
        assert!(user.require_scope("secrets:write").is_err());
    }

    #[test]
    fn api_token_wildcard_grants_everything() {
        let user = AuthUser {
            user_id: Uuid::new_v4(),
            source: AuthSource::ApiToken {
                token_id: Uuid::new_v4(),
                scopes: vec!["*".into()],
            },
        };
        assert!(user.require_scope("secrets:read").is_ok());
        assert!(user.require_scope("tokens:write").is_ok());
    }
}
