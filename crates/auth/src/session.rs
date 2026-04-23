//! Refresh sessions stored in Postgres.
//!
//! A **session** is the long-lived counterpart to the short-lived JWT access
//! token. It lives in the `sessions` table, is keyed by a random 32-byte
//! refresh token, and lasts 14 days by default.
//!
//! ## Rotation and theft detection
//!
//! Every time a refresh token is used, it is **rotated** — a new refresh
//! token is issued and the old one is marked used. All sessions sharing the
//! same `family_id` form a chain of rotations.
//!
//! If a refresh token is ever presented *after* it has been rotated out,
//! that is taken as evidence of token theft: the whole family is revoked,
//! forcing the attacker *and* the legitimate user to re-authenticate.
//! This is the standard OAuth 2.0 refresh-rotation defence.
//!
//! ## Storage
//!
//! Refresh tokens are **never** stored in plaintext. Only SHA-256 hashes
//! are persisted. The plaintext token is returned exactly once, from
//! [`SessionStore::create`] or [`SessionStore::rotate`].

use std::time::Duration;

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Default refresh-token lifetime: 14 days.
pub const DEFAULT_REFRESH_TTL: Duration = Duration::from_secs(14 * 24 * 60 * 60);

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("session not found")]
    NotFound,
    #[error("session has expired")]
    Expired,
    #[error("session was revoked")]
    Revoked,
    #[error("refresh token reuse detected — family revoked")]
    ReuseDetected,
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
}

/// A persisted refresh session.
#[derive(Debug, Clone)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    /// All rotations of a single login share the same `family_id`. When any
    /// member of the family is compromised, the whole family is revoked.
    pub family_id: Uuid,
    pub refresh_token_hash: Vec<u8>,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
}

/// Result of [`SessionStore::create`] or [`SessionStore::rotate`].
///
/// The plaintext refresh token is returned **once**; callers must hand it
/// straight to the client and never store it themselves.
#[derive(Debug, Clone)]
pub struct IssuedSession {
    pub session: Session,
    pub refresh_token_plain: String,
}

/// Trait-object interface to a session store.
///
/// Tests use a mock impl; production uses [`PgSessionStore`].
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Start a brand-new session (new `family_id`). Called on login/signup.
    async fn create(
        &self,
        user_id: Uuid,
        user_agent: Option<String>,
        ip: Option<String>,
        refresh_ttl: Duration,
    ) -> Result<IssuedSession, SessionError>;

    /// Rotate an active refresh token. Returns a fresh session in the same
    /// family with a new refresh token. If the presented token was already
    /// rotated, revokes the family and returns [`SessionError::ReuseDetected`].
    async fn rotate(
        &self,
        refresh_token_plain: &str,
        refresh_ttl: Duration,
    ) -> Result<IssuedSession, SessionError>;

    /// Revoke every session in the given family (e.g. on explicit logout).
    async fn revoke_family(&self, family_id: Uuid) -> Result<(), SessionError>;

    /// Look up the active session behind a refresh token without rotating.
    /// Returns [`SessionError::NotFound`] if the token is unknown, expired,
    /// revoked, or already rotated.
    async fn get_active(&self, refresh_token_plain: &str) -> Result<Session, SessionError>;
}

/// Hash a plaintext refresh token for storage.
///
/// SHA-256 is fine here because the token is already 32 bytes of CSPRNG
/// entropy — we do not need argon2-level stretching.
#[must_use]
pub fn hash_refresh_token(plaintext: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(plaintext.as_bytes());
    hasher.finalize().to_vec()
}

/// Generate a fresh 32-byte refresh token, URL-safe base64-encoded.
#[must_use]
pub fn generate_refresh_token() -> String {
    let bytes: [u8; 32] = rand::random();
    URL_SAFE_NO_PAD.encode(bytes)
}

// -----------------------------------------------------------------------------
// Postgres implementation
// -----------------------------------------------------------------------------

/// Session store backed by a sqlx Postgres pool.
///
/// Expects the schema from `FerrLabs-Cloud` migration `0002_create_sessions.sql`:
///
/// ```sql
/// CREATE TABLE sessions (
///   id                  uuid PRIMARY KEY,
///   user_id             uuid NOT NULL,
///   family_id           uuid NOT NULL,
///   refresh_token_hash  bytea NOT NULL,
///   user_agent          text,
///   ip                  text,
///   created_at          timestamptz NOT NULL DEFAULT now(),
///   last_used_at        timestamptz NOT NULL DEFAULT now(),
///   revoked_at          timestamptz,
///   expires_at          timestamptz NOT NULL
/// );
/// ```
#[derive(Clone)]
pub struct PgSessionStore {
    pool: sqlx::PgPool,
}

impl PgSessionStore {
    #[must_use]
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SessionStore for PgSessionStore {
    async fn create(
        &self,
        user_id: Uuid,
        user_agent: Option<String>,
        ip: Option<String>,
        refresh_ttl: Duration,
    ) -> Result<IssuedSession, SessionError> {
        let refresh_token = generate_refresh_token();
        let refresh_hash = hash_refresh_token(&refresh_token);
        let id = Uuid::new_v4();
        let family_id = Uuid::new_v4();
        let now = Utc::now();
        let expires_at = now
            + chrono::Duration::from_std(refresh_ttl)
                .unwrap_or_else(|_| chrono::Duration::days(14));

        sqlx::query(
            "INSERT INTO sessions \
             (id, user_id, family_id, refresh_token_hash, user_agent, ip, created_at, last_used_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8)",
        )
        .bind(id)
        .bind(user_id)
        .bind(family_id)
        .bind(&refresh_hash)
        .bind(&user_agent)
        .bind(&ip)
        .bind(now)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        Ok(IssuedSession {
            session: Session {
                id,
                user_id,
                family_id,
                refresh_token_hash: refresh_hash,
                user_agent,
                ip,
                created_at: now,
                last_used_at: now,
                revoked_at: None,
                expires_at,
            },
            refresh_token_plain: refresh_token,
        })
    }

    async fn rotate(
        &self,
        refresh_token_plain: &str,
        refresh_ttl: Duration,
    ) -> Result<IssuedSession, SessionError> {
        let hash = hash_refresh_token(refresh_token_plain);
        let mut tx = self.pool.begin().await?;

        // Look up the row matching this hash across ALL sessions — we need
        // to distinguish "unknown token" from "known but already rotated".
        let row: Option<(
            Uuid,
            Uuid,
            Uuid,
            Option<DateTime<Utc>>,
            DateTime<Utc>,
            DateTime<Utc>,
        )> = sqlx::query_as(
            "SELECT id, user_id, family_id, revoked_at, expires_at, last_used_at \
                 FROM sessions WHERE refresh_token_hash = $1 FOR UPDATE",
        )
        .bind(&hash)
        .fetch_optional(&mut *tx)
        .await?;

        let Some((old_id, user_id, family_id, revoked_at, expires_at, _last_used)) = row else {
            return Err(SessionError::NotFound);
        };

        // Already revoked or rotated → this is a replay. Burn the family.
        if revoked_at.is_some() {
            sqlx::query(
                "UPDATE sessions SET revoked_at = now() \
                 WHERE family_id = $1 AND revoked_at IS NULL",
            )
            .bind(family_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Err(SessionError::ReuseDetected);
        }

        let now = Utc::now();
        if expires_at < now {
            return Err(SessionError::Expired);
        }

        // Mark the old session revoked and issue a fresh one in the same family.
        sqlx::query("UPDATE sessions SET revoked_at = $1 WHERE id = $2")
            .bind(now)
            .bind(old_id)
            .execute(&mut *tx)
            .await?;

        let new_token = generate_refresh_token();
        let new_hash = hash_refresh_token(&new_token);
        let new_id = Uuid::new_v4();
        let new_expires = now
            + chrono::Duration::from_std(refresh_ttl)
                .unwrap_or_else(|_| chrono::Duration::days(14));

        sqlx::query(
            "INSERT INTO sessions \
             (id, user_id, family_id, refresh_token_hash, created_at, last_used_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $5, $6)",
        )
        .bind(new_id)
        .bind(user_id)
        .bind(family_id)
        .bind(&new_hash)
        .bind(now)
        .bind(new_expires)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(IssuedSession {
            session: Session {
                id: new_id,
                user_id,
                family_id,
                refresh_token_hash: new_hash,
                user_agent: None,
                ip: None,
                created_at: now,
                last_used_at: now,
                revoked_at: None,
                expires_at: new_expires,
            },
            refresh_token_plain: new_token,
        })
    }

    async fn revoke_family(&self, family_id: Uuid) -> Result<(), SessionError> {
        sqlx::query(
            "UPDATE sessions SET revoked_at = now() \
             WHERE family_id = $1 AND revoked_at IS NULL",
        )
        .bind(family_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_active(&self, refresh_token_plain: &str) -> Result<Session, SessionError> {
        let hash = hash_refresh_token(refresh_token_plain);
        let row: Option<(
            Uuid,
            Uuid,
            Uuid,
            Vec<u8>,
            Option<String>,
            Option<String>,
            DateTime<Utc>,
            DateTime<Utc>,
            Option<DateTime<Utc>>,
            DateTime<Utc>,
        )> = sqlx::query_as(
            "SELECT id, user_id, family_id, refresh_token_hash, user_agent, ip, \
                    created_at, last_used_at, revoked_at, expires_at \
             FROM sessions \
             WHERE refresh_token_hash = $1 AND revoked_at IS NULL AND expires_at > now()",
        )
        .bind(&hash)
        .fetch_optional(&self.pool)
        .await?;

        row.map(
            |(
                id,
                user_id,
                family_id,
                refresh_token_hash,
                user_agent,
                ip,
                created_at,
                last_used_at,
                revoked_at,
                expires_at,
            )| Session {
                id,
                user_id,
                family_id,
                refresh_token_hash,
                user_agent,
                ip,
                created_at,
                last_used_at,
                revoked_at,
                expires_at,
            },
        )
        .ok_or(SessionError::NotFound)
    }
}

// -----------------------------------------------------------------------------
// Pure-logic tests (no database)
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn generated_refresh_tokens_are_unique_and_url_safe() {
        let a = generate_refresh_token();
        let b = generate_refresh_token();
        assert_ne!(a, b);
        // URL-safe base64, no padding: only [A-Za-z0-9_-].
        assert!(
            a.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        // 32 bytes → 43 base64url chars without padding.
        assert_eq!(a.len(), 43);
    }

    #[test]
    fn hash_is_deterministic_and_hides_plaintext() {
        let token = generate_refresh_token();
        let h1 = hash_refresh_token(&token);
        let h2 = hash_refresh_token(&token);
        assert_eq!(h1, h2);
        assert_ne!(h1.as_slice(), token.as_bytes());
        assert_eq!(h1.len(), 32); // SHA-256
    }

    #[test]
    fn hash_of_different_tokens_differs() {
        let a = hash_refresh_token("token-a");
        let b = hash_refresh_token("token-b");
        assert_ne!(a, b);
    }

    // -------------------------------------------------------------------------
    // In-memory mock store — exercises rotation/reuse logic without Postgres.
    // -------------------------------------------------------------------------

    #[derive(Default)]
    struct MockStore {
        inner: Mutex<Vec<Session>>,
    }

    #[async_trait]
    impl SessionStore for MockStore {
        async fn create(
            &self,
            user_id: Uuid,
            user_agent: Option<String>,
            ip: Option<String>,
            refresh_ttl: Duration,
        ) -> Result<IssuedSession, SessionError> {
            let token = generate_refresh_token();
            let hash = hash_refresh_token(&token);
            let now = Utc::now();
            let session = Session {
                id: Uuid::new_v4(),
                user_id,
                family_id: Uuid::new_v4(),
                refresh_token_hash: hash.clone(),
                user_agent,
                ip,
                created_at: now,
                last_used_at: now,
                revoked_at: None,
                expires_at: now
                    + chrono::Duration::from_std(refresh_ttl)
                        .unwrap_or_else(|_| chrono::Duration::days(14)),
            };
            self.inner.lock().unwrap().push(session.clone());
            Ok(IssuedSession {
                session,
                refresh_token_plain: token,
            })
        }

        async fn rotate(
            &self,
            refresh_token_plain: &str,
            refresh_ttl: Duration,
        ) -> Result<IssuedSession, SessionError> {
            let hash = hash_refresh_token(refresh_token_plain);
            let mut sessions = self.inner.lock().unwrap();
            let idx = sessions.iter().position(|s| s.refresh_token_hash == hash);
            let Some(idx) = idx else {
                return Err(SessionError::NotFound);
            };

            if sessions[idx].revoked_at.is_some() {
                let family = sessions[idx].family_id;
                for s in sessions
                    .iter_mut()
                    .filter(|s| s.family_id == family && s.revoked_at.is_none())
                {
                    s.revoked_at = Some(Utc::now());
                }
                return Err(SessionError::ReuseDetected);
            }

            let now = Utc::now();
            if sessions[idx].expires_at < now {
                return Err(SessionError::Expired);
            }

            let family_id = sessions[idx].family_id;
            let user_id = sessions[idx].user_id;
            sessions[idx].revoked_at = Some(now);

            let token = generate_refresh_token();
            let new = Session {
                id: Uuid::new_v4(),
                user_id,
                family_id,
                refresh_token_hash: hash_refresh_token(&token),
                user_agent: None,
                ip: None,
                created_at: now,
                last_used_at: now,
                revoked_at: None,
                expires_at: now
                    + chrono::Duration::from_std(refresh_ttl)
                        .unwrap_or_else(|_| chrono::Duration::days(14)),
            };
            sessions.push(new.clone());
            Ok(IssuedSession {
                session: new,
                refresh_token_plain: token,
            })
        }

        async fn revoke_family(&self, family_id: Uuid) -> Result<(), SessionError> {
            let now = Utc::now();
            let mut sessions = self.inner.lock().unwrap();
            for s in sessions
                .iter_mut()
                .filter(|s| s.family_id == family_id && s.revoked_at.is_none())
            {
                s.revoked_at = Some(now);
            }
            Ok(())
        }

        async fn get_active(&self, refresh_token_plain: &str) -> Result<Session, SessionError> {
            let hash = hash_refresh_token(refresh_token_plain);
            let sessions = self.inner.lock().unwrap();
            sessions
                .iter()
                .find(|s| {
                    s.refresh_token_hash == hash
                        && s.revoked_at.is_none()
                        && s.expires_at > Utc::now()
                })
                .cloned()
                .ok_or(SessionError::NotFound)
        }
    }

    #[tokio::test]
    async fn create_and_rotate_happy_path() {
        let store = MockStore::default();
        let user = Uuid::new_v4();

        let first = store
            .create(user, None, None, DEFAULT_REFRESH_TTL)
            .await
            .unwrap();
        let family = first.session.family_id;

        let second = store
            .rotate(&first.refresh_token_plain, DEFAULT_REFRESH_TTL)
            .await
            .unwrap();

        // Same family, new token, old token no longer active.
        assert_eq!(second.session.family_id, family);
        assert_ne!(second.refresh_token_plain, first.refresh_token_plain);
        assert!(matches!(
            store.get_active(&first.refresh_token_plain).await,
            Err(SessionError::NotFound)
        ));
        assert!(store.get_active(&second.refresh_token_plain).await.is_ok());
    }

    #[tokio::test]
    async fn reusing_old_token_burns_the_family() {
        let store = MockStore::default();
        let user = Uuid::new_v4();

        let a = store
            .create(user, None, None, DEFAULT_REFRESH_TTL)
            .await
            .unwrap();
        let b = store
            .rotate(&a.refresh_token_plain, DEFAULT_REFRESH_TTL)
            .await
            .unwrap();
        let c = store
            .rotate(&b.refresh_token_plain, DEFAULT_REFRESH_TTL)
            .await
            .unwrap();

        // Attacker tries to reuse the second-oldest (already-rotated) token.
        let attack = store
            .rotate(&b.refresh_token_plain, DEFAULT_REFRESH_TTL)
            .await;
        assert!(matches!(attack, Err(SessionError::ReuseDetected)));

        // Legitimate user's current token is also dead now.
        assert!(matches!(
            store.get_active(&c.refresh_token_plain).await,
            Err(SessionError::NotFound)
        ));
    }

    #[tokio::test]
    async fn unknown_token_is_not_found() {
        let store = MockStore::default();
        let err = store
            .rotate("completely-unknown-token", DEFAULT_REFRESH_TTL)
            .await;
        assert!(matches!(err, Err(SessionError::NotFound)));
    }

    #[tokio::test]
    async fn revoke_family_invalidates_every_member() {
        let store = MockStore::default();
        let user = Uuid::new_v4();
        let a = store
            .create(user, None, None, DEFAULT_REFRESH_TTL)
            .await
            .unwrap();
        let b = store
            .rotate(&a.refresh_token_plain, DEFAULT_REFRESH_TTL)
            .await
            .unwrap();

        store.revoke_family(b.session.family_id).await.unwrap();
        assert!(matches!(
            store.get_active(&b.refresh_token_plain).await,
            Err(SessionError::NotFound)
        ));
    }

    #[tokio::test]
    async fn expired_session_cannot_rotate() {
        let store = MockStore::default();
        let user = Uuid::new_v4();
        let first = store
            .create(user, None, None, Duration::from_secs(0))
            .await
            .unwrap();
        // With TTL=0, expires_at == created_at, so it's already expired.
        tokio::time::sleep(Duration::from_millis(10)).await;
        let err = store
            .rotate(&first.refresh_token_plain, DEFAULT_REFRESH_TTL)
            .await;
        assert!(matches!(err, Err(SessionError::Expired)));
    }

    #[tokio::test]
    async fn get_active_hides_revoked_sessions() {
        let store = MockStore::default();
        let user = Uuid::new_v4();
        let s = store
            .create(user, None, None, DEFAULT_REFRESH_TTL)
            .await
            .unwrap();
        store.revoke_family(s.session.family_id).await.unwrap();
        assert!(matches!(
            store.get_active(&s.refresh_token_plain).await,
            Err(SessionError::NotFound)
        ));
    }
}
