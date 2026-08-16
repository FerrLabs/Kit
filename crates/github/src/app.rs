use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};

use crate::GithubError;

/// GitHub rejects an App JWT whose `exp` is more than 10 minutes out. Nine
/// leaves room for the backdated `iat` without touching that ceiling.
const JWT_LIFETIME_SECS: u64 = 540;

/// `iat` is backdated so a GitHub clock running slightly behind ours does not
/// see a token issued in its future.
const CLOCK_SKEW_SECS: u64 = 60;

/// Installation tokens are refreshed this far ahead of expiry, so one is never
/// handed out with barely any life left.
const REFRESH_MARGIN_SECS: u64 = 60;

/// Used when GitHub's `expires_at` cannot be parsed. Shorter than the ~1 hour
/// GitHub actually grants, so a parsing change costs an early refresh rather
/// than a token used past its life.
const FALLBACK_TTL_SECS: u64 = 3000;

#[derive(Debug, PartialEq, Eq, Serialize)]
struct AppClaims {
    iat: u64,
    exp: u64,
    iss: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    token: String,
    expires_at: String,
}

fn app_claims(app_id: u64, now: u64) -> AppClaims {
    AppClaims {
        iat: now.saturating_sub(CLOCK_SKEW_SECS),
        exp: now + JWT_LIFETIME_SECS,
        iss: app_id.to_string(),
    }
}

fn is_fresh(expiry: u64, now: u64) -> bool {
    expiry > now + REFRESH_MARGIN_SECS
}

/// Signs an App JWT and exchanges it for per-installation access tokens.
///
/// `Clone` shares the cache, so cloning this into per-request state keeps one
/// map rather than one per clone.
#[derive(Clone)]
pub struct GithubAppAuth {
    app_id: u64,
    key: EncodingKey,
    user_agent: String,
    http: reqwest::Client,
    /// `(installation_id, repo scope) -> (token, expiry epoch secs)`. The scope
    /// belongs in the key: a token minted for one repository must never be
    /// handed to work on another.
    cache: Arc<DashMap<(i64, String), (String, u64)>>,
}

impl GithubAppAuth {
    /// Build from the App id and its RSA private key PEM.
    ///
    /// `user_agent` is sent on every call; GitHub rejects API requests without
    /// one. Use something that identifies the calling product.
    pub fn new(
        app_id: u64,
        private_key_pem: &str,
        user_agent: impl Into<String>,
    ) -> Result<Self, GithubError> {
        let key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
            .map_err(GithubError::PrivateKey)?;
        Ok(Self {
            app_id,
            key,
            user_agent: user_agent.into(),
            http: reqwest::Client::new(),
            cache: Arc::new(DashMap::new()),
        })
    }

    fn now_secs() -> Result<u64, GithubError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .map_err(|_| GithubError::Clock)
    }

    fn app_jwt(&self, now: u64) -> Result<String, GithubError> {
        encode(
            &Header::new(Algorithm::RS256),
            &app_claims(self.app_id, now),
            &self.key,
        )
        .map_err(GithubError::JwtSigning)
    }

    /// A cached installation access token.
    ///
    /// `repos` narrows the token to those repositories, by short name rather
    /// than `owner/name`. This matters when the App is installed org-wide: an
    /// unscoped installation token carries write access to *every* repository
    /// the installation can see, so scoping it keeps work triggered on one
    /// repository from reaching another.
    ///
    /// An empty slice keeps the full installation scope. That is the caller's
    /// explicit choice and should never be a fallback for "no scope known".
    pub async fn installation_token(
        &self,
        installation_id: i64,
        repos: &[String],
    ) -> Result<String, GithubError> {
        let now = Self::now_secs()?;
        let key = (installation_id, repos.join(","));

        if let Some(entry) = self.cache.get(&key)
            && is_fresh(entry.1, now)
        {
            return Ok(entry.0.clone());
        }

        let mut body = serde_json::Map::new();
        if !repos.is_empty() {
            body.insert("repositories".into(), serde_json::json!(repos));
        }

        let response = self
            .http
            .post(format!(
                "https://api.github.com/app/installations/{installation_id}/access_tokens"
            ))
            .json(&serde_json::Value::Object(body))
            .header("Authorization", format!("Bearer {}", self.app_jwt(now)?))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", &self.user_agent)
            .send()
            .await
            .map_err(GithubError::http("requesting an installation token"))?
            .error_for_status()
            .map_err(GithubError::http(
                "the installation token request returned an error status",
            ))?;

        let token: TokenResponse = response
            .json()
            .await
            .map_err(GithubError::http("decoding the installation token"))?;

        let expiry = chrono::DateTime::parse_from_rfc3339(&token.expires_at)
            .map_or(now + FALLBACK_TTL_SECS, |at| at.timestamp().unsigned_abs());
        self.cache.insert(key, (token.token.clone(), expiry));

        Ok(token.token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_rejects_a_pem_it_cannot_parse() {
        assert!(matches!(
            GithubAppAuth::new(123, "not a pem", "test"),
            Err(GithubError::PrivateKey(_))
        ));
    }

    #[test]
    fn claims_stay_inside_githubs_ten_minute_ceiling() {
        let now = 1_700_000_000;
        let claims = app_claims(42, now);

        assert_eq!(claims.exp - now, JWT_LIFETIME_SECS);
        assert!(
            claims.exp - now <= 600,
            "GitHub rejects an App JWT expiring more than 10 minutes out"
        );
        assert_eq!(claims.iss, "42");
    }

    #[test]
    fn claims_backdate_iat_to_absorb_clock_skew() {
        let now = 1_700_000_000;
        assert_eq!(app_claims(42, now).iat, now - CLOCK_SKEW_SECS);
    }

    /// A clock reporting an epoch under the skew window must not wrap around to
    /// a `iat` decades in the future, which would make every JWT unusable.
    #[test]
    fn claims_do_not_underflow_near_the_epoch() {
        assert_eq!(app_claims(42, 5).iat, 0);
    }

    #[test]
    fn a_token_expiring_within_the_margin_is_not_reused() {
        let now = 1_700_000_000;

        assert!(is_fresh(now + REFRESH_MARGIN_SECS + 1, now));
        assert!(!is_fresh(now + REFRESH_MARGIN_SECS, now));
        assert!(!is_fresh(now, now));
        assert!(!is_fresh(now - 1, now));
    }
}
