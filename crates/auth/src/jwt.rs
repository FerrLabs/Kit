//! JWT access tokens for FerrLabs APIs.
//!
//! Signed with **EdDSA (ed25519)**. The private key lives in Vault at
//! `secret/ferrlabs/auth/jwt-private-key` and is injected into
//! `ferrlabs-api` via FerrVault. Public key is shipped with the API
//! binary and cached by any downstream verifier.
//!
//! Access tokens are short-lived (15 minutes by convention). They are paired
//! with an opaque refresh token (see [`crate::session`]) which lasts 14 days
//! and is the sole mechanism for getting a new access token.

use std::time::Duration;

use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Default access-token TTL.
pub const DEFAULT_ACCESS_TTL: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("token is malformed or signed with the wrong key")]
    Invalid,
    #[error("token has expired")]
    Expired,
    #[error("token issuer does not match")]
    WrongIssuer,
    #[error("failed to load signing key: {0}")]
    KeyLoad(String),
    #[error("internal jwt error: {0}")]
    Internal(#[from] jsonwebtoken::errors::Error),
}

/// Runtime config for issuing and verifying JWTs.
///
/// Build one of these at API startup from keys loaded out of Vault. Clone
/// the struct freely — both `EncodingKey` and `DecodingKey` are cheap-clone
/// reference-counted wrappers around the key material.
#[derive(Clone)]
pub struct JwtConfig {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    issuer: String,
    access_ttl_seconds: i64,
}

impl JwtConfig {
    /// Build a [`JwtConfig`] from ed25519 PEM key material.
    ///
    /// `private_pem` must be a PKCS#8 ed25519 private key. `public_pem` must
    /// be the matching SubjectPublicKeyInfo public key. Both are base64-PEM.
    ///
    /// # Errors
    /// Returns [`JwtError::KeyLoad`] if either PEM cannot be parsed.
    pub fn from_ed25519_pems(
        private_pem: &[u8],
        public_pem: &[u8],
        issuer: impl Into<String>,
        access_ttl: Duration,
    ) -> Result<Self, JwtError> {
        let encoding_key = EncodingKey::from_ed_pem(private_pem)
            .map_err(|e| JwtError::KeyLoad(format!("private key: {e}")))?;
        let decoding_key = DecodingKey::from_ed_pem(public_pem)
            .map_err(|e| JwtError::KeyLoad(format!("public key: {e}")))?;

        Ok(Self {
            encoding_key,
            decoding_key,
            issuer: issuer.into(),
            access_ttl_seconds: i64::try_from(access_ttl.as_secs()).unwrap_or(i64::MAX),
        })
    }

    /// The configured issuer claim (`iss`) for tokens.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Access-token TTL in seconds.
    #[must_use]
    pub fn access_ttl_seconds(&self) -> i64 {
        self.access_ttl_seconds
    }
}

/// Claims encoded in every FerrLabs access token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    /// Subject — the user's UUID.
    pub sub: Uuid,
    /// Issuer — always the same string this API was started with.
    pub iss: String,
    /// Expiration timestamp (unix seconds).
    pub exp: i64,
    /// Issued-at timestamp (unix seconds).
    pub iat: i64,
    /// Active organization ID, if the user is acting on behalf of one.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub org: Option<Uuid>,
}

/// Issue a signed access token for a user.
///
/// # Errors
/// Returns [`JwtError::Internal`] if encoding fails (should not happen
/// with a well-formed config).
pub fn issue_token(
    config: &JwtConfig,
    user_id: Uuid,
    org: Option<Uuid>,
) -> Result<String, JwtError> {
    let now = Utc::now().timestamp();
    let claims = Claims {
        sub: user_id,
        iss: config.issuer.clone(),
        exp: now + config.access_ttl_seconds,
        iat: now,
        org,
    };
    let header = Header::new(Algorithm::EdDSA);
    Ok(encode(&header, &claims, &config.encoding_key)?)
}

/// Verify a signed access token and return its claims.
///
/// Validates signature, expiration, and issuer. Does **not** check
/// audience — we have a single audience today.
///
/// # Errors
/// - [`JwtError::Expired`] — token's `exp` is in the past.
/// - [`JwtError::WrongIssuer`] — token's `iss` doesn't match config.
/// - [`JwtError::Invalid`] — bad signature, malformed, or any other decode failure.
pub fn verify_token(config: &JwtConfig, token: &str) -> Result<Claims, JwtError> {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&[&config.issuer]);
    validation.validate_exp = true;
    validation.leeway = 0;

    let data =
        decode::<Claims>(token, &config.decoding_key, &validation).map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => JwtError::Expired,
            jsonwebtoken::errors::ErrorKind::InvalidIssuer => JwtError::WrongIssuer,
            _ => JwtError::Invalid,
        })?;

    Ok(data.claims)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use ed25519_dalek::pkcs8::spki::EncodePublicKey;
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;

    use super::*;

    fn generate_keypair() -> (String, String) {
        let seed: [u8; 32] = rand::random();
        let signing = SigningKey::from_bytes(&seed);
        let private_pem = signing
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode pkcs8 private key")
            .to_string();
        let public_pem = signing
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("encode spki public key");
        (private_pem, public_pem)
    }

    fn config_with(issuer: &str, ttl: Duration, keypair: &(String, String)) -> JwtConfig {
        let (private_pem, public_pem) = keypair;
        JwtConfig::from_ed25519_pems(private_pem.as_bytes(), public_pem.as_bytes(), issuer, ttl)
            .expect("generated test keys should parse")
    }

    fn test_config(ttl: Duration) -> JwtConfig {
        config_with("ferrlabs-test", ttl, &generate_keypair())
    }

    #[test]
    fn issue_and_verify_round_trip() {
        let config = test_config(DEFAULT_ACCESS_TTL);
        let user_id = Uuid::new_v4();
        let org_id = Uuid::new_v4();

        let token = issue_token(&config, user_id, Some(org_id)).unwrap();
        let claims = verify_token(&config, &token).unwrap();

        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.iss, "ferrlabs-test");
        assert_eq!(claims.org, Some(org_id));
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn round_trip_without_org() {
        let config = test_config(DEFAULT_ACCESS_TTL);
        let user_id = Uuid::new_v4();

        let token = issue_token(&config, user_id, None).unwrap();
        let claims = verify_token(&config, &token).unwrap();

        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.org, None);
    }

    #[test]
    fn expired_token_rejected() {
        // Issue with negative TTL → token is already expired when it returns.
        let config = test_config(Duration::from_secs(0));
        let user_id = Uuid::new_v4();

        let token = issue_token(&config, user_id, None).unwrap();
        // Force-sleep isn't needed; `exp` is `now + 0` which is `<= now`.
        std::thread::sleep(Duration::from_millis(1100));

        match verify_token(&config, &token) {
            Err(JwtError::Expired) => {}
            other => panic!("expected Expired, got {other:?}"),
        }
    }

    #[test]
    fn tampered_signature_rejected() {
        let config = test_config(DEFAULT_ACCESS_TTL);
        let token = issue_token(&config, Uuid::new_v4(), None).unwrap();

        // Flip the last byte of the signature (base64-url section).
        let mut bytes: Vec<u8> = token.into_bytes();
        let last = bytes.last_mut().unwrap();
        *last = if *last == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).unwrap();

        match verify_token(&config, &tampered) {
            Err(JwtError::Invalid) => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn wrong_issuer_rejected() {
        let keypair = generate_keypair();
        let signer = config_with("other-issuer", DEFAULT_ACCESS_TTL, &keypair);
        let verifier = config_with("ferrlabs-test", DEFAULT_ACCESS_TTL, &keypair);

        let token = issue_token(&signer, Uuid::new_v4(), None).unwrap();

        match verify_token(&verifier, &token) {
            Err(JwtError::WrongIssuer) => {}
            other => panic!("expected WrongIssuer, got {other:?}"),
        }
    }

    #[test]
    fn malformed_token_rejected() {
        let config = test_config(DEFAULT_ACCESS_TTL);
        match verify_token(&config, "not.a.jwt") {
            Err(JwtError::Invalid) => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn claims_exp_is_ttl_from_now() {
        let config = test_config(Duration::from_secs(900));
        let token = issue_token(&config, Uuid::new_v4(), None).unwrap();
        let claims = verify_token(&config, &token).unwrap();

        let now = Utc::now().timestamp();
        assert!(claims.exp >= now + 895);
        assert!(claims.exp <= now + 905);
    }
}
