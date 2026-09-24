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
//!
//! # Audience
//!
//! One key signs tokens for every product, so `aud` is what stops a token
//! minted for one API from being replayed against another. Configure it with
//! [`JwtConfig::with_audience`] on both ends.
//!
//! Rollout order matters, because a verifier that expects no audience rejects
//! a token that carries one (RFC 7519: a principal that does not identify
//! itself with a value in `aud` must reject the token). Configure every
//! verifier with its audience first, then start minting tokens that carry it.
//!
//! # The `org` claim is an assertion, not an authorization
//!
//! [`Claims::org`] says which organization the user had selected when the
//! token was minted. It is signed, so it cannot be forged, but it is not
//! re-checked: a membership revoked one minute after the token was issued
//! keeps asserting that org for the rest of the TTL. Every caller that acts on
//! org data must re-check membership against its own store on each request,
//! and use the claim only to know which org the caller *means*.

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
    #[error("token audience does not match")]
    WrongAudience,
    #[error("token is not valid yet")]
    NotYetValid,
    #[error("this config has no signing key, it can only verify")]
    VerifyOnly,
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
    encoding_key: Option<EncodingKey>,
    /// Current key first, then keys kept for a rotation overlap.
    decoding_keys: Vec<DecodingKey>,
    issuer: String,
    audience: Option<String>,
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
            encoding_key: Some(encoding_key),
            decoding_keys: vec![decoding_key],
            issuer: issuer.into(),
            audience: None,
            access_ttl_seconds: i64::try_from(access_ttl.as_secs()).unwrap_or(i64::MAX),
        })
    }

    /// Build a verify-only [`JwtConfig`] from the public key alone.
    ///
    /// A service that only consumes tokens has no business holding the signing
    /// key. [`issue_token`] on such a config returns [`JwtError::VerifyOnly`].
    ///
    /// # Errors
    /// Returns [`JwtError::KeyLoad`] if the PEM cannot be parsed.
    pub fn verifier_from_public_pem(
        public_pem: &[u8],
        issuer: impl Into<String>,
    ) -> Result<Self, JwtError> {
        let decoding_key = DecodingKey::from_ed_pem(public_pem)
            .map_err(|e| JwtError::KeyLoad(format!("public key: {e}")))?;

        Ok(Self {
            encoding_key: None,
            decoding_keys: vec![decoding_key],
            issuer: issuer.into(),
            audience: None,
            access_ttl_seconds: i64::try_from(DEFAULT_ACCESS_TTL.as_secs()).unwrap_or(i64::MAX),
        })
    }

    /// Bind this config to one audience: [`issue_token`] stamps it into `aud`,
    /// and [`verify_token`] rejects a token carrying any other value, or none.
    #[must_use]
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Keep accepting tokens signed by a previous key during a rotation.
    ///
    /// Add the outgoing public key here when the new one takes over, and drop
    /// it once every token minted under it has expired. Without this, rotating
    /// the signing key invalidates every outstanding token at once.
    ///
    /// # Errors
    /// Returns [`JwtError::KeyLoad`] if the PEM cannot be parsed.
    pub fn with_previous_public_pem(mut self, public_pem: &[u8]) -> Result<Self, JwtError> {
        let decoding_key = DecodingKey::from_ed_pem(public_pem)
            .map_err(|e| JwtError::KeyLoad(format!("previous public key: {e}")))?;
        self.decoding_keys.push(decoding_key);
        Ok(self)
    }

    /// The audience this config issues and expects, when one is configured.
    #[must_use]
    pub fn audience(&self) -> Option<&str> {
        self.audience.as_deref()
    }

    fn validation(&self) -> Validation {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[&self.issuer]);
        validation.validate_exp = true;
        // A token that carries a future `nbf` is refused. Tokens minted here
        // leave it unset: `nbf` would equal `iat`, and a verifier whose clock
        // sits a second behind the issuer would then reject every fresh token.
        validation.validate_nbf = true;
        validation.leeway = 0;

        match self.audience.as_deref() {
            Some(audience) => {
                validation.set_audience(&[audience]);
                // jsonwebtoken accepts a token with no `aud` even when one is
                // expected, so presence is required separately.
                validation.set_required_spec_claims(&["exp", "iss", "aud"]);
            }
            None => validation.set_required_spec_claims(&["exp", "iss"]),
        }

        validation
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
    /// Audience — the API this token was minted for. Absent on tokens issued
    /// by a config with no audience configured.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub aud: Option<String>,
    /// Not-before timestamp (unix seconds), when the issuer set one.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub nbf: Option<i64>,
    /// Active organization ID, if the user is acting on behalf of one.
    ///
    /// Signed, so it cannot be forged, but not re-checked: see the trust
    /// boundary in the module documentation before authorizing on it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub org: Option<Uuid>,
}

/// Issue a signed access token for a user.
///
/// # Errors
/// - [`JwtError::VerifyOnly`] — this config holds no signing key.
/// - [`JwtError::Internal`] — encoding failed (should not happen with a
///   well-formed config).
pub fn issue_token(
    config: &JwtConfig,
    user_id: Uuid,
    org: Option<Uuid>,
) -> Result<String, JwtError> {
    issue_token_for(config, user_id, org, config.audience.as_deref())
}

/// Issue a signed access token for one audience, whatever the config carries.
///
/// The central API mints a token per product this way; everything else should
/// reach for [`issue_token`] and let the config decide.
///
/// # Errors
/// - [`JwtError::VerifyOnly`] — this config holds no signing key.
/// - [`JwtError::Internal`] — encoding failed.
pub fn issue_token_for(
    config: &JwtConfig,
    user_id: Uuid,
    org: Option<Uuid>,
    audience: Option<&str>,
) -> Result<String, JwtError> {
    let encoding_key = config.encoding_key.as_ref().ok_or(JwtError::VerifyOnly)?;
    let now = Utc::now().timestamp();
    let claims = Claims {
        sub: user_id,
        iss: config.issuer.clone(),
        exp: now + config.access_ttl_seconds,
        iat: now,
        aud: audience.map(ToOwned::to_owned),
        nbf: None,
        org,
    };
    let header = Header::new(Algorithm::EdDSA);
    Ok(encode(&header, &claims, encoding_key)?)
}

/// Verify a signed access token and return its claims.
///
/// Validates the signature, `exp`, `iss`, `nbf` when the token carries one,
/// and `aud` when the config was given one. Keys added with
/// [`JwtConfig::with_previous_public_pem`] are tried after the current one.
///
/// The returned [`Claims::org`] is an assertion by the issuer, not an
/// authorization: re-check membership before acting on it.
///
/// # Errors
/// - [`JwtError::Expired`] — token's `exp` is in the past.
/// - [`JwtError::NotYetValid`] — token's `nbf` is in the future.
/// - [`JwtError::WrongIssuer`] — token's `iss` doesn't match config.
/// - [`JwtError::WrongAudience`] — token's `aud` doesn't match the configured
///   audience, is missing while one is expected, or is present while none is.
/// - [`JwtError::Invalid`] — bad signature, malformed, or any other decode failure.
pub fn verify_token(config: &JwtConfig, token: &str) -> Result<Claims, JwtError> {
    let validation = config.validation();
    let mut best_error = None;

    for key in &config.decoding_keys {
        match decode::<Claims>(token, key, &validation) {
            Ok(data) => return Ok(data.claims),
            Err(error) => {
                // A key the token was not signed with can only report a bad
                // signature. Anything else means the token decoded and a claim
                // was refused, which is the failure the caller needs to read.
                let claim_failure = !matches!(
                    error.kind(),
                    jsonwebtoken::errors::ErrorKind::InvalidSignature
                );
                if best_error.is_none() || claim_failure {
                    best_error = Some(error);
                }
            }
        }
    }

    Err(map_error(&best_error.expect(
        "a config always carries at least one decoding key",
    )))
}

fn map_error(error: &jsonwebtoken::errors::Error) -> JwtError {
    use jsonwebtoken::errors::ErrorKind;

    match error.kind() {
        ErrorKind::ExpiredSignature => JwtError::Expired,
        ErrorKind::ImmatureSignature => JwtError::NotYetValid,
        ErrorKind::InvalidIssuer => JwtError::WrongIssuer,
        ErrorKind::InvalidAudience => JwtError::WrongAudience,
        ErrorKind::MissingRequiredClaim(claim) if claim == "aud" => JwtError::WrongAudience,
        _ => JwtError::Invalid,
    }
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

    /// One key signs for every product, so without `aud` a token minted for
    /// FerrTrack unlocks FerrVault.
    #[test]
    fn a_token_for_another_product_is_rejected() {
        let keypair = generate_keypair();
        let track = config_with("ferrlabs-test", DEFAULT_ACCESS_TTL, &keypair)
            .with_audience("api.ferrtrack.com");
        let vault = config_with("ferrlabs-test", DEFAULT_ACCESS_TTL, &keypair)
            .with_audience("api.ferrvault.com");

        let token = issue_token(&track, Uuid::new_v4(), None).unwrap();

        assert_eq!(
            verify_token(&track, &token).unwrap().aud.as_deref(),
            Some("api.ferrtrack.com")
        );
        match verify_token(&vault, &token) {
            Err(JwtError::WrongAudience) => {}
            other => panic!("expected WrongAudience, got {other:?}"),
        }
    }

    /// jsonwebtoken lets a token with no `aud` through even when one is
    /// expected, so a verifier would otherwise accept pre-audience tokens for
    /// as long as any remain in circulation.
    #[test]
    fn a_token_without_an_audience_is_rejected_when_one_is_expected() {
        let keypair = generate_keypair();
        let central = config_with("ferrlabs-test", DEFAULT_ACCESS_TTL, &keypair);
        let product = config_with("ferrlabs-test", DEFAULT_ACCESS_TTL, &keypair)
            .with_audience("api.ferrtrack.com");

        let token = issue_token(&central, Uuid::new_v4(), None).unwrap();

        match verify_token(&product, &token) {
            Err(JwtError::WrongAudience) => {}
            other => panic!("expected WrongAudience, got {other:?}"),
        }
    }

    /// The other direction, which decides the rollout order: verifiers have to
    /// learn their audience before the issuer starts stamping one.
    #[test]
    fn a_verifier_expecting_no_audience_rejects_a_token_that_carries_one() {
        let keypair = generate_keypair();
        let issuer = config_with("ferrlabs-test", DEFAULT_ACCESS_TTL, &keypair)
            .with_audience("api.ferrtrack.com");
        let verifier = config_with("ferrlabs-test", DEFAULT_ACCESS_TTL, &keypair);

        let token = issue_token(&issuer, Uuid::new_v4(), None).unwrap();

        match verify_token(&verifier, &token) {
            Err(JwtError::WrongAudience) => {}
            other => panic!("expected WrongAudience, got {other:?}"),
        }
    }

    #[test]
    fn issue_token_for_overrides_the_configured_audience() {
        let keypair = generate_keypair();
        let central = config_with("ferrlabs-test", DEFAULT_ACCESS_TTL, &keypair)
            .with_audience("api.ferrlabs.com");
        let growth = config_with("ferrlabs-test", DEFAULT_ACCESS_TTL, &keypair)
            .with_audience("api.ferrgrowth.com");

        let token =
            issue_token_for(&central, Uuid::new_v4(), None, Some("api.ferrgrowth.com")).unwrap();

        assert!(verify_token(&growth, &token).is_ok());
    }

    #[test]
    fn a_pre_dated_token_is_rejected() {
        let config = test_config(DEFAULT_ACCESS_TTL);
        let now = Utc::now().timestamp();
        let claims = Claims {
            sub: Uuid::new_v4(),
            iss: "ferrlabs-test".to_owned(),
            exp: now + 900,
            iat: now,
            aud: None,
            nbf: Some(now + 600),
            org: None,
        };
        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &claims,
            config.encoding_key.as_ref().unwrap(),
        )
        .unwrap();

        match verify_token(&config, &token) {
            Err(JwtError::NotYetValid) => {}
            other => panic!("expected NotYetValid, got {other:?}"),
        }
    }

    #[test]
    fn a_verify_only_config_verifies_but_cannot_mint() {
        let (private_pem, public_pem) = generate_keypair();
        let signer = JwtConfig::from_ed25519_pems(
            private_pem.as_bytes(),
            public_pem.as_bytes(),
            "ferrlabs-test",
            DEFAULT_ACCESS_TTL,
        )
        .unwrap();
        let verifier =
            JwtConfig::verifier_from_public_pem(public_pem.as_bytes(), "ferrlabs-test").unwrap();

        let user_id = Uuid::new_v4();
        let token = issue_token(&signer, user_id, None).unwrap();

        assert_eq!(verify_token(&verifier, &token).unwrap().sub, user_id);
        match issue_token(&verifier, user_id, None) {
            Err(JwtError::VerifyOnly) => {}
            other => panic!("expected VerifyOnly, got {other:?}"),
        }
    }

    /// Rotating the signing key must not invalidate every token in flight.
    #[test]
    fn a_token_signed_by_the_previous_key_survives_the_overlap() {
        let old = generate_keypair();
        let new = generate_keypair();

        let old_signer = config_with("ferrlabs-test", DEFAULT_ACCESS_TTL, &old);
        let token = issue_token(&old_signer, Uuid::new_v4(), None).unwrap();

        let during_overlap = config_with("ferrlabs-test", DEFAULT_ACCESS_TTL, &new)
            .with_previous_public_pem(old.1.as_bytes())
            .unwrap();
        assert!(verify_token(&during_overlap, &token).is_ok());

        let after_overlap = config_with("ferrlabs-test", DEFAULT_ACCESS_TTL, &new);
        match verify_token(&after_overlap, &token) {
            Err(JwtError::Invalid) => {}
            other => panic!("expected Invalid once the old key is dropped, got {other:?}"),
        }
    }

    /// Every session in flight when the key rotates expires under the old key.
    /// Reporting that as `Invalid` would log out the callers that refresh on
    /// `Expired`, which is what the overlap exists to avoid.
    #[test]
    fn an_expired_token_under_the_previous_key_still_reads_as_expired() {
        let old = generate_keypair();
        let new = generate_keypair();

        let old_signer = config_with("ferrlabs-test", Duration::from_secs(0), &old);
        let token = issue_token(&old_signer, Uuid::new_v4(), None).unwrap();
        std::thread::sleep(Duration::from_millis(1100));

        let rotated = config_with("ferrlabs-test", DEFAULT_ACCESS_TTL, &new)
            .with_previous_public_pem(old.1.as_bytes())
            .unwrap();

        match verify_token(&rotated, &token) {
            Err(JwtError::Expired) => {}
            other => panic!("expected Expired, got {other:?}"),
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
