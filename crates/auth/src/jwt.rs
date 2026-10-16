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
//! ## Audience binding
//!
//! Each token carries an `aud` claim naming the product API it is for
//! (`ferrvault`, `ferrtrack`, `ferrgrowth`, `ferrfleet`, `ferrlabs`).
//! [`verify_token`] requires the caller to pass the audience it expects;
//! a token minted for one product API will not verify against another.
//! Cross-product tokens can list multiple audiences via [`issue_token_for`].
//!
//! ## Key rotation
//!
//! [`JwtConfig`] holds a map of `kid → DecodingKey`. The JWT header's `kid`
//! selects which key verifies a given token; rotating the signing key only
//! requires keeping the previous public key in the map until every
//! outstanding token has expired (15 minutes by default), then removing it.
//!
//! Tokens that omit `kid` fall back to a default key — useful while
//! migrating from a single-key deployment.
//!
//! ## `org` claim is an assertion, not authorization
//!
//! `Claims.org` reflects the org the user was acting on behalf of at the
//! moment the token was issued. It is **not** a live membership check:
//! a user removed from the org will continue to present `org = X` until
//! their token expires (up to a full TTL). Callers MUST re-validate
//! membership against the database at the point of authorization —
//! typically in `ferrlabs-permissions` or in product-specific RBAC
//! middleware.

use std::collections::HashMap;
use std::time::Duration;

use chrono::Utc;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Default access-token TTL.
pub const DEFAULT_ACCESS_TTL: Duration = Duration::from_secs(15 * 60);

/// Fallback kid for deployments that have not yet introduced explicit key rotation.
pub const DEFAULT_KID: &str = "default";

#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("token is malformed or signed with the wrong key")]
    Invalid,
    #[error("token has expired")]
    Expired,
    #[error("token's not-before claim is in the future")]
    NotYetValid,
    #[error("token issuer does not match")]
    WrongIssuer,
    #[error("token audience does not match")]
    WrongAudience,
    #[error("token's kid does not match any configured verification key")]
    UnknownKid,
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
///
/// `decoding_keys` is a `kid → DecodingKey` map. The active signing key's
/// `kid` is stored separately so freshly minted tokens advertise it on the
/// header; verification accepts any key in the map, which supports the
/// "accept previous key during rotation overlap" path.
#[derive(Clone)]
pub struct JwtConfig {
    encoding_key: EncodingKey,
    active_kid: String,
    decoding_keys: HashMap<String, DecodingKey>,
    issuer: String,
    access_ttl_seconds: i64,
}

impl JwtConfig {
    /// Build a [`JwtConfig`] from ed25519 PEM key material with a single
    /// active key. Equivalent to [`JwtConfig::with_keys`] passing the
    /// default kid.
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

        let mut decoding_keys = HashMap::new();
        decoding_keys.insert(DEFAULT_KID.to_string(), decoding_key);

        Ok(Self {
            encoding_key,
            active_kid: DEFAULT_KID.to_string(),
            decoding_keys,
            issuer: issuer.into(),
            access_ttl_seconds: i64::try_from(access_ttl.as_secs()).unwrap_or(i64::MAX),
        })
    }

    /// Build a [`JwtConfig`] with explicit signing kid and a verification
    /// map of `kid → ed25519 public PEM`. The signing kid MUST be present
    /// in the verification map.
    ///
    /// # Errors
    /// Returns [`JwtError::KeyLoad`] if any PEM fails to parse or if the
    /// signing kid is missing from the verification map.
    pub fn with_keys(
        private_pem: &[u8],
        active_kid: impl Into<String>,
        public_pems: HashMap<String, Vec<u8>>,
        issuer: impl Into<String>,
        access_ttl: Duration,
    ) -> Result<Self, JwtError> {
        let active_kid: String = active_kid.into();
        if !public_pems.contains_key(&active_kid) {
            return Err(JwtError::KeyLoad(format!(
                "active kid {active_kid:?} missing from verification key map"
            )));
        }

        let encoding_key = EncodingKey::from_ed_pem(private_pem)
            .map_err(|e| JwtError::KeyLoad(format!("private key: {e}")))?;

        let mut decoding_keys = HashMap::with_capacity(public_pems.len());
        for (kid, pem) in public_pems {
            let key = DecodingKey::from_ed_pem(&pem)
                .map_err(|e| JwtError::KeyLoad(format!("public key {kid:?}: {e}")))?;
            decoding_keys.insert(kid, key);
        }

        Ok(Self {
            encoding_key,
            active_kid,
            decoding_keys,
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

    /// The kid stamped onto freshly issued tokens.
    #[must_use]
    pub fn active_kid(&self) -> &str {
        &self.active_kid
    }
}

/// Claims encoded in every FerrLabs access token.
///
/// `org` is an assertion of *which* org the subject was acting on behalf of
/// at issue time, not an authorization grant — see the module-level doc.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    /// Subject — the user's UUID.
    pub sub: Uuid,
    /// Issuer — always the same string this API was started with.
    pub iss: String,
    /// Audience(s) — the product API(s) this token is intended for.
    pub aud: Vec<String>,
    /// Expiration timestamp (unix seconds).
    pub exp: i64,
    /// Not-before timestamp (unix seconds).
    pub nbf: i64,
    /// Issued-at timestamp (unix seconds).
    pub iat: i64,
    /// Active organization ID, if the user is acting on behalf of one.
    ///
    /// Callers MUST re-check membership against the DB at the point of
    /// authorization — this claim is at most TTL-stale.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub org: Option<Uuid>,
}

/// Issue a signed access token for a user, scoped to a single audience.
///
/// # Errors
/// Returns [`JwtError::Internal`] if encoding fails (should not happen
/// with a well-formed config).
pub fn issue_token(
    config: &JwtConfig,
    user_id: Uuid,
    org: Option<Uuid>,
    audience: impl Into<String>,
) -> Result<String, JwtError> {
    issue_token_for(config, user_id, org, vec![audience.into()])
}

/// Issue a signed access token bound to one or more audiences. Use when a
/// token is explicitly intended to be cross-product (e.g. an SSO bootstrap
/// token accepted by every API).
///
/// # Errors
/// Returns [`JwtError::Internal`] if encoding fails.
pub fn issue_token_for(
    config: &JwtConfig,
    user_id: Uuid,
    org: Option<Uuid>,
    audiences: Vec<String>,
) -> Result<String, JwtError> {
    let now = Utc::now().timestamp();
    let claims = Claims {
        sub: user_id,
        iss: config.issuer.clone(),
        aud: audiences,
        exp: now + config.access_ttl_seconds,
        nbf: now,
        iat: now,
        org,
    };
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(config.active_kid.clone());
    Ok(encode(&header, &claims, &config.encoding_key)?)
}

/// Verify a signed access token and return its claims.
///
/// Validates signature, expiration, not-before, issuer, and audience. The
/// caller passes the expected audience — typically the constant naming the
/// product API doing the verification.
///
/// # Errors
/// - [`JwtError::Expired`] — token's `exp` is in the past.
/// - [`JwtError::NotYetValid`] — token's `nbf` is in the future.
/// - [`JwtError::WrongIssuer`] — token's `iss` doesn't match config.
/// - [`JwtError::WrongAudience`] — token's `aud` doesn't include `expected_audience`.
/// - [`JwtError::UnknownKid`] — token's `kid` is not in the verification map.
/// - [`JwtError::Invalid`] — bad signature, malformed, or any other decode failure.
pub fn verify_token(
    config: &JwtConfig,
    token: &str,
    expected_audience: &str,
) -> Result<Claims, JwtError> {
    let header = decode_header(token).map_err(|_| JwtError::Invalid)?;
    let kid = header.kid.as_deref().unwrap_or(DEFAULT_KID);
    let decoding_key = config
        .decoding_keys
        .get(kid)
        .ok_or(JwtError::UnknownKid)?;

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&[&config.issuer]);
    validation.set_audience(&[expected_audience]);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.required_spec_claims = ["exp", "nbf", "iss", "aud", "sub"]
        .iter()
        .map(ToString::to_string)
        .collect();
    validation.leeway = 0;

    let data = decode::<Claims>(token, decoding_key, &validation).map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => JwtError::Expired,
        jsonwebtoken::errors::ErrorKind::ImmatureSignature => JwtError::NotYetValid,
        jsonwebtoken::errors::ErrorKind::InvalidIssuer => JwtError::WrongIssuer,
        jsonwebtoken::errors::ErrorKind::InvalidAudience => JwtError::WrongAudience,
        _ => JwtError::Invalid,
    })?;

    Ok(data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_AUD: &str = "ferrlabs-test-aud";

    const TEST_PRIVATE_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----\n\
MC4CAQAwBQYDK2VwBCIEIFPsFIG7m7HPSKR4iUQ5yt527q3dEUnjM+67hM+cPQmb\n\
-----END PRIVATE KEY-----\n";

    const TEST_PUBLIC_PEM: &[u8] = b"-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEAO1omu6L4Mq9i4RmjolYvPFA7So9ePE3/CVkTAGJvmjM=\n\
-----END PUBLIC KEY-----\n";

    fn test_config(ttl: Duration) -> JwtConfig {
        JwtConfig::from_ed25519_pems(TEST_PRIVATE_PEM, TEST_PUBLIC_PEM, "ferrlabs-test", ttl)
            .expect("test keys should parse")
    }

    #[test]
    fn issue_and_verify_round_trip() {
        let config = test_config(DEFAULT_ACCESS_TTL);
        let user_id = Uuid::new_v4();
        let org_id = Uuid::new_v4();

        let token = issue_token(&config, user_id, Some(org_id), TEST_AUD).unwrap();
        let claims = verify_token(&config, &token, TEST_AUD).unwrap();

        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.iss, "ferrlabs-test");
        assert_eq!(claims.aud, vec![TEST_AUD.to_string()]);
        assert_eq!(claims.org, Some(org_id));
        assert!(claims.exp > claims.iat);
        assert_eq!(claims.nbf, claims.iat);
    }

    #[test]
    fn round_trip_without_org() {
        let config = test_config(DEFAULT_ACCESS_TTL);
        let user_id = Uuid::new_v4();

        let token = issue_token(&config, user_id, None, TEST_AUD).unwrap();
        let claims = verify_token(&config, &token, TEST_AUD).unwrap();

        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.org, None);
    }

    #[test]
    fn expired_token_rejected() {
        let config = test_config(Duration::from_secs(0));
        let user_id = Uuid::new_v4();

        let token = issue_token(&config, user_id, None, TEST_AUD).unwrap();
        std::thread::sleep(Duration::from_millis(1100));

        match verify_token(&config, &token, TEST_AUD) {
            Err(JwtError::Expired) => {}
            other => panic!("expected Expired, got {other:?}"),
        }
    }

    #[test]
    fn tampered_signature_rejected() {
        let config = test_config(DEFAULT_ACCESS_TTL);
        let token = issue_token(&config, Uuid::new_v4(), None, TEST_AUD).unwrap();

        let mut bytes: Vec<u8> = token.into_bytes();
        let last = bytes.last_mut().unwrap();
        *last = if *last == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).unwrap();

        match verify_token(&config, &tampered, TEST_AUD) {
            Err(JwtError::Invalid) => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn wrong_issuer_rejected() {
        let signer = JwtConfig::from_ed25519_pems(
            TEST_PRIVATE_PEM,
            TEST_PUBLIC_PEM,
            "other-issuer",
            DEFAULT_ACCESS_TTL,
        )
        .unwrap();
        let verifier = test_config(DEFAULT_ACCESS_TTL);

        let token = issue_token(&signer, Uuid::new_v4(), None, TEST_AUD).unwrap();

        match verify_token(&verifier, &token, TEST_AUD) {
            Err(JwtError::WrongIssuer) => {}
            other => panic!("expected WrongIssuer, got {other:?}"),
        }
    }

    #[test]
    fn malformed_token_rejected() {
        let config = test_config(DEFAULT_ACCESS_TTL);
        match verify_token(&config, "not.a.jwt", TEST_AUD) {
            Err(JwtError::Invalid) => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn claims_exp_is_ttl_from_now() {
        let config = test_config(Duration::from_secs(900));
        let token = issue_token(&config, Uuid::new_v4(), None, TEST_AUD).unwrap();
        let claims = verify_token(&config, &token, TEST_AUD).unwrap();

        let now = Utc::now().timestamp();
        assert!(claims.exp >= now + 895);
        assert!(claims.exp <= now + 905);
    }

    #[test]
    fn wrong_audience_rejected() {
        let config = test_config(DEFAULT_ACCESS_TTL);
        let token = issue_token(&config, Uuid::new_v4(), None, "ferrvault").unwrap();

        match verify_token(&config, &token, "ferrtrack") {
            Err(JwtError::WrongAudience) => {}
            other => panic!("expected WrongAudience, got {other:?}"),
        }
    }

    #[test]
    fn multi_audience_token_verifies_against_each_member() {
        let config = test_config(DEFAULT_ACCESS_TTL);
        let token = issue_token_for(
            &config,
            Uuid::new_v4(),
            None,
            vec!["ferrvault".into(), "ferrtrack".into()],
        )
        .unwrap();

        verify_token(&config, &token, "ferrvault").unwrap();
        verify_token(&config, &token, "ferrtrack").unwrap();

        match verify_token(&config, &token, "ferrgrowth") {
            Err(JwtError::WrongAudience) => {}
            other => panic!("expected WrongAudience, got {other:?}"),
        }
    }

    #[test]
    fn missing_audience_claim_rejected() {
        let config = test_config(DEFAULT_ACCESS_TTL);

        #[derive(Serialize)]
        struct ClaimsNoAud {
            sub: Uuid,
            iss: String,
            exp: i64,
            nbf: i64,
            iat: i64,
        }

        let now = Utc::now().timestamp();
        let bad_claims = ClaimsNoAud {
            sub: Uuid::new_v4(),
            iss: "ferrlabs-test".into(),
            exp: now + 300,
            nbf: now,
            iat: now,
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(DEFAULT_KID.into());
        let token = encode(&header, &bad_claims, &config.encoding_key).unwrap();

        match verify_token(&config, &token, TEST_AUD) {
            Err(JwtError::Invalid) => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn future_nbf_rejected() {
        let config = test_config(DEFAULT_ACCESS_TTL);

        #[derive(Serialize)]
        struct FutureNbfClaims {
            sub: Uuid,
            iss: String,
            aud: Vec<String>,
            exp: i64,
            nbf: i64,
            iat: i64,
        }

        let now = Utc::now().timestamp();
        let claims = FutureNbfClaims {
            sub: Uuid::new_v4(),
            iss: "ferrlabs-test".into(),
            aud: vec![TEST_AUD.into()],
            exp: now + 600,
            nbf: now + 300,
            iat: now,
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(DEFAULT_KID.into());
        let token = encode(&header, &claims, &config.encoding_key).unwrap();

        match verify_token(&config, &token, TEST_AUD) {
            Err(JwtError::NotYetValid) => {}
            other => panic!("expected NotYetValid, got {other:?}"),
        }
    }

    #[test]
    fn multi_kid_verification_kidA_signed_token_verifies_when_other_kids_present() {
        // Two kids mapped: kidA and kidB. We sign with kidA. The verifier
        // accepts both. The kid on the header selects kidA's key — proving
        // header-driven key lookup works even when other keys are present.
        let mut public_pems = HashMap::new();
        public_pems.insert("kidA".to_string(), TEST_PUBLIC_PEM.to_vec());
        public_pems.insert("kidB".to_string(), TEST_PUBLIC_PEM.to_vec());

        let signer = JwtConfig::with_keys(
            TEST_PRIVATE_PEM,
            "kidA",
            public_pems,
            "ferrlabs-test",
            DEFAULT_ACCESS_TTL,
        )
        .unwrap();

        let token = issue_token(&signer, Uuid::new_v4(), None, TEST_AUD).unwrap();
        let claims = verify_token(&signer, &token, TEST_AUD).unwrap();
        assert_eq!(claims.aud, vec![TEST_AUD.to_string()]);
    }

    #[test]
    fn unknown_kid_rejected() {
        // Build a verifier that only knows kidA. Mint a token whose header
        // says kid=kidX. Verifier must reject before even trying to verify
        // the signature.
        let mut verifier_pems = HashMap::new();
        verifier_pems.insert("kidA".to_string(), TEST_PUBLIC_PEM.to_vec());
        let verifier = JwtConfig::with_keys(
            TEST_PRIVATE_PEM,
            "kidA",
            verifier_pems,
            "ferrlabs-test",
            DEFAULT_ACCESS_TTL,
        )
        .unwrap();

        let mut signer_pems = HashMap::new();
        signer_pems.insert("kidX".to_string(), TEST_PUBLIC_PEM.to_vec());
        let signer = JwtConfig::with_keys(
            TEST_PRIVATE_PEM,
            "kidX",
            signer_pems,
            "ferrlabs-test",
            DEFAULT_ACCESS_TTL,
        )
        .unwrap();

        let token = issue_token(&signer, Uuid::new_v4(), None, TEST_AUD).unwrap();

        match verify_token(&verifier, &token, TEST_AUD) {
            Err(JwtError::UnknownKid) => {}
            other => panic!("expected UnknownKid, got {other:?}"),
        }
    }

    #[test]
    fn rotation_overlap_accepts_old_then_rejects_after_dropping_key() {
        // Phase 1: overlap window — both kidOld and kidNew in the verifier
        // map. A token minted under kidOld must verify.
        let mut overlap_pems = HashMap::new();
        overlap_pems.insert("kidOld".to_string(), TEST_PUBLIC_PEM.to_vec());
        overlap_pems.insert("kidNew".to_string(), TEST_PUBLIC_PEM.to_vec());

        let signer_old = JwtConfig::with_keys(
            TEST_PRIVATE_PEM,
            "kidOld",
            overlap_pems.clone(),
            "ferrlabs-test",
            DEFAULT_ACCESS_TTL,
        )
        .unwrap();
        let token_old = issue_token(&signer_old, Uuid::new_v4(), None, TEST_AUD).unwrap();
        verify_token(&signer_old, &token_old, TEST_AUD).unwrap();

        // Phase 2: rotation done, kidOld dropped from verifier map.
        let mut new_only_pems = HashMap::new();
        new_only_pems.insert("kidNew".to_string(), TEST_PUBLIC_PEM.to_vec());
        let post_rotation = JwtConfig::with_keys(
            TEST_PRIVATE_PEM,
            "kidNew",
            new_only_pems,
            "ferrlabs-test",
            DEFAULT_ACCESS_TTL,
        )
        .unwrap();

        match verify_token(&post_rotation, &token_old, TEST_AUD) {
            Err(JwtError::UnknownKid) => {}
            other => panic!("expected UnknownKid, got {other:?}"),
        }
    }
}
