#![forbid(unsafe_code)]
//! Offline license keys for FerrLabs self-host editions.
//!
//! A license is an **EdDSA (ed25519) signed JWT**. FerrLabs mints one with the
//! private key (kept offline, never shipped); the product binary verifies it at
//! startup with the embedded public key. No phone-home, no network — an
//! air-gapped deployment can validate its own license.
//!
//! The product refuses to serve without a valid license (see the self-host RFC,
//! `FerrVault-Cloud#365`). Cloud and FerrLabs-internal deployments run an
//! [`LicenseKind::Admin`] license, which carries no seat or feature limits;
//! customer self-host deployments run an [`LicenseKind::Customer`] license bound
//! to a tier, seat count, and feature set.
//!
//! The `aud` claim binds a license to one product, so a FerrTrack license can
//! never unlock FerrVault even though both verify against the same key.

use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

/// `iss` claim every FerrLabs license carries. Verification rejects any other.
pub const ISSUER: &str = "ferrlabs-licensing";

#[derive(Debug, thiserror::Error)]
pub enum LicenseError {
    #[error("license is malformed or signed with the wrong key")]
    Invalid,
    #[error("license has expired")]
    Expired,
    #[error("license is not valid yet")]
    NotYetValid,
    #[error("license issuer does not match")]
    WrongIssuer,
    #[error("license is for a different product")]
    WrongProduct,
    #[error("failed to load license key: {0}")]
    KeyLoad(String),
    #[error("internal license error")]
    Internal,
}

/// Whether a license is a FerrLabs-internal/cloud key (unlimited) or a
/// customer self-host key (bounded by tier, seats, and features).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseKind {
    /// FerrLabs-internal or cloud deployment. No seat or feature limits.
    Admin,
    /// Customer self-host deployment. Subject to tier / seat / feature limits.
    Customer,
}

/// Subscription tier carried by a customer license. Mirrors the billing
/// convention shared across the FerrLabs suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseTier {
    Free,
    Pro,
    Team,
    Enterprise,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    aud: String,
    exp: i64,
    iat: i64,
    nbf: i64,
    kind: LicenseKind,
    tier: LicenseTier,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    org: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    seats: Option<u32>,
    #[serde(default)]
    features: Vec<String>,
}

/// A verified, decoded license. Only ever produced by
/// [`LicenseVerifier::verify`], so holding one means signature, issuer,
/// product, and validity window have all passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct License {
    pub id: String,
    pub product: String,
    pub org: Option<String>,
    pub kind: LicenseKind,
    pub tier: LicenseTier,
    pub seats: Option<u32>,
    pub features: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl License {
    /// FerrLabs-internal / cloud key — exempt from seat and feature limits.
    #[must_use]
    pub fn is_admin(&self) -> bool {
        matches!(self.kind, LicenseKind::Admin)
    }

    /// Whether `feature` is unlocked. Admin licenses unlock everything.
    #[must_use]
    pub fn allows(&self, feature: &str) -> bool {
        self.is_admin() || self.features.iter().any(|f| f == feature)
    }

    /// Seat ceiling for this license. `None` means unlimited (always so for
    /// an admin license, and for a customer license that sets no seat cap).
    #[must_use]
    pub fn seat_limit(&self) -> Option<u32> {
        if self.is_admin() { None } else { self.seats }
    }
}

/// Verifies licenses against the FerrLabs public key. Cheap to clone.
#[derive(Clone)]
pub struct LicenseVerifier {
    decoding_key: DecodingKey,
}

impl LicenseVerifier {
    /// Build a verifier from the ed25519 SubjectPublicKeyInfo PEM shipped with
    /// the product binary.
    pub fn from_ed25519_pem(public_pem: &[u8]) -> Result<Self, LicenseError> {
        let decoding_key = DecodingKey::from_ed_pem(public_pem)
            .map_err(|e| LicenseError::KeyLoad(format!("public key: {e}")))?;
        Ok(Self { decoding_key })
    }

    /// Verify a license token for `product` (e.g. `"ferrvault"`).
    ///
    /// Checks signature, issuer, audience (`product`), and the `nbf`/`exp`
    /// window with zero leeway.
    pub fn verify(&self, token: &str, product: &str) -> Result<License, LicenseError> {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[ISSUER]);
        validation.set_audience(&[product]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "nbf"]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = 0;

        let claims = decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|e| map_jwt_err(&e))?
            .claims;

        Ok(License {
            id: claims.sub,
            product: claims.aud,
            org: claims.org,
            kind: claims.kind,
            tier: claims.tier,
            seats: claims.seats,
            features: claims.features,
            issued_at: DateTime::from_timestamp(claims.iat, 0).ok_or(LicenseError::Invalid)?,
            expires_at: DateTime::from_timestamp(claims.exp, 0).ok_or(LicenseError::Invalid)?,
        })
    }
}

/// The fields needed to mint a license. Used by the FerrLabs-internal license
/// generator — never by a product binary.
#[derive(Debug, Clone)]
pub struct LicenseSpec {
    pub id: String,
    pub product: String,
    pub org: Option<String>,
    pub kind: LicenseKind,
    pub tier: LicenseTier,
    pub seats: Option<u32>,
    pub features: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Mints licenses with the FerrLabs private key. Only ever instantiated by the
/// offline license generator; the private key is never shipped to customers.
pub struct LicenseSigner {
    encoding_key: EncodingKey,
}

impl LicenseSigner {
    /// Build a signer from the ed25519 PKCS#8 private key PEM.
    pub fn from_ed25519_pem(private_pem: &[u8]) -> Result<Self, LicenseError> {
        let encoding_key = EncodingKey::from_ed_pem(private_pem)
            .map_err(|e| LicenseError::KeyLoad(format!("private key: {e}")))?;
        Ok(Self { encoding_key })
    }

    /// Sign `spec` into a license token.
    pub fn sign(&self, spec: &LicenseSpec) -> Result<String, LicenseError> {
        let claims = Claims {
            sub: spec.id.clone(),
            iss: ISSUER.to_string(),
            aud: spec.product.clone(),
            exp: spec.expires_at.timestamp(),
            iat: spec.issued_at.timestamp(),
            nbf: spec.issued_at.timestamp(),
            kind: spec.kind,
            tier: spec.tier,
            org: spec.org.clone(),
            seats: spec.seats,
            features: spec.features.clone(),
        };
        encode(&Header::new(Algorithm::EdDSA), &claims, &self.encoding_key)
            .map_err(|_| LicenseError::Internal)
    }
}

fn map_jwt_err(e: &jsonwebtoken::errors::Error) -> LicenseError {
    use jsonwebtoken::errors::ErrorKind;
    match e.kind() {
        ErrorKind::ExpiredSignature => LicenseError::Expired,
        ErrorKind::ImmatureSignature => LicenseError::NotYetValid,
        ErrorKind::InvalidIssuer => LicenseError::WrongIssuer,
        ErrorKind::InvalidAudience => LicenseError::WrongProduct,
        _ => LicenseError::Invalid,
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use ed25519_dalek::pkcs8::spki::EncodePublicKey;
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;

    use super::*;

    fn keypair() -> (String, String) {
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

    fn customer_spec() -> LicenseSpec {
        let now = Utc::now();
        LicenseSpec {
            id: "lic_123".into(),
            product: "ferrvault".into(),
            org: Some("acme".into()),
            kind: LicenseKind::Customer,
            tier: LicenseTier::Team,
            seats: Some(25),
            features: vec!["dynamic_secrets".into(), "audit_export".into()],
            issued_at: now,
            expires_at: now + Duration::days(365),
        }
    }

    #[test]
    fn round_trip_customer_license() {
        let (priv_pem, pub_pem) = keypair();
        let signer = LicenseSigner::from_ed25519_pem(priv_pem.as_bytes()).unwrap();
        let verifier = LicenseVerifier::from_ed25519_pem(pub_pem.as_bytes()).unwrap();

        let token = signer.sign(&customer_spec()).unwrap();
        let lic = verifier.verify(&token, "ferrvault").unwrap();

        assert_eq!(lic.id, "lic_123");
        assert_eq!(lic.product, "ferrvault");
        assert_eq!(lic.org.as_deref(), Some("acme"));
        assert_eq!(lic.kind, LicenseKind::Customer);
        assert_eq!(lic.tier, LicenseTier::Team);
        assert_eq!(lic.seat_limit(), Some(25));
        assert!(lic.allows("dynamic_secrets"));
        assert!(!lic.allows("sso"));
        assert!(!lic.is_admin());
    }

    #[test]
    fn admin_license_is_unlimited() {
        let (priv_pem, pub_pem) = keypair();
        let signer = LicenseSigner::from_ed25519_pem(priv_pem.as_bytes()).unwrap();
        let verifier = LicenseVerifier::from_ed25519_pem(pub_pem.as_bytes()).unwrap();

        let now = Utc::now();
        let spec = LicenseSpec {
            id: "lic_internal".into(),
            product: "ferrvault".into(),
            org: None,
            kind: LicenseKind::Admin,
            tier: LicenseTier::Enterprise,
            seats: Some(1),
            features: vec![],
            issued_at: now,
            expires_at: now + Duration::days(3650),
        };
        let token = signer.sign(&spec).unwrap();
        let lic = verifier.verify(&token, "ferrvault").unwrap();

        assert!(lic.is_admin());
        // Admin ignores the encoded seat cap and the empty feature list.
        assert_eq!(lic.seat_limit(), None);
        assert!(lic.allows("anything_at_all"));
    }

    #[test]
    fn expired_license_rejected() {
        let (priv_pem, pub_pem) = keypair();
        let signer = LicenseSigner::from_ed25519_pem(priv_pem.as_bytes()).unwrap();
        let verifier = LicenseVerifier::from_ed25519_pem(pub_pem.as_bytes()).unwrap();

        let now = Utc::now();
        let mut spec = customer_spec();
        spec.issued_at = now - Duration::days(10);
        spec.expires_at = now - Duration::days(1);
        let token = signer.sign(&spec).unwrap();

        match verifier.verify(&token, "ferrvault") {
            Err(LicenseError::Expired) => {}
            other => panic!("expected Expired, got {other:?}"),
        }
    }

    #[test]
    fn not_yet_valid_license_rejected() {
        let (priv_pem, pub_pem) = keypair();
        let signer = LicenseSigner::from_ed25519_pem(priv_pem.as_bytes()).unwrap();
        let verifier = LicenseVerifier::from_ed25519_pem(pub_pem.as_bytes()).unwrap();

        let now = Utc::now();
        let mut spec = customer_spec();
        spec.issued_at = now + Duration::days(2);
        spec.expires_at = now + Duration::days(365);
        let token = signer.sign(&spec).unwrap();

        match verifier.verify(&token, "ferrvault") {
            Err(LicenseError::NotYetValid) => {}
            other => panic!("expected NotYetValid, got {other:?}"),
        }
    }

    #[test]
    fn wrong_product_rejected() {
        let (priv_pem, pub_pem) = keypair();
        let signer = LicenseSigner::from_ed25519_pem(priv_pem.as_bytes()).unwrap();
        let verifier = LicenseVerifier::from_ed25519_pem(pub_pem.as_bytes()).unwrap();

        // Minted for ferrvault, presented to a ferrtrack binary.
        let token = signer.sign(&customer_spec()).unwrap();

        match verifier.verify(&token, "ferrtrack") {
            Err(LicenseError::WrongProduct) => {}
            other => panic!("expected WrongProduct, got {other:?}"),
        }
    }

    #[test]
    fn wrong_key_rejected() {
        let (priv_pem, _) = keypair();
        let (_, other_pub) = keypair();
        let signer = LicenseSigner::from_ed25519_pem(priv_pem.as_bytes()).unwrap();
        let verifier = LicenseVerifier::from_ed25519_pem(other_pub.as_bytes()).unwrap();

        let token = signer.sign(&customer_spec()).unwrap();

        match verifier.verify(&token, "ferrvault") {
            Err(LicenseError::Invalid) => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn tampered_token_rejected() {
        let (priv_pem, pub_pem) = keypair();
        let signer = LicenseSigner::from_ed25519_pem(priv_pem.as_bytes()).unwrap();
        let verifier = LicenseVerifier::from_ed25519_pem(pub_pem.as_bytes()).unwrap();

        let token = signer.sign(&customer_spec()).unwrap();
        let mut bytes = token.into_bytes();
        let last = bytes.last_mut().unwrap();
        *last = if *last == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).unwrap();

        match verifier.verify(&tampered, "ferrvault") {
            Err(LicenseError::Invalid) => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn malformed_token_rejected() {
        let (_, pub_pem) = keypair();
        let verifier = LicenseVerifier::from_ed25519_pem(pub_pem.as_bytes()).unwrap();
        match verifier.verify("not.a.jwt", "ferrvault") {
            Err(LicenseError::Invalid) => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
    }
}
