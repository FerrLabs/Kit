#![forbid(unsafe_code)]
//! Inbound webhook verification primitives.
//!
//! Two concerns: verifying that a payload was signed with a shared secret
//! (HMAC-SHA256, constant-time comparison) and ensuring a redelivered event is
//! processed at most once ([`DeliveryStore`]).

use dashmap::DashSet;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Why a signature failed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    /// The header was not in a recognised format.
    MalformedHeader,
    /// The signature did not match the computed HMAC.
    Mismatch,
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedHeader => f.write_str("malformed signature header"),
            Self::Mismatch => f.write_str("signature mismatch"),
        }
    }
}

impl std::error::Error for SignatureError {}

fn compute(secret: &[u8], body: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(body);
    mac.finalize().into_bytes().into()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Verify a raw hex-encoded HMAC-SHA256 signature against `body`.
///
/// The comparison is constant-time to avoid leaking the secret via timing.
pub fn verify_hex(secret: &[u8], body: &[u8], signature_hex: &str) -> Result<(), SignatureError> {
    let provided =
        hex::decode(signature_hex.trim()).map_err(|_| SignatureError::MalformedHeader)?;
    let expected = compute(secret, body);
    if ct_eq(&expected, &provided) {
        Ok(())
    } else {
        Err(SignatureError::Mismatch)
    }
}

/// Verify a GitHub-style `sha256=<hex>` signature header against `body`.
pub fn verify_github(secret: &[u8], body: &[u8], header: &str) -> Result<(), SignatureError> {
    let hex_part = header
        .trim()
        .strip_prefix("sha256=")
        .ok_or(SignatureError::MalformedHeader)?;
    verify_hex(secret, body, hex_part)
}

/// Produce the GitHub-style signature header value for a body. Useful in tests
/// and for outbound signing.
#[must_use]
pub fn sign_github(secret: &[u8], body: &[u8]) -> String {
    format!("sha256={}", hex::encode(compute(secret, body)))
}

/// Tracks which webhook deliveries have already been processed so redeliveries
/// are dropped.
pub trait DeliveryStore: Send + Sync {
    /// Whether `delivery_id` has already been recorded.
    fn seen(&self, delivery_id: &str) -> bool;

    /// Record `delivery_id`. Returns `true` if it was newly inserted, `false`
    /// if it was already present.
    fn record(&self, delivery_id: &str) -> bool;
}

/// In-memory [`DeliveryStore`] backed by a [`DashSet`]. Suitable for tests and
/// single-process deployments; swap for a shared store across replicas.
#[derive(Default)]
pub struct InMemoryDeliveryStore {
    seen: DashSet<String>,
}

impl InMemoryDeliveryStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl DeliveryStore for InMemoryDeliveryStore {
    fn seen(&self, delivery_id: &str) -> bool {
        self.seen.contains(delivery_id)
    }

    fn record(&self, delivery_id: &str) -> bool {
        self.seen.insert(delivery_id.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"it's a secret to everybody";
    const BODY: &[u8] = b"Hello, World!";

    #[test]
    fn github_round_trip_verifies() {
        let header = sign_github(SECRET, BODY);
        assert!(verify_github(SECRET, BODY, &header).is_ok());
    }

    #[test]
    fn tampered_body_fails() {
        let header = sign_github(SECRET, BODY);
        assert_eq!(
            verify_github(SECRET, b"Hello, world!", &header),
            Err(SignatureError::Mismatch)
        );
    }

    #[test]
    fn wrong_secret_fails() {
        let header = sign_github(SECRET, BODY);
        assert_eq!(
            verify_github(b"other", BODY, &header),
            Err(SignatureError::Mismatch)
        );
    }

    #[test]
    fn malformed_header_rejected() {
        assert_eq!(
            verify_github(SECRET, BODY, "sha1=deadbeef"),
            Err(SignatureError::MalformedHeader)
        );
        assert_eq!(
            verify_hex(SECRET, BODY, "nothex"),
            Err(SignatureError::MalformedHeader)
        );
    }

    #[test]
    fn raw_hex_format_verifies() {
        let header = sign_github(SECRET, BODY);
        let raw = header.strip_prefix("sha256=").unwrap();
        assert!(verify_hex(SECRET, BODY, raw).is_ok());
    }

    #[test]
    fn ct_eq_handles_length_mismatch() {
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(ct_eq(b"abc", b"abc"));
    }

    #[test]
    fn idempotency_dedups_repeated_delivery() {
        let store = InMemoryDeliveryStore::new();
        assert!(!store.seen("d-1"));
        assert!(store.record("d-1"));
        assert!(store.seen("d-1"));
        assert!(!store.record("d-1"));
    }
}
