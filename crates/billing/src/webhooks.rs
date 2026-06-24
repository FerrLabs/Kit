//! Stripe webhook signature verification and event parsing.
//!
//! Stripe signs each webhook delivery with the `Stripe-Signature` header,
//! formatted as a comma-separated list of `key=value` pairs:
//!
//! ```text
//! t=1614556800,v1=5257a869e7ecebeda32affa62cdca3fa51cad7e77a0e56ff536d0ce8e108d8bd,v0=...
//! ```
//!
//! `t` is the unix timestamp the event was signed at. Each `v1` is an
//! HMAC-SHA256 of `"{t}.{body}"` keyed by the endpoint's signing secret
//! (`whsec_...`), hex-encoded. We recompute the expected signature, compare it
//! against every `v1` scheme in constant time, and reject deliveries whose
//! timestamp is outside a tolerance window to defeat replay.
//!
//! The verification here is deliberately independent of any Stripe SDK so the
//! security-critical path is pure, has no network or runtime dependency, and
//! is exhaustively unit-tested.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::SignatureError;

type HmacSha256 = Hmac<Sha256>;

/// Default replay-protection window: reject events whose signing timestamp is
/// more than five minutes from now. Matches Stripe's own recommended default.
pub const DEFAULT_TOLERANCE_SECS: i64 = 300;

/// A parsed `Stripe-Signature` header.
struct ParsedHeader {
    timestamp: i64,
    v1_signatures: Vec<Vec<u8>>,
}

fn parse_signature_header(header: &str) -> Result<ParsedHeader, SignatureError> {
    let mut timestamp: Option<i64> = None;
    let mut v1_signatures = Vec::new();

    for pair in header.split(',') {
        let (key, value) = pair
            .split_once('=')
            .ok_or(SignatureError::MalformedHeader)?;
        match key.trim() {
            "t" => {
                timestamp = Some(
                    value
                        .trim()
                        .parse()
                        .map_err(|_| SignatureError::MalformedHeader)?,
                );
            }
            "v1" => {
                let bytes =
                    hex::decode(value.trim()).map_err(|_| SignatureError::MalformedHeader)?;
                v1_signatures.push(bytes);
            }
            _ => {}
        }
    }

    let timestamp = timestamp.ok_or(SignatureError::MalformedHeader)?;
    if v1_signatures.is_empty() {
        return Err(SignatureError::MalformedHeader);
    }

    Ok(ParsedHeader {
        timestamp,
        v1_signatures,
    })
}

fn expected_signature(secret: &[u8], timestamp: i64, body: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(secret)
        .expect("HMAC accepts keys of any length, so this never fails");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    mac.finalize().into_bytes().to_vec()
}

/// Verify a `Stripe-Signature` header against the raw request body.
///
/// `now` is the current unix timestamp (injected so the timestamp-tolerance
/// check is testable). `tolerance_secs` is the maximum absolute drift between
/// the signature's timestamp and `now`.
///
/// On success the verified signing timestamp is returned.
///
/// # Errors
/// - [`SignatureError::MalformedHeader`] — the header could not be parsed.
/// - [`SignatureError::TimestampOutOfTolerance`] — replay-window violation.
/// - [`SignatureError::NoMatch`] — no `v1` signature matched.
pub fn verify_signature(
    payload: &[u8],
    signature_header: &str,
    secret: &[u8],
    now: i64,
    tolerance_secs: i64,
) -> Result<i64, SignatureError> {
    let parsed = parse_signature_header(signature_header)?;

    let tolerance = u64::try_from(tolerance_secs.max(0)).unwrap_or(u64::MAX);
    if now.abs_diff(parsed.timestamp) > tolerance {
        return Err(SignatureError::TimestampOutOfTolerance);
    }

    let expected = expected_signature(secret, parsed.timestamp, payload);

    let matched = parsed
        .v1_signatures
        .iter()
        .any(|candidate| bool::from(candidate.ct_eq(&expected)));

    if matched {
        Ok(parsed.timestamp)
    } else {
        Err(SignatureError::NoMatch)
    }
}

/// Convenience wrapper around an optional header value, e.g. the result of
/// `headers.get("stripe-signature")`. Maps `None` to
/// [`SignatureError::MissingHeader`].
///
/// # Errors
/// Propagates every failure mode of [`verify_signature`], plus
/// [`SignatureError::MissingHeader`] when `signature_header` is `None`.
pub fn verify_optional_signature(
    payload: &[u8],
    signature_header: Option<&str>,
    secret: &[u8],
    now: i64,
    tolerance_secs: i64,
) -> Result<i64, SignatureError> {
    let header = signature_header.ok_or(SignatureError::MissingHeader)?;
    verify_signature(payload, header, secret, now, tolerance_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"whsec_test_secret_value";

    fn sign(body: &[u8], timestamp: i64, secret: &[u8]) -> String {
        let sig = expected_signature(secret, timestamp, body);
        format!("t={timestamp},v1={}", hex::encode(sig))
    }

    #[test]
    fn valid_signature_passes() {
        let body = br#"{"id":"evt_1","type":"invoice.paid"}"#;
        let now = 1_700_000_000;
        let header = sign(body, now, SECRET);

        let ts = verify_signature(body, &header, SECRET, now, DEFAULT_TOLERANCE_SECS).unwrap();
        assert_eq!(ts, now);
    }

    #[test]
    fn signature_within_tolerance_passes() {
        let body = b"payload";
        let signed_at = 1_700_000_000;
        let header = sign(body, signed_at, SECRET);
        let now = signed_at + 120;

        assert!(verify_signature(body, &header, SECRET, now, DEFAULT_TOLERANCE_SECS).is_ok());
    }

    #[test]
    fn tampered_body_fails() {
        let body = b"original payload";
        let now = 1_700_000_000;
        let header = sign(body, now, SECRET);

        let err = verify_signature(
            b"tampered payload",
            &header,
            SECRET,
            now,
            DEFAULT_TOLERANCE_SECS,
        )
        .unwrap_err();
        assert_eq!(err, SignatureError::NoMatch);
    }

    #[test]
    fn tampered_signature_fails() {
        let body = b"payload";
        let now = 1_700_000_000;
        let good = expected_signature(SECRET, now, body);
        let mut bad = good.clone();
        bad[0] ^= 0xff;
        let header = format!("t={now},v1={}", hex::encode(bad));

        let err = verify_signature(body, &header, SECRET, now, DEFAULT_TOLERANCE_SECS).unwrap_err();
        assert_eq!(err, SignatureError::NoMatch);
    }

    #[test]
    fn wrong_secret_fails() {
        let body = b"payload";
        let now = 1_700_000_000;
        let header = sign(body, now, SECRET);

        let err = verify_signature(body, &header, b"whsec_other", now, DEFAULT_TOLERANCE_SECS)
            .unwrap_err();
        assert_eq!(err, SignatureError::NoMatch);
    }

    #[test]
    fn stale_timestamp_fails() {
        let body = b"payload";
        let signed_at = 1_700_000_000;
        let header = sign(body, signed_at, SECRET);
        let now = signed_at + DEFAULT_TOLERANCE_SECS + 1;

        let err = verify_signature(body, &header, SECRET, now, DEFAULT_TOLERANCE_SECS).unwrap_err();
        assert_eq!(err, SignatureError::TimestampOutOfTolerance);
    }

    #[test]
    fn future_timestamp_beyond_tolerance_fails() {
        let body = b"payload";
        let signed_at = 1_700_000_000;
        let header = sign(body, signed_at, SECRET);
        let now = signed_at - DEFAULT_TOLERANCE_SECS - 1;

        let err = verify_signature(body, &header, SECRET, now, DEFAULT_TOLERANCE_SECS).unwrap_err();
        assert_eq!(err, SignatureError::TimestampOutOfTolerance);
    }

    #[test]
    fn header_without_timestamp_is_malformed() {
        let body = b"payload";
        let sig = expected_signature(SECRET, 1_700_000_000, body);
        let header = format!("v1={}", hex::encode(sig));

        let err = verify_signature(body, &header, SECRET, 1_700_000_000, DEFAULT_TOLERANCE_SECS)
            .unwrap_err();
        assert_eq!(err, SignatureError::MalformedHeader);
    }

    #[test]
    fn header_without_v1_is_malformed() {
        let err =
            verify_signature(b"payload", "t=1700000000", SECRET, 1_700_000_000, 300).unwrap_err();
        assert_eq!(err, SignatureError::MalformedHeader);
    }

    #[test]
    fn non_numeric_timestamp_is_malformed() {
        let err = verify_signature(
            b"payload",
            "t=notanumber,v1=abcd",
            SECRET,
            1_700_000_000,
            300,
        )
        .unwrap_err();
        assert_eq!(err, SignatureError::MalformedHeader);
    }

    #[test]
    fn non_hex_v1_is_malformed() {
        let err = verify_signature(
            b"payload",
            "t=1700000000,v1=zzzz",
            SECRET,
            1_700_000_000,
            300,
        )
        .unwrap_err();
        assert_eq!(err, SignatureError::MalformedHeader);
    }

    #[test]
    fn multiple_v1_signatures_one_matching_passes() {
        let body = b"payload";
        let now = 1_700_000_000;
        let good = hex::encode(expected_signature(SECRET, now, body));
        let header = format!("t={now},v1=deadbeef,v1={good}");

        assert!(verify_signature(body, &header, SECRET, now, DEFAULT_TOLERANCE_SECS).is_ok());
    }

    #[test]
    fn missing_header_maps_to_missing_header_error() {
        let err =
            verify_optional_signature(b"payload", None, SECRET, 1_700_000_000, 300).unwrap_err();
        assert_eq!(err, SignatureError::MissingHeader);
    }
}
