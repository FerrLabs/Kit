//! TOTP (RFC 6238) two-factor authentication.
//!
//! ## Seed at rest
//!
//! The TOTP seed is never stored in cleartext. [`TotpEnrollment::seal_seed`]
//! envelope-encrypts it through a [`ferrlabs_crypto::KeyProvider`] (local KEK
//! in dev/self-host, GCP Cloud KMS in hosted) and [`unseal_seed`] reverses it.
//! The DB column holds only the wrapped bytes.
//!
//! ## Verification window
//!
//! Codes are verified with a ±1 step (±30 s) tolerance so a code generated at
//! the boundary of a step still validates, but a code two steps away is
//! rejected. This is the standard skew=1 setting.
//!
//! ## Recovery codes
//!
//! [`generate_recovery_codes`] returns N single-use codes shown to the user
//! **once**. Only their SHA-256 hashes are persisted; [`verify_and_consume`]
//! checks a presented code against the stored hashes in constant time and
//! returns which one matched so the caller can mark it used.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ferrlabs_crypto::SharedKeyProvider;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use totp_rs::{Algorithm, TOTP};

const TOTP_DIGITS: usize = 6;
const TOTP_STEP_SECS: u64 = 30;
const TOTP_SKEW: u8 = 1;
const SECRET_BYTES: usize = 20;

/// Default number of single-use recovery codes minted at enrollment.
pub const DEFAULT_RECOVERY_CODE_COUNT: usize = 10;

/// TOTP issuer shown in authenticator apps.
pub const ISSUER: &str = "FerrLabs";

#[derive(Debug, thiserror::Error)]
pub enum TotpError {
    #[error("invalid totp parameters: {0}")]
    InvalidConfig(String),
    #[error("failed to seal/unseal totp seed: {0}")]
    Crypto(#[source] anyhow::Error),
    #[error("system clock is before the unix epoch")]
    ClockError,
}

/// A freshly enrolled TOTP factor, before the seed is sealed for storage.
///
/// Hold this only long enough to render the provisioning URI / QR and to seal
/// the seed; do not persist the plaintext `seed`.
pub struct TotpEnrollment {
    seed: Vec<u8>,
    account: String,
}

impl TotpEnrollment {
    /// Generate a new random 160-bit TOTP seed for `account_email`.
    #[must_use]
    pub fn generate(account_email: &str) -> Self {
        let seed = rand::random::<[u8; SECRET_BYTES]>().to_vec();
        Self {
            seed,
            account: account_email.to_string(),
        }
    }

    /// Rebuild an enrollment from a seed already unsealed from storage.
    #[must_use]
    pub fn from_seed(seed: Vec<u8>, account_email: &str) -> Self {
        Self {
            seed,
            account: account_email.to_string(),
        }
    }

    fn totp(&self) -> Result<TOTP, TotpError> {
        TOTP::new(
            Algorithm::SHA1,
            TOTP_DIGITS,
            TOTP_SKEW,
            TOTP_STEP_SECS,
            self.seed.clone(),
            Some(ISSUER.to_string()),
            self.account.clone(),
        )
        .map_err(|e| TotpError::InvalidConfig(e.to_string()))
    }

    /// The `otpauth://totp/...` provisioning URI for authenticator apps.
    ///
    /// # Errors
    /// [`TotpError::InvalidConfig`] if the seed/account is rejected by totp-rs.
    pub fn provisioning_uri(&self) -> Result<String, TotpError> {
        Ok(self.totp()?.get_url())
    }

    /// Envelope-encrypt the seed for storage via `key_provider`.
    ///
    /// # Errors
    /// [`TotpError::Crypto`] if the key provider fails to wrap the seed.
    pub async fn seal_seed(&self, key_provider: &SharedKeyProvider) -> Result<Vec<u8>, TotpError> {
        key_provider
            .wrap_dek(&self.seed)
            .await
            .map_err(TotpError::Crypto)
    }

    /// Verify a 6-digit `code` against this seed at `unix_time`, with a ±1 step
    /// tolerance window.
    ///
    /// # Errors
    /// [`TotpError::InvalidConfig`] if the seed/account is invalid.
    pub fn verify_at(&self, code: &str, unix_time: u64) -> Result<bool, TotpError> {
        Ok(self.totp()?.check(code, unix_time))
    }

    /// Verify a 6-digit `code` against the current system time.
    ///
    /// # Errors
    /// - [`TotpError::InvalidConfig`] if the seed/account is invalid.
    /// - [`TotpError::ClockError`] if the system clock predates the unix epoch.
    pub fn verify_now(&self, code: &str) -> Result<bool, TotpError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| TotpError::ClockError)?
            .as_secs();
        self.verify_at(code, now)
    }

    /// Generate the current 6-digit code (test/debug helper).
    ///
    /// # Errors
    /// [`TotpError::InvalidConfig`] if the seed/account is invalid.
    pub fn current_code_at(&self, unix_time: u64) -> Result<String, TotpError> {
        Ok(self.totp()?.generate(unix_time))
    }
}

/// Unseal a stored TOTP seed via `key_provider`.
///
/// # Errors
/// [`TotpError::Crypto`] if the key provider fails to unwrap the seed.
pub async fn unseal_seed(
    key_provider: &SharedKeyProvider,
    sealed: &[u8],
) -> Result<Vec<u8>, TotpError> {
    key_provider
        .unwrap_dek(sealed)
        .await
        .map_err(TotpError::Crypto)
}

/// A single recovery code in plaintext (shown once) paired with its stored hash.
#[derive(Debug, Clone)]
pub struct RecoveryCode {
    pub plaintext: String,
    pub hash: Vec<u8>,
}

/// Hash a recovery code for storage. SHA-256 is sufficient: the codes are
/// high-entropy CSPRNG output, so no password-style stretching is needed —
/// matching [`crate::session::hash_refresh_token`].
#[must_use]
pub fn hash_recovery_code(code: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    hasher.finalize().to_vec()
}

/// Generate `count` single-use recovery codes. The plaintext is returned for
/// one-time display; persist only the `hash` of each.
#[must_use]
pub fn generate_recovery_codes(count: usize) -> Vec<RecoveryCode> {
    (0..count)
        .map(|_| {
            let bytes: [u8; 10] = rand::random();
            let plaintext = URL_SAFE_NO_PAD.encode(bytes);
            let hash = hash_recovery_code(&plaintext);
            RecoveryCode { plaintext, hash }
        })
        .collect()
}

/// Check a presented recovery `code` against the stored `hashes` in constant
/// time. Returns the index of the matching hash so the caller can mark exactly
/// that code consumed, or `None` if nothing matched.
///
/// The comparison is constant-time per candidate to avoid leaking which code
/// (if any) was close via timing.
#[must_use]
pub fn verify_and_consume(code: &str, hashes: &[Vec<u8>]) -> Option<usize> {
    let presented = hash_recovery_code(code);
    let mut matched: Option<usize> = None;
    for (idx, stored) in hashes.iter().enumerate() {
        if bool::from(presented.ct_eq(stored)) {
            matched = Some(idx);
        }
    }
    matched
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrlabs_crypto::LocalKek;
    use std::sync::Arc;

    #[test]
    fn provisioning_uri_has_issuer_and_account() {
        let enrollment = TotpEnrollment::generate("ada@example.com");
        let uri = enrollment.provisioning_uri().unwrap();
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("issuer=FerrLabs"));
        assert!(uri.contains("ada%40example.com") || uri.contains("ada@example.com"));
    }

    #[test]
    fn rfc6238_sha1_known_vectors() {
        // RFC 6238 Appendix B uses the ASCII seed "12345678901234567890" with
        // SHA-1, 8 digits, 30 s step. We assert against an 8-digit TOTP built
        // on that seed so the values match the published table.
        let seed = b"12345678901234567890".to_vec();
        let totp = TOTP::new(
            Algorithm::SHA1,
            8,
            1,
            30,
            seed,
            Some(ISSUER.to_string()),
            "rfc6238@example.com".to_string(),
        )
        .unwrap();

        assert_eq!(totp.generate(59), "94287082");
        assert_eq!(totp.generate(1_111_111_109), "07081804");
        assert_eq!(totp.generate(1_234_567_890), "89005924");
        assert_eq!(totp.generate(2_000_000_000), "69279037");
    }

    #[test]
    fn code_for_current_step_verifies() {
        let enrollment = TotpEnrollment::generate("user@example.com");
        let t = 1_700_000_000;
        let code = enrollment.current_code_at(t).unwrap();
        assert!(enrollment.verify_at(&code, t).unwrap());
    }

    #[test]
    fn code_from_previous_step_within_tolerance_verifies() {
        let enrollment = TotpEnrollment::generate("user@example.com");
        let t = 1_700_000_000;
        let prev = enrollment.current_code_at(t - TOTP_STEP_SECS).unwrap();
        assert!(enrollment.verify_at(&prev, t).unwrap());
    }

    #[test]
    fn code_from_next_step_within_tolerance_verifies() {
        let enrollment = TotpEnrollment::generate("user@example.com");
        let t = 1_700_000_000;
        let next = enrollment.current_code_at(t + TOTP_STEP_SECS).unwrap();
        assert!(enrollment.verify_at(&next, t).unwrap());
    }

    #[test]
    fn code_two_steps_away_is_rejected() {
        let enrollment = TotpEnrollment::generate("user@example.com");
        let t = 1_700_000_000;
        let stale = enrollment.current_code_at(t - 2 * TOTP_STEP_SECS).unwrap();
        let future = enrollment.current_code_at(t + 2 * TOTP_STEP_SECS).unwrap();
        assert!(!enrollment.verify_at(&stale, t).unwrap());
        assert!(!enrollment.verify_at(&future, t).unwrap());
    }

    #[test]
    fn wrong_code_is_rejected() {
        let enrollment = TotpEnrollment::generate("user@example.com");
        assert!(!enrollment.verify_at("000000", 1_700_000_000).unwrap());
    }

    #[tokio::test]
    async fn seed_seal_unseal_round_trips() {
        let provider: SharedKeyProvider = Arc::new(LocalKek::new(vec![7u8; 32]));
        let enrollment = TotpEnrollment::generate("user@example.com");
        let original_code = enrollment.current_code_at(1_700_000_000).unwrap();

        let sealed = enrollment.seal_seed(&provider).await.unwrap();
        let unsealed = unseal_seed(&provider, &sealed).await.unwrap();

        let restored = TotpEnrollment::from_seed(unsealed, "user@example.com");
        let restored_code = restored.current_code_at(1_700_000_000).unwrap();
        assert_eq!(original_code, restored_code);
    }

    #[tokio::test]
    async fn sealed_seed_is_not_plaintext() {
        let provider: SharedKeyProvider = Arc::new(LocalKek::new(vec![3u8; 32]));
        let enrollment = TotpEnrollment::generate("user@example.com");
        let sealed = enrollment.seal_seed(&provider).await.unwrap();
        let unsealed = unseal_seed(&provider, &sealed).await.unwrap();
        assert_ne!(
            sealed, unsealed,
            "sealed bytes must differ from the raw seed"
        );
        assert_eq!(unsealed.len(), SECRET_BYTES);
    }

    #[test]
    fn recovery_codes_are_unique_and_hashed() {
        let codes = generate_recovery_codes(DEFAULT_RECOVERY_CODE_COUNT);
        assert_eq!(codes.len(), DEFAULT_RECOVERY_CODE_COUNT);

        let plaintexts: std::collections::HashSet<_> =
            codes.iter().map(|c| c.plaintext.clone()).collect();
        assert_eq!(
            plaintexts.len(),
            DEFAULT_RECOVERY_CODE_COUNT,
            "codes must be unique"
        );

        for code in &codes {
            assert_eq!(code.hash, hash_recovery_code(&code.plaintext));
            assert_ne!(code.hash.as_slice(), code.plaintext.as_bytes());
            assert_eq!(code.hash.len(), 32);
        }
    }

    #[test]
    fn verify_and_consume_matches_correct_index() {
        let codes = generate_recovery_codes(5);
        let hashes: Vec<Vec<u8>> = codes.iter().map(|c| c.hash.clone()).collect();

        let idx = verify_and_consume(&codes[3].plaintext, &hashes);
        assert_eq!(idx, Some(3));
    }

    #[test]
    fn verify_and_consume_rejects_unknown_code() {
        let codes = generate_recovery_codes(5);
        let hashes: Vec<Vec<u8>> = codes.iter().map(|c| c.hash.clone()).collect();
        assert_eq!(verify_and_consume("not-a-real-code", &hashes), None);
    }

    #[test]
    fn consumed_code_no_longer_matches_remaining() {
        let codes = generate_recovery_codes(3);
        let mut hashes: Vec<Vec<u8>> = codes.iter().map(|c| c.hash.clone()).collect();

        let idx = verify_and_consume(&codes[1].plaintext, &hashes).unwrap();
        hashes.remove(idx);
        assert_eq!(verify_and_consume(&codes[1].plaintext, &hashes), None);
        assert!(verify_and_consume(&codes[0].plaintext, &hashes).is_some());
    }
}
