//! Envelope encryption primitives.
//!
//! Secrets are encrypted with per-row DEKs (data encryption keys, AES-GCM-256);
//! DEKs are wrapped by a KEK (key encryption key) that's either a raw local
//! byte array (dev / self-host) or a GCP Cloud KMS `CryptoKey` (hosted).
//!
//! The [`KeyProvider`] trait abstracts the KEK so the rest of the code
//! doesn't care where the unwrap happens. A short-lived in-memory cache
//! amortises round-trips to the managed backend — revealing 50 secrets from
//! a vault becomes 1 KMS call + 49 cache hits instead of 50 round-trips.
//!
//! ## AAD binding (breaking change in 0.3.0)
//!
//! [`encrypt_value`] / [`decrypt_value`] and [`KeyProvider::wrap_dek`] /
//! [`KeyProvider::unwrap_dek`] take a mandatory `aad: &[u8]` argument that
//! is bound into the AES-GCM authentication tag. Callers are expected to
//! derive this from a stable, immutable identifier of the record the
//! ciphertext lives in — typically `org_id|vault_id|secret_id|version`
//! concatenated as bytes. The exact encoding does not matter as long as it
//! is identical on encrypt and decrypt; mismatched AAD causes
//! authentication failure.
//!
//! The AAD must be **immutable for the lifetime of the ciphertext**. If the
//! record gets a new identity (e.g. moved between orgs by an admin tool),
//! the ciphertext must be decrypted with the old AAD and re-encrypted with
//! the new one.
//!
//! Passing `&[]` is legal and reproduces the pre-0.3 behaviour, but it is
//! the caller's explicit decision rather than the silent default.
//!
//! ### Migration from 0.2.x
//!
//! Existing rows encrypted with the empty-AAD API can be migrated lazily:
//!
//! 1. On read, decrypt with `aad = &[]`.
//! 2. Re-encrypt with the bound AAD.
//! 3. Write back the new ciphertext.
//!
//! Downstream consumers (`FerrLabs-Cloud/api`, `FerrVault-Cloud/api`) own
//! the migration timing — the crate does not gate on a stored format
//! marker, so both shapes round-trip independently as long as the caller
//! remembers which AAD a given row was sealed with.
//!
//! TODO: add AWS KMS and `HashiCorp` Vault Transit providers behind the same
//! [`KeyProvider`] trait for BYOK self-host customers.

pub mod gcp_kms;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, Payload, rand_core::RngCore},
};
use async_trait::async_trait;
use tokio::sync::Mutex;

const NONCE_SIZE: usize = 12;

fn rng() -> impl RngCore {
    aes_gcm::aead::OsRng
}

#[must_use]
pub fn generate_dek() -> Vec<u8> {
    let mut dek = vec![0u8; 32];
    rng().fill_bytes(&mut dek);
    dek
}

/// Encrypt `plaintext` under `dek` with AES-256-GCM, binding `aad` into the
/// authentication tag. The returned bytes are `nonce || ciphertext_and_tag`.
///
/// The AAD must be reproduced byte-for-byte on [`decrypt_value`]; see the
/// crate-level docs for the binding contract.
///
/// # Errors
/// Returns an error if the underlying AEAD encryption fails (in practice
/// only on integer overflow for impossibly large inputs).
pub fn encrypt_value(plaintext: &[u8], dek: &[u8], aad: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    let key = Key::<Aes256Gcm>::from_slice(dek);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt `encrypted` under `dek`, requiring `aad` to match the value
/// passed to [`encrypt_value`] exactly. Mismatched AAD surfaces as a
/// decryption error — by design, indistinguishable from a tampered
/// ciphertext or wrong key.
///
/// # Errors
/// Returns an error if `encrypted` is shorter than the nonce, if the AAD
/// does not match, or if the ciphertext has been tampered with.
pub fn decrypt_value(encrypted: &[u8], dek: &[u8], aad: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    if encrypted.len() < NONCE_SIZE {
        return Err(anyhow::anyhow!("ciphertext too short"));
    }

    let key = Key::<Aes256Gcm>::from_slice(dek);
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(&encrypted[..NONCE_SIZE]);
    let ciphertext = &encrypted[NONCE_SIZE..];

    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|e| anyhow::anyhow!("decryption failed: {e}"))
}

pub fn parse_kek(hex_key: &str) -> Result<Vec<u8>, anyhow::Error> {
    let bytes = hex::decode(hex_key)?;
    if bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "ENCRYPTION_KEY must be 32 bytes (64 hex chars), got {}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// KeyProvider — the abstraction that picks between local-KEK and GCP KMS
// ---------------------------------------------------------------------------

/// Wraps and unwraps DEKs. Implementations are swappable at startup based on
/// env: `LocalKek` for dev / self-host, `GcpKmsKek` for hosted.
///
/// `aad` follows the same binding contract as [`encrypt_value`] — typically
/// the identifier of the secret whose DEK is being wrapped. On the GCP KMS
/// backend it is forwarded as `additionalAuthenticatedData` on the
/// encrypt/decrypt RPC; on the local KEK backend it is bound into the
/// AES-GCM tag.
///
/// Ciphertext encoding differs between backends and is intentionally opaque
/// to callers. The discriminator is carried on the ciphertext bytes
/// themselves (see [`is_gcp_kms_ciphertext`]), so the same DB column can hold
/// rows from both backends during a migration window.
#[async_trait]
pub trait KeyProvider: Send + Sync {
    async fn wrap_dek(
        &self,
        plaintext_dek: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, anyhow::Error>;
    async fn unwrap_dek(
        &self,
        encrypted_dek: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, anyhow::Error>;

    /// Cheap liveness probe for the key backend. Called by `/readyz`.
    /// For `LocalKek` this is a no-op; for `GcpKmsKek` it performs (at most)
    /// one cached wrap against the configured key so a KMS outage surfaces
    /// as 503 on the readiness endpoint.
    async fn health_check(&self) -> Result<(), anyhow::Error> {
        Ok(())
    }
}

/// GCP Cloud KMS emits base64-encoded ciphertexts that are ASCII-only.
/// Local KEK wraps produce raw binary AES-GCM bytes (12-byte nonce +
/// ciphertext) which are almost always not valid UTF-8. We wrap the GCP
/// ciphertext with a `gcp-kms:` prefix so the `unwrap_dek` dispatch can
/// tell the backends apart by looking at the stored bytes alone.
pub const GCP_KMS_PREFIX: &[u8] = b"gcp-kms:";

#[must_use]
pub fn is_gcp_kms_ciphertext(bytes: &[u8]) -> bool {
    bytes.starts_with(GCP_KMS_PREFIX)
}

// ---------------------------------------------------------------------------
// Local KEK backend
// ---------------------------------------------------------------------------

/// Raw AES-GCM KEK held in process memory. Used in `development` and
/// `selfhosted` modes where the customer doesn't run GCP KMS. Ciphertext is
/// the raw AES-GCM output — no discriminator prefix (we detect its absence
/// to route to this backend on unwrap).
pub struct LocalKek {
    kek: Vec<u8>,
}

impl LocalKek {
    #[must_use]
    pub fn new(kek: Vec<u8>) -> Self {
        Self { kek }
    }
}

#[async_trait]
impl KeyProvider for LocalKek {
    async fn wrap_dek(
        &self,
        plaintext_dek: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, anyhow::Error> {
        encrypt_value(plaintext_dek, &self.kek, aad)
    }
    async fn unwrap_dek(
        &self,
        encrypted_dek: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, anyhow::Error> {
        if is_gcp_kms_ciphertext(encrypted_dek) {
            return Err(anyhow::anyhow!(
                "secret was wrapped by GCP Cloud KMS but the API is running with a local \
                 KEK — switch the backend or run the re-wrap migration"
            ));
        }
        decrypt_value(encrypted_dek, &self.kek, aad)
    }
}

// ---------------------------------------------------------------------------
// Convenience types shared by the KMS backend
// ---------------------------------------------------------------------------

struct CachedDek {
    plaintext: Vec<u8>,
    cached_at: Instant,
}

pub type SharedKeyProvider = Arc<dyn KeyProvider>;

// ---------------------------------------------------------------------------
// GCP Cloud KMS backend
// ---------------------------------------------------------------------------

/// Wraps DEKs against a GCP Cloud KMS `CryptoKey`. The key material never
/// leaves Google's infrastructure — the API calls `encrypt`/`decrypt` on the
/// managed service and stores GCP's base64 ciphertext, prefixed with
/// `gcp-kms:` so the unwrap dispatch can route correctly.
///
/// Credentials come from Application Default Credentials: `gcloud auth
/// application-default login` on a dev laptop, `GOOGLE_APPLICATION_CREDENTIALS`
/// pointing at a service-account JSON file, or the GCE/GKE metadata server
/// for Workload Identity. The [`gcp_auth`] crate picks the right one.
pub struct GcpKmsKek {
    client: crate::gcp_kms::GcpKmsClient,
    key_name: String,
    cache: Mutex<HashMap<CacheKey, CachedDek>>,
    ttl: Duration,
    max_entries: usize,
    /// Last successful health check, if any. `/readyz` re-probes GCP at most
    /// once every 10 s so repeated scrapes don't hammer the KMS quota.
    last_health_ok: Mutex<Option<Instant>>,
}

#[derive(Hash, PartialEq, Eq, Clone)]
struct CacheKey {
    ciphertext: Vec<u8>,
    aad: Vec<u8>,
}

impl GcpKmsKek {
    #[must_use]
    pub fn new(client: crate::gcp_kms::GcpKmsClient, key_name: String) -> Self {
        Self {
            client,
            key_name,
            cache: Mutex::new(HashMap::new()),
            // 60s: absorbs burst reveals (50 secrets from one vault = 1 GCP
            // KMS call + 49 hits), short enough that a GCP-side key rotation
            // propagates within a minute without operator action.
            ttl: Duration::from_secs(60),
            // Bounded so a request-flood of distinct ciphertexts can't OOM.
            // 1024 × ~64 bytes ≈ 64 KiB worst case.
            max_entries: 1024,
            last_health_ok: Mutex::new(None),
        }
    }

    async fn cache_get(&self, key: &CacheKey) -> Option<Vec<u8>> {
        let mut cache = self.cache.lock().await;
        if let Some(entry) = cache.get(key) {
            if entry.cached_at.elapsed() < self.ttl {
                return Some(entry.plaintext.clone());
            }
            cache.remove(key);
        }
        None
    }

    async fn cache_put(&self, key: CacheKey, plaintext: Vec<u8>) {
        let mut cache = self.cache.lock().await;
        if cache.len() >= self.max_entries {
            let mut entries: Vec<_> = cache.drain().collect();
            entries.sort_by_key(|(_, v)| v.cached_at);
            for (k, v) in entries.into_iter().skip(self.max_entries / 2) {
                cache.insert(k, v);
            }
        }
        cache.insert(
            key,
            CachedDek {
                plaintext,
                cached_at: Instant::now(),
            },
        );
    }
}

#[async_trait]
impl KeyProvider for GcpKmsKek {
    async fn wrap_dek(
        &self,
        plaintext_dek: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, anyhow::Error> {
        let ct = self
            .client
            .encrypt(&self.key_name, plaintext_dek, aad)
            .await
            .map_err(|e| anyhow::anyhow!("gcp kms encrypt: {e}"))?;
        // `gcp-kms:` + ASCII base64 ciphertext. Simple string concat; the
        // prefix is just a marker for the backend-routing in `unwrap_dek`.
        let mut out = Vec::with_capacity(GCP_KMS_PREFIX.len() + ct.len());
        out.extend_from_slice(GCP_KMS_PREFIX);
        out.extend_from_slice(ct.as_bytes());
        Ok(out)
    }

    async fn unwrap_dek(
        &self,
        encrypted_dek: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, anyhow::Error> {
        if !is_gcp_kms_ciphertext(encrypted_dek) {
            return Err(anyhow::anyhow!(
                "secret was wrapped by a local KEK but the API is running against GCP \
                 Cloud KMS — run the re-wrap migration"
            ));
        }
        let cache_key = CacheKey {
            ciphertext: encrypted_dek.to_vec(),
            aad: aad.to_vec(),
        };
        if let Some(cached) = self.cache_get(&cache_key).await {
            return Ok(cached);
        }
        let ct = std::str::from_utf8(&encrypted_dek[GCP_KMS_PREFIX.len()..])
            .map_err(|e| anyhow::anyhow!("gcp kms ciphertext not utf-8: {e}"))?;
        let plaintext = self
            .client
            .decrypt(&self.key_name, ct, aad)
            .await
            .map_err(|e| anyhow::anyhow!("gcp kms decrypt: {e}"))?;
        self.cache_put(cache_key, plaintext.clone()).await;
        Ok(plaintext)
    }

    async fn health_check(&self) -> Result<(), anyhow::Error> {
        // Short-circuit if we succeeded within the last 10 s. Readyz gets
        // scraped frequently — we don't want to burn a real KMS call on every
        // probe, but we also don't want to cache a stale "ok" longer than
        // necessary when the backend starts misbehaving.
        {
            let guard = self.last_health_ok.lock().await;
            if let Some(t) = *guard
                && t.elapsed() < Duration::from_secs(10)
            {
                return Ok(());
            }
        }

        self.client
            .encrypt(&self.key_name, b"readyz-probe", b"")
            .await
            .map_err(|e| anyhow::anyhow!("gcp kms health probe: {e}"))?;

        *self.last_health_ok.lock().await = Some(Instant::now());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_AAD: &[u8] = b"org=123|secret=abc|version=1";

    #[tokio::test]
    async fn local_kek_round_trip() {
        let kek = vec![1u8; 32];
        let provider = LocalKek::new(kek);
        let dek = generate_dek();
        let wrapped = provider.wrap_dek(&dek, TEST_AAD).await.unwrap();
        let unwrapped = provider.unwrap_dek(&wrapped, TEST_AAD).await.unwrap();
        assert_eq!(dek, unwrapped);
    }

    #[tokio::test]
    async fn local_kek_refuses_gcp_ciphertext() {
        let provider = LocalKek::new(vec![1u8; 32]);
        let err = provider
            .unwrap_dek(b"gcp-kms:CiQA0xxxx-base64-gcp-ciphertext", TEST_AAD)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("GCP Cloud KMS"));
    }

    #[tokio::test]
    async fn local_kek_rejects_mismatched_aad() {
        let provider = LocalKek::new(vec![1u8; 32]);
        let dek = generate_dek();
        let wrapped = provider.wrap_dek(&dek, b"org=A|secret=1").await.unwrap();
        let err = provider
            .unwrap_dek(&wrapped, b"org=B|secret=1")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("decryption failed"));
    }

    #[test]
    fn gcp_ciphertext_detection() {
        assert!(is_gcp_kms_ciphertext(b"gcp-kms:CiQA0"));
        assert!(!is_gcp_kms_ciphertext(b"vault:v1:abc"));
        assert!(!is_gcp_kms_ciphertext(&[0u8; 32]));
        assert!(!is_gcp_kms_ciphertext(b"gcp"));
    }

    #[tokio::test]
    async fn encrypt_decrypt_value_round_trips_with_aad() {
        let dek = generate_dek();
        let message = b"hunter2 is a terrible password";
        let ct = encrypt_value(message, &dek, TEST_AAD).unwrap();
        let pt = decrypt_value(&ct, &dek, TEST_AAD).unwrap();
        assert_eq!(pt, message);
    }

    #[tokio::test]
    async fn encrypt_decrypt_value_round_trips_with_empty_aad() {
        let dek = generate_dek();
        let message = b"empty AAD must remain legal";
        let ct = encrypt_value(message, &dek, &[]).unwrap();
        let pt = decrypt_value(&ct, &dek, &[]).unwrap();
        assert_eq!(pt, message);
    }

    #[tokio::test]
    async fn decrypt_value_fails_on_mismatched_aad() {
        let dek = generate_dek();
        let ct = encrypt_value(b"payload", &dek, b"context-1").unwrap();
        let err = decrypt_value(&ct, &dek, b"context-2").unwrap_err();
        assert!(err.to_string().contains("decryption failed"));
    }

    #[tokio::test]
    async fn decrypt_value_fails_when_aad_missing_after_encrypt() {
        let dek = generate_dek();
        let ct = encrypt_value(b"payload", &dek, b"context-1").unwrap();
        let err = decrypt_value(&ct, &dek, &[]).unwrap_err();
        assert!(err.to_string().contains("decryption failed"));
    }

    #[tokio::test]
    async fn decrypt_value_detects_ciphertext_tampering() {
        let dek = generate_dek();
        let mut ct = encrypt_value(b"payload", &dek, TEST_AAD).unwrap();
        let last = ct.last_mut().unwrap();
        *last ^= 0x01;
        let err = decrypt_value(&ct, &dek, TEST_AAD).unwrap_err();
        assert!(err.to_string().contains("decryption failed"));
    }

    #[tokio::test]
    async fn value_swap_between_records_is_rejected() {
        let dek = generate_dek();
        let aad_a = b"org=1|secret=A";
        let aad_b = b"org=1|secret=B";

        let ct_a = encrypt_value(b"value-of-a", &dek, aad_a).unwrap();

        // Attacker copies record A's ciphertext into record B's row.
        // Decrypting with record B's AAD must fail.
        let err = decrypt_value(&ct_a, &dek, aad_b).unwrap_err();
        assert!(err.to_string().contains("decryption failed"));
    }
}
