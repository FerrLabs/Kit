//! Envelope encryption primitives for FerrLabs.
//!
//! Every secret (FerrVault), OAuth token, and 2FA seed (auth) is encrypted
//! with a unique per-record DEK (Data Encryption Key), which is itself
//! wrapped by a KEK (Key Encryption Key) held in a KMS. The KEK never
//! leaves the KMS — only wrapped DEKs are kept in the database.
//!
//! ## Swapping KMS providers
//!
//! All KMS backends implement the [`KekProvider`] trait. Swap in AWS KMS,
//! GCP Cloud KMS, HashiCorp Vault Transit, or (for dev only) a static key
//! loaded from env.
//!
//! ```ignore
//! let provider = GcpKms::from_env().await?;
//! let envelope = Envelope::new(provider);
//! let blob = envelope.encrypt(b"my-secret").await?;
//! let plaintext = envelope.decrypt(&blob).await?;
//! ```

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub mod providers;

/// Versioned blob stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    /// AES-GCM ciphertext of the plaintext, with nonce prepended.
    pub ciphertext: Vec<u8>,
    /// DEK wrapped by the KEK — opaque, meaningful only to the KMS.
    pub wrapped_dek: Vec<u8>,
    /// KEK identifier (e.g. `projects/.../locations/.../keyRings/.../cryptoKeys/v3`).
    pub kek_id: String,
    /// Algorithm identifier for forward compatibility.
    pub algo: &'static str,
}

/// A pluggable KMS backend. Implementations wrap/unwrap DEKs using a KEK
/// that never leaves the KMS.
#[async_trait]
pub trait KekProvider: Send + Sync {
    /// Generate a fresh DEK and wrap it with the KEK. Returns (plaintext_dek, wrapped_dek).
    async fn generate_dek(&self) -> anyhow::Result<(Vec<u8>, Vec<u8>)>;

    /// Unwrap a previously wrapped DEK.
    async fn unwrap_dek(&self, wrapped: &[u8]) -> anyhow::Result<Vec<u8>>;

    /// Identifier of the current KEK (for blob metadata).
    fn kek_id(&self) -> &str;
}

/// High-level envelope encryption API.
pub struct Envelope<P: KekProvider> {
    provider: P,
}

impl<P: KekProvider> Envelope<P> {
    pub fn new(provider: P) -> Self {
        Self { provider }
    }

    pub async fn encrypt(&self, _plaintext: &[u8]) -> anyhow::Result<EncryptedBlob> {
        // TODO: generate DEK via provider, AES-GCM encrypt plaintext with DEK,
        // zero the DEK from memory, return blob.
        anyhow::bail!("Envelope::encrypt not yet implemented")
    }

    pub async fn decrypt(&self, _blob: &EncryptedBlob) -> anyhow::Result<Vec<u8>> {
        // TODO: unwrap DEK via provider, AES-GCM decrypt ciphertext, zero DEK.
        anyhow::bail!("Envelope::decrypt not yet implemented")
    }
}
