//! KMS provider implementations.
//!
//! Each provider implements [`crate::KekProvider`]. Swap via config at
//! startup:
//!
//! ```toml
//! [encryption]
//! provider = "gcp-kms"  # or "aws-kms", "vault-transit", "static"
//! ```

use crate::KekProvider;
use async_trait::async_trait;

/// GCP Cloud KMS. Used for hosted FerrLabs.
pub struct GcpKms {
    // TODO: google-cloud-kms client, key_name config
}

#[async_trait]
impl KekProvider for GcpKms {
    async fn generate_dek(&self) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        anyhow::bail!("GcpKms::generate_dek not yet implemented")
    }
    async fn unwrap_dek(&self, _wrapped: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("GcpKms::unwrap_dek not yet implemented")
    }
    fn kek_id(&self) -> &str {
        "gcp-kms:todo"
    }
}

/// AWS KMS. Common BYOK option for self-host customers.
pub struct AwsKms {
    // TODO: aws-sdk-kms client, key_id config
}

#[async_trait]
impl KekProvider for AwsKms {
    async fn generate_dek(&self) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        anyhow::bail!("AwsKms::generate_dek not yet implemented")
    }
    async fn unwrap_dek(&self, _wrapped: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("AwsKms::unwrap_dek not yet implemented")
    }
    fn kek_id(&self) -> &str {
        "aws-kms:todo"
    }
}

/// HashiCorp Vault Transit. Popular with self-host customers who already run Vault.
pub struct VaultTransit {
    // TODO: vault HTTP client, transit key name
}

#[async_trait]
impl KekProvider for VaultTransit {
    async fn generate_dek(&self) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        anyhow::bail!("VaultTransit::generate_dek not yet implemented")
    }
    async fn unwrap_dek(&self, _wrapped: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("VaultTransit::unwrap_dek not yet implemented")
    }
    fn kek_id(&self) -> &str {
        "vault-transit:todo"
    }
}

/// Static key loaded from env — **dev/eval only**. Production must use a real KMS.
///
/// Logs a loud warning on startup to discourage misuse.
pub struct StaticKey {
    // TODO: AES-256 key material from env var
}

impl StaticKey {
    pub fn from_env() -> anyhow::Result<Self> {
        tracing::warn!(
            "StaticKey KEK provider is in use — NOT suitable for production. \
             Set FERRLABS_KEK_PROVIDER=gcp-kms (or aws-kms / vault-transit) for real deployments."
        );
        Ok(Self {})
    }
}

#[async_trait]
impl KekProvider for StaticKey {
    async fn generate_dek(&self) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        anyhow::bail!("StaticKey::generate_dek not yet implemented")
    }
    async fn unwrap_dek(&self, _wrapped: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("StaticKey::unwrap_dek not yet implemented")
    }
    fn kek_id(&self) -> &str {
        "static:v1"
    }
}
