//! Minimal Google Cloud KMS client.
//!
//! Only the three operations `FerrFlow` needs —
//!
//! - **`encrypt`** / **`decrypt`** against a symmetric `CryptoKey` for the KEK.
//!   The plaintext DEK never leaves Google's infrastructure; we store the
//!   opaque base64 ciphertext in Postgres and ask GCP to unwrap on reveal.
//! - **`asymmetricSign`** against an Ed25519 `CryptoKeyVersion` for install
//!   licenses. GCP signs the raw JWT `<header>.<payload>` and returns the
//!   64-byte Ed25519 signature; we assemble the final compact JWT.
//!
//! Auth is delegated to [`gcp_auth`], which walks the standard ADC chain:
//! `GOOGLE_APPLICATION_CREDENTIALS` file, `~/.config/gcloud/...json`, GCE
//! metadata server (for Workload Identity on GKE). The token is cached and
//! auto-refreshed — we just call `token()` before each request.

use std::sync::Arc;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD as b64};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

/// Target scope for Cloud KMS. Must be exact for the auth library to mint a
/// correctly-scoped token.
const KMS_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

const KMS_BASE: &str = "https://cloudkms.googleapis.com/v1";

/// Thin GCP KMS client. Cheap to clone — internal `Arc`s.
#[derive(Clone)]
pub struct GcpKmsClient {
    inner: Arc<Inner>,
}

struct Inner {
    http: reqwest::Client,
    auth: Arc<dyn gcp_auth::TokenProvider>,
}

impl GcpKmsClient {
    /// Build a client using the standard Application Default Credentials
    /// chain. Fails if no credentials are discoverable (no ADC file, no
    /// metadata server, no `GOOGLE_APPLICATION_CREDENTIALS`).
    pub async fn from_adc() -> Result<Self, KmsError> {
        let auth = gcp_auth::provider()
            .await
            .map_err(|e| KmsError::Auth(format!("resolve credentials: {e}")))?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("reqwest client build");
        Ok(Self {
            inner: Arc::new(Inner { http, auth }),
        })
    }

    async fn bearer(&self) -> Result<String, KmsError> {
        let token = self
            .inner
            .auth
            .token(&[KMS_SCOPE])
            .await
            .map_err(|e| KmsError::Auth(format!("fetch token: {e}")))?;
        Ok(token.as_str().to_string())
    }

    /// Encrypt `plaintext` with the symmetric `CryptoKey` at `key_name`
    /// (full resource path — `projects/*/locations/*/keyRings/*/cryptoKeys/*`).
    /// Returns the opaque base64 ciphertext as emitted by GCP.
    pub async fn encrypt(&self, key_name: &str, plaintext: &[u8]) -> Result<String, KmsError> {
        #[derive(Serialize)]
        struct Body {
            plaintext: String,
        }
        let token = self.bearer().await?;
        let resp = self
            .inner
            .http
            .post(format!("{KMS_BASE}/{key_name}:encrypt"))
            .bearer_auth(token)
            .json(&Body {
                plaintext: b64.encode(plaintext),
            })
            .send()
            .await
            .map_err(KmsError::Http)?;
        let out: EncryptResponse = parse(resp).await?;
        Ok(out.ciphertext)
    }

    /// Decrypt `ciphertext` (the string we stored, as returned by `encrypt`).
    pub async fn decrypt(&self, key_name: &str, ciphertext: &str) -> Result<Vec<u8>, KmsError> {
        #[derive(Serialize)]
        struct Body<'a> {
            ciphertext: &'a str,
        }
        let token = self.bearer().await?;
        let resp = self
            .inner
            .http
            .post(format!("{KMS_BASE}/{key_name}:decrypt"))
            .bearer_auth(token)
            .json(&Body { ciphertext })
            .send()
            .await
            .map_err(KmsError::Http)?;
        let out: DecryptResponse = parse(resp).await?;
        b64.decode(&out.plaintext)
            .map_err(|e| KmsError::Protocol(format!("bad base64 in plaintext: {e}")))
    }

    /// Sign `message` with an Ed25519 `CryptoKeyVersion`. `version_name` must
    /// be the FULL resource path down to the version —
    /// `projects/*/locations/*/keyRings/*/cryptoKeys/*/cryptoKeyVersions/*`.
    ///
    /// Ed25519 signs the message directly (no pre-hash), which matches JWT
    /// `EdDSA` semantics; we just concatenate the returned signature into the
    /// JWT compact form.
    pub async fn asymmetric_sign_ed25519(
        &self,
        version_name: &str,
        message: &[u8],
    ) -> Result<Vec<u8>, KmsError> {
        #[derive(Serialize)]
        struct Body {
            data: String,
        }
        let token = self.bearer().await?;
        let resp = self
            .inner
            .http
            .post(format!("{KMS_BASE}/{version_name}:asymmetricSign"))
            .bearer_auth(token)
            .json(&Body {
                data: b64.encode(message),
            })
            .send()
            .await
            .map_err(KmsError::Http)?;
        let out: AsymmetricSignResponse = parse(resp).await?;
        b64.decode(&out.signature)
            .map_err(|e| KmsError::Protocol(format!("bad base64 in signature: {e}")))
    }
}

impl std::fmt::Debug for GcpKmsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpKmsClient").finish_non_exhaustive()
    }
}

async fn parse<T: for<'de> Deserialize<'de>>(resp: reqwest::Response) -> Result<T, KmsError> {
    let status = resp.status();
    if status.is_success() {
        return resp.json().await.map_err(KmsError::Http);
    }
    let body = resp.text().await.unwrap_or_default();
    Err(match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => KmsError::AuthDenied(body),
        StatusCode::NOT_FOUND => KmsError::NotFound,
        _ => KmsError::Api { status, body },
    })
}

#[derive(Debug, thiserror::Error)]
pub enum KmsError {
    #[error("GCP auth error: {0}")]
    Auth(String),
    #[error("GCP KMS HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("GCP KMS access denied: {0}")]
    AuthDenied(String),
    #[error("GCP KMS resource not found")]
    NotFound,
    #[error("GCP KMS API error {status}: {body}")]
    Api { status: StatusCode, body: String },
    #[error("GCP KMS protocol error: {0}")]
    Protocol(String),
}

#[derive(Deserialize)]
struct EncryptResponse {
    ciphertext: String,
}
#[derive(Deserialize)]
struct DecryptResponse {
    plaintext: String,
}
#[derive(Deserialize)]
struct AsymmetricSignResponse {
    signature: String,
}
