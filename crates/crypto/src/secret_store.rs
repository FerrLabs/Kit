use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{KeyProvider, decrypt_value, encrypt_value, generate_dek};

const PREFIX: &str = "enc:v1:";
const LEN_BYTES: usize = 2;

#[derive(Debug, Error)]
pub enum SecretStoreError {
    #[error("value is not a sealed secret")]
    NotSealed,
    #[error("sealed secret is not valid base64url")]
    InvalidEncoding,
    #[error("sealed secret is truncated")]
    Truncated,
    #[error("wrapped data key is too large")]
    WrappedKeyTooLarge,
    #[error("decrypted secret is not valid UTF-8")]
    InvalidUtf8,
    #[error("{context}: {source}")]
    Crypto {
        context: &'static str,
        #[source]
        source: anyhow::Error,
    },
}

impl SecretStoreError {
    fn crypto(context: &'static str) -> impl FnOnce(anyhow::Error) -> Self {
        move |source| Self::Crypto { context, source }
    }
}

pub struct SecretStore {
    provider: Arc<dyn KeyProvider>,
}

impl SecretStore {
    #[must_use]
    pub fn new(provider: Arc<dyn KeyProvider>) -> Self {
        Self { provider }
    }

    pub async fn seal(&self, plaintext: &str) -> Result<String, SecretStoreError> {
        let dek = generate_dek();
        let ciphertext = encrypt_value(plaintext.as_bytes(), &dek)
            .map_err(SecretStoreError::crypto("encrypting a secret"))?;
        let wrapped = self
            .provider
            .wrap_dek(&dek)
            .await
            .map_err(SecretStoreError::crypto("wrapping the data key"))?;

        let len = u16::try_from(wrapped.len()).map_err(|_| SecretStoreError::WrappedKeyTooLarge)?;
        let mut blob = Vec::with_capacity(LEN_BYTES + wrapped.len() + ciphertext.len());
        blob.extend_from_slice(&len.to_be_bytes());
        blob.extend_from_slice(&wrapped);
        blob.extend_from_slice(&ciphertext);

        Ok(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(&blob)))
    }

    pub async fn open(&self, stored: &str) -> Result<Zeroizing<String>, SecretStoreError> {
        let encoded = stored
            .strip_prefix(PREFIX)
            .ok_or(SecretStoreError::NotSealed)?;
        let blob = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| SecretStoreError::InvalidEncoding)?;

        let (len_bytes, rest) = blob
            .split_first_chunk::<LEN_BYTES>()
            .ok_or(SecretStoreError::Truncated)?;
        let len = usize::from(u16::from_be_bytes(*len_bytes));
        if rest.len() < len {
            return Err(SecretStoreError::Truncated);
        }
        let (wrapped, ciphertext) = rest.split_at(len);

        let dek = self
            .provider
            .unwrap_dek(wrapped)
            .await
            .map_err(SecretStoreError::crypto("unwrapping the data key"))?;
        let plaintext = Zeroizing::new(
            decrypt_value(ciphertext, &dek)
                .map_err(SecretStoreError::crypto("decrypting a secret"))?,
        );

        String::from_utf8(plaintext.to_vec())
            .map(Zeroizing::new)
            .map_err(|_| SecretStoreError::InvalidUtf8)
    }
}

#[must_use]
pub fn is_sealed(stored: &str) -> bool {
    stored.starts_with(PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LocalKek;

    fn store_with(key_byte: u8) -> SecretStore {
        SecretStore::new(Arc::new(LocalKek::new(Zeroizing::new(vec![key_byte; 32]))))
    }

    fn tamper(sealed: &str, index_from_end: usize) -> String {
        let encoded = sealed.strip_prefix(PREFIX).unwrap();
        let mut blob = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        let at = blob.len() - index_from_end;
        blob[at] ^= 0x01;
        format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(&blob))
    }

    #[tokio::test]
    async fn round_trips_and_hides_the_plaintext() {
        let store = store_with(7);
        let sealed = store.seal("ghu_supersecret").await.unwrap();

        assert!(is_sealed(&sealed));
        assert!(!sealed.contains("ghu_supersecret"));
        assert_eq!(&*store.open(&sealed).await.unwrap(), "ghu_supersecret");
    }

    #[tokio::test]
    async fn sealing_twice_gives_different_blobs() {
        let store = store_with(7);
        let a = store.seal("same").await.unwrap();
        let b = store.seal("same").await.unwrap();

        assert_ne!(a, b);
        assert_eq!(&*store.open(&a).await.unwrap(), "same");
        assert_eq!(&*store.open(&b).await.unwrap(), "same");
    }

    #[tokio::test]
    async fn wrong_kek_fails() {
        let sealed = store_with(7).seal("secret").await.unwrap();
        assert!(matches!(
            store_with(9).open(&sealed).await,
            Err(SecretStoreError::Crypto { .. })
        ));
    }

    #[tokio::test]
    async fn unprefixed_value_is_rejected() {
        assert!(matches!(
            store_with(7).open("ghu_plaintext").await,
            Err(SecretStoreError::NotSealed)
        ));
        assert!(!is_sealed("ghu_plaintext"));
    }

    #[tokio::test]
    async fn tampered_ciphertext_fails() {
        let store = store_with(7);
        let sealed = store.seal("secret").await.unwrap();

        assert!(matches!(
            store.open(&tamper(&sealed, 1)).await,
            Err(SecretStoreError::Crypto { .. })
        ));
    }

    #[tokio::test]
    async fn tampered_wrapped_key_fails() {
        let store = store_with(7);
        let sealed = store.seal("secret").await.unwrap();
        let encoded = sealed.strip_prefix(PREFIX).unwrap();
        let mut blob = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        blob[LEN_BYTES] ^= 0x01;
        let tampered = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(&blob));

        assert!(store.open(&tampered).await.is_err());
    }

    #[tokio::test]
    async fn malformed_blobs_error_without_panicking() {
        let store = store_with(7);
        assert!(matches!(
            store.open("enc:v1:!!!").await,
            Err(SecretStoreError::InvalidEncoding)
        ));
        for truncated in ["enc:v1:", "enc:v1:AA", "enc:v1:AP8A"] {
            assert!(
                matches!(
                    store.open(truncated).await,
                    Err(SecretStoreError::Truncated)
                ),
                "{truncated}"
            );
        }
    }
}
