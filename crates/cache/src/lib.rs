//! Shared Valkey (Redis-compatible) connection pool for FerrLabs APIs.
//!
//! Mirrors `ferrlabs-db`: config-from-env plus a `connect` factory that returns
//! an initialised `fred` pool. Consumers run commands against `fred` directly —
//! it is re-exported here so they don't take a separate `fred` dependency.

use fred::prelude::*;

pub use fred;

mod swr;
pub use swr::Swr;

#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub url: String,
    pub pool_size: usize,
    /// Path to a PEM-encoded CA certificate used to verify the server's TLS
    /// certificate when `url` uses the `rediss://` scheme. Ignored for
    /// plaintext `redis://` connections.
    pub ca_cert_path: Option<String>,
}

impl CacheConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let url = std::env::var("VALKEY_URL")
            .or_else(|_| std::env::var("REDIS_URL"))
            .map_err(|_| anyhow::anyhow!("VALKEY_URL (or REDIS_URL) not set"))?;
        let pool_size = std::env::var("VALKEY_POOL_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(6);
        let ca_cert_path = std::env::var("VALKEY_CA_CERT").ok();
        Ok(Self {
            url,
            pool_size,
            ca_cert_path,
        })
    }
}

pub type CachePool = RedisPool;

/// Build a `rustls::ClientConfig` that trusts only the CA certificate(s)
/// found at `ca_cert_path`, with full server certificate + hostname
/// verification (no "accept invalid certs" escape hatch).
fn rustls_config_with_ca(ca_cert_path: &str) -> anyhow::Result<fred::rustls::ClientConfig> {
    let pem_bytes = std::fs::read(ca_cert_path)
        .map_err(|e| anyhow::anyhow!("failed to read VALKEY_CA_CERT ({ca_cert_path}): {e}"))?;
    let mut reader = std::io::BufReader::new(pem_bytes.as_slice());
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("failed to parse VALKEY_CA_CERT PEM: {e}"))?;
    if certs.is_empty() {
        anyhow::bail!("VALKEY_CA_CERT ({ca_cert_path}) contains no certificates");
    }

    let mut roots = fred::rustls::RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert)
            .map_err(|e| anyhow::anyhow!("invalid CA certificate in VALKEY_CA_CERT: {e}"))?;
    }

    Ok(fred::rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

pub async fn connect(config: &CacheConfig) -> anyhow::Result<CachePool> {
    let mut cfg = RedisConfig::from_url(&config.url)
        .map_err(|e| anyhow::anyhow!("invalid VALKEY_URL: {e}"))?;

    let tls_enabled = config.url.starts_with("rediss://");
    if tls_enabled {
        if let Some(ca_cert_path) = &config.ca_cert_path {
            let client_config = rustls_config_with_ca(ca_cert_path)?;
            cfg.tls = Some(client_config.into());
        }
        // else: keep whatever `RedisConfig::from_url` derived (system roots
        // via `TlsConnector::default_rustls()`), still with full verification.
    }

    let pool = RedisPool::new(cfg, None, None, None, config.pool_size)
        .map_err(|e| anyhow::anyhow!("failed to build Valkey pool: {e}"))?;
    let _handle = pool.connect();
    pool.wait_for_connect()
        .await
        .map_err(|e| anyhow::anyhow!("Valkey connect failed: {e}"))?;
    tracing::info!(
        pool_size = config.pool_size,
        tls = tls_enabled,
        "connected to Valkey"
    );
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fred::interfaces::KeysInterface;

    /// Gate: run only when a local TLS Valkey is available.
    ///
    /// `TEST_VALKEY_TLS_URL` — e.g. `<rediss://127.0.0.1:6380>`
    /// `TEST_VALKEY_TLS_CA` — path to the CA PEM that signed the server cert
    fn tls_env() -> Option<(String, String)> {
        let url = std::env::var("TEST_VALKEY_TLS_URL").ok()?;
        let ca = std::env::var("TEST_VALKEY_TLS_CA").ok()?;
        Some((url, ca))
    }

    #[tokio::test]
    async fn connects_over_tls_with_valid_ca() {
        let Some((url, ca_cert_path)) = tls_env() else {
            eprintln!("skipping: TEST_VALKEY_TLS_URL / TEST_VALKEY_TLS_CA not set");
            return;
        };

        let pool = connect(&CacheConfig {
            url,
            pool_size: 2,
            ca_cert_path: Some(ca_cert_path),
        })
        .await
        .expect("expected TLS connect with valid CA to succeed");

        pool.set::<(), _, _>("ferrlabs-cache:tls-test", "ok", None, None, false)
            .await
            .expect("SET over TLS should succeed");
        let value: String = pool
            .get("ferrlabs-cache:tls-test")
            .await
            .expect("GET over TLS should succeed");
        assert_eq!(value, "ok");
    }

    #[tokio::test]
    async fn rejects_tls_connection_without_trusted_ca() {
        let Some((url, _)) = tls_env() else {
            eprintln!("skipping: TEST_VALKEY_TLS_URL / TEST_VALKEY_TLS_CA not set");
            return;
        };

        // No `ca_cert_path` => falls back to system roots, which do not
        // trust our self-signed test CA. The handshake must fail: this
        // proves verification is real, not an accept-all connector.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            connect(&CacheConfig {
                url,
                pool_size: 1,
                ca_cert_path: None,
            }),
        )
        .await;

        // Either an explicit connect error, or a timeout waiting for a
        // handshake that never completes: both prove it never succeeded.
        if let Ok(connect_result) = result {
            assert!(
                connect_result.is_err(),
                "connecting over TLS without a trusted CA must fail"
            );
        }
    }
}
