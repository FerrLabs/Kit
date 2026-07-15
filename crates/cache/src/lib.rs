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

/// Percent-encode the `user`/`password` portion of a `redis://`/`rediss://`
/// URL's userinfo so that URL-breaking characters (`/`, `+`, `=`, `@`, `:`,
/// `%`, ...) in a raw password — e.g. a base64-generated Valkey password —
/// don't get misparsed as part of the host, path, or query.
///
/// The host is assumed to never contain `@`, so splitting on the *last* `@`
/// in `scheme://...` unambiguously separates userinfo from the rest, even
/// when the password itself contains `@`. Within the userinfo, the *first*
/// `:` separates `user` from `password` (Valkey's typical `:password` form
/// has an empty `user`), so a password containing `:` is preserved intact.
///
/// URLs with no userinfo (no `@` after the scheme) are returned unchanged.
fn percent_encode_userinfo(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let (scheme, rest) = url.split_at(scheme_end + 3);

    let Some(at_pos) = rest.rfind('@') else {
        return url.to_string();
    };
    let (userinfo, host_part) = rest.split_at(at_pos);
    let host_part = &host_part[1..]; // drop the leading '@'

    // Encode everything that is not an unreserved character (RFC 3986),
    // which in particular covers '%' itself (so an already-`%`-containing
    // raw password isn't double-decoded), '/', '+', '=', '@', ':', '#',
    // '?', and '&'.
    let encode_set: &percent_encoding::AsciiSet = percent_encoding::NON_ALPHANUMERIC;

    if let Some((user, pass)) = userinfo.split_once(':') {
        let enc_user = percent_encoding::utf8_percent_encode(user, encode_set);
        let enc_pass = percent_encoding::utf8_percent_encode(pass, encode_set);
        format!("{scheme}{enc_user}:{enc_pass}@{host_part}")
    } else {
        let enc_user = percent_encoding::utf8_percent_encode(userinfo, encode_set);
        format!("{scheme}{enc_user}@{host_part}")
    }
}

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
    let sanitized_url = percent_encode_userinfo(&config.url);
    let mut cfg = RedisConfig::from_url(&sanitized_url)
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

    #[tokio::test]
    async fn rejects_wrong_explicit_ca() {
        // Exercises the primary security path directly: an explicit
        // `ca_cert_path` pointing at a CA (CA_B) that did NOT sign the
        // server's certificate (signed by CA_A). The custom `RootCertStore`
        // built in `rustls_config_with_ca` must reject the server cert —
        // proving it verifies against the provided CA rather than accepting
        // anything.
        let Some((url, _)) = tls_env() else {
            eprintln!("skipping: TEST_VALKEY_TLS_URL / TEST_VALKEY_TLS_CA not set");
            return;
        };
        let Ok(wrong_ca) = std::env::var("TEST_VALKEY_TLS_WRONG_CA") else {
            eprintln!("skipping: TEST_VALKEY_TLS_WRONG_CA not set");
            return;
        };

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            connect(&CacheConfig {
                url,
                pool_size: 1,
                ca_cert_path: Some(wrong_ca),
            }),
        )
        .await;

        // Explicit connect error, or a timeout on a handshake that never
        // completes: both prove the wrong CA was not accepted.
        if let Ok(connect_result) = result {
            assert!(
                connect_result.is_err(),
                "connecting over TLS with a non-signing CA must fail"
            );
        }
    }

    // -- percent_encode_userinfo: pure unit tests, no network required --

    #[test]
    fn percent_encode_userinfo_splits_on_last_at_for_password_containing_at() {
        // Password itself contains '@'; the host must not absorb it. Only
        // the *last* '@' in the string is the userinfo/host separator.
        let raw = "redis://:ab@cd@127.0.0.1:6379";
        let sanitized = percent_encode_userinfo(raw);
        assert_eq!(sanitized, "redis://:ab%40cd@127.0.0.1:6379");
    }

    #[test]
    fn percent_encode_userinfo_splits_on_first_colon_for_password_containing_colon() {
        // Password contains ':'; user/password must split on the *first*
        // ':' in the userinfo so the rest of the password survives intact.
        let raw = "redis://:ab:cd@127.0.0.1:6379";
        let sanitized = percent_encode_userinfo(raw);
        assert_eq!(sanitized, "redis://:ab%3Acd@127.0.0.1:6379");
    }

    #[test]
    fn percent_encode_userinfo_encodes_percent_sign_itself() {
        // A raw password already containing a literal '%' must have that
        // '%' escaped too, otherwise `from_url` would misinterpret it as
        // the start of a (possibly invalid) percent-escape and mangle the
        // decoded password.
        let raw = "redis://:ab%cd@127.0.0.1:6379";
        let sanitized = percent_encode_userinfo(raw);
        assert_eq!(sanitized, "redis://:ab%25cd@127.0.0.1:6379");
    }

    #[test]
    fn percent_encode_userinfo_covers_slash_plus_equals() {
        let raw = "redis://:ab/cd+ef=gh@127.0.0.1:6379";
        let sanitized = percent_encode_userinfo(raw);
        assert_eq!(sanitized, "redis://:ab%2Fcd%2Bef%3Dgh@127.0.0.1:6379");
    }

    #[test]
    fn percent_encode_userinfo_leaves_url_without_userinfo_unchanged() {
        let raw = "redis://127.0.0.1:6379";
        assert_eq!(percent_encode_userinfo(raw), raw);
    }

    #[test]
    fn percent_encode_userinfo_preserves_rediss_scheme() {
        let raw = "rediss://:ab/cd@127.0.0.1:6380";
        let sanitized = percent_encode_userinfo(raw);
        assert_eq!(sanitized, "rediss://:ab%2Fcd@127.0.0.1:6380");
    }

    // -- end-to-end: a real Valkey instance with a URL-breaking password --

    /// Gate: run only when a local Valkey with a URL-breaking password is
    /// available.
    ///
    /// `TEST_VALKEY_URL_SAFE_PASSWORD_URL` — the RAW, non-percent-encoded
    /// `redis://:<password>@host:port` URL, exactly as a Vault template
    /// would render it (e.g. password `ab/cd+ef=gh` generated by
    /// `openssl rand -base64 32`).
    fn url_safe_password_env() -> Option<String> {
        std::env::var("TEST_VALKEY_URL_SAFE_PASSWORD_URL").ok()
    }

    #[tokio::test]
    async fn connects_with_raw_password_containing_url_breaking_characters() {
        let Some(url) = url_safe_password_env() else {
            eprintln!("skipping: TEST_VALKEY_URL_SAFE_PASSWORD_URL not set");
            return;
        };

        // Before the fix this failed with `invalid VALKEY_URL: Url Error:
        // EmptyHost`, because the raw '/' in the password terminated the
        // authority early. The fix pre-encodes the userinfo before handing
        // the URL to `RedisConfig::from_url`, and `fred`/`url` decode it
        // back to the raw password for the actual AUTH handshake.
        let pool = connect(&CacheConfig {
            url,
            pool_size: 2,
            ca_cert_path: None,
        })
        .await
        .expect("connect with a raw URL-breaking password should succeed");

        pool.set::<(), _, _>("ferrlabs-cache:url-safe-pw-test", "ok", None, None, false)
            .await
            .expect("SET should succeed once AUTH has decoded the real password");
        let value: String = pool
            .get("ferrlabs-cache:url-safe-pw-test")
            .await
            .expect("GET should succeed");
        assert_eq!(value, "ok");
    }
}
