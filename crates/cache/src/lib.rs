//! Shared Valkey (Redis-compatible) connection pool for FerrLabs APIs.
//!
//! Mirrors `ferrlabs-db`: config-from-env plus a `connect` factory that returns
//! an initialised `fred` pool. Consumers run commands against `fred` directly —
//! it is re-exported here so they don't take a separate `fred` dependency.

use fred::prelude::*;

pub use fred;

mod swr;
pub use swr::Swr;

/// `Debug` is implemented by hand (see below) rather than derived, because
/// both `url` and `password` can carry the AUTH secret — a derived `Debug`
/// would print it in the clear via any `{:?}` or `tracing::debug!(?config)`,
/// defeating the entire point of keeping the password out of the logs.
/// Do **not** replace it with `#[derive(Debug)]`.
#[derive(Clone)]
pub struct CacheConfig {
    pub url: String,
    pub pool_size: usize,
    /// Path to a PEM-encoded CA certificate used to verify the server's TLS
    /// certificate when `url` uses the `rediss://` scheme. Ignored for
    /// plaintext `redis://` connections.
    pub ca_cert_path: Option<String>,
    /// The Valkey/Redis AUTH password, kept out of `url` entirely.
    ///
    /// This is the **recommended** way to supply a password: `url` becomes
    /// credential-free (e.g. `rediss://host:6379`) and never ends up in
    /// logs, error messages, or metrics that capture the connection string.
    /// When set, it takes priority over any credentials embedded in `url`.
    ///
    /// The URL-with-credentials form (`redis://:<password>@host:port`,
    /// percent-encoded by [`connect`]) remains supported for backward
    /// compatibility, but it cannot represent a password containing a raw
    /// `?` or `#`: those characters make the URL's authority/query/fragment
    /// boundary structurally ambiguous no matter how the userinfo is
    /// encoded. A password with `?`/`#` in it must use `password` /
    /// `VALKEY_PASSWORD`.
    pub password: Option<String>,
}

/// Render a connection URL in a form that is safe to log: the scheme and the
/// host (`redis://127.0.0.1:6379`), with any userinfo — which routinely
/// carries the AUTH password in the `redis://:<password>@host` form — and any
/// path/query/fragment dropped entirely.
///
/// When the userinfo boundary cannot be located unambiguously (a password
/// containing a raw `?`/`#` puts a delimiter *before* the real `@`; see
/// [`percent_encode_userinfo`]), this bails out to a fully redacted value
/// rather than risk printing a prefix of the password.
fn redact_url(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return "<redacted>".to_string();
    };
    let (scheme, rest) = url.split_at(scheme_end + 3);

    // Same bounded search as `percent_encode_userinfo`: an '@' after a '?'/'#'
    // belongs to the query/fragment, not to the userinfo.
    let search_end = rest.find(['?', '#']).unwrap_or(rest.len());
    let after_userinfo = match rest[..search_end].rfind('@') {
        Some(at_pos) => &rest[at_pos + 1..],
        None if rest.contains('@') => {
            // There *is* an '@' but only beyond a '?'/'#': the userinfo itself
            // contains a raw delimiter, so the authority can't be split
            // safely. Redact wholesale — never print a partial password.
            return format!("{scheme}<redacted>");
        }
        None => rest,
    };

    let host_end = after_userinfo
        .find(['/', '?', '#'])
        .unwrap_or(after_userinfo.len());
    format!("{scheme}{}", &after_userinfo[..host_end])
}

/// Hand-written so the AUTH secret never reaches a log line. `password` is
/// reduced to a presence flag (never its value, never its length), and `url`
/// is passed through [`redact_url`] because it can embed credentials.
impl std::fmt::Debug for CacheConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheConfig")
            .field("url", &redact_url(&self.url))
            .field("pool_size", &self.pool_size)
            .field("ca_cert_path", &self.ca_cert_path)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl CacheConfig {
    /// Reads `VALKEY_URL`/`REDIS_URL`, `VALKEY_POOL_SIZE`, `VALKEY_CA_CERT`
    /// and `VALKEY_PASSWORD` from the environment.
    ///
    /// `VALKEY_PASSWORD` is the recommended way to supply a password: set it
    /// and use a credential-free `VALKEY_URL` (e.g. `rediss://host:6379`).
    /// The legacy URL-with-credentials form is still read and supported (see
    /// [`CacheConfig::password`] for why it can't handle every password).
    pub fn from_env() -> anyhow::Result<Self> {
        let url = std::env::var("VALKEY_URL")
            .or_else(|_| std::env::var("REDIS_URL"))
            .map_err(|_| anyhow::anyhow!("VALKEY_URL (or REDIS_URL) not set"))?;
        let pool_size = std::env::var("VALKEY_POOL_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(6);
        let ca_cert_path = std::env::var("VALKEY_CA_CERT").ok();
        let password = std::env::var("VALKEY_PASSWORD")
            .ok()
            .filter(|v| !v.is_empty());
        Ok(Self {
            url,
            pool_size,
            ca_cert_path,
            password,
        })
    }
}

pub type CachePool = RedisPool;

/// Percent-encode the `user`/`password` portion of a `redis://`/`rediss://`
/// URL's userinfo so that URL-breaking characters (`/`, `+`, `=`, `@`, `:`,
/// `%`, ...) in a raw password — e.g. a base64-generated Valkey password —
/// don't get misparsed as part of the host, path, or query.
///
/// Finding the userinfo/host boundary in a URL whose password is *not* yet
/// encoded is a chicken-and-egg problem: the password may itself contain the
/// very delimiters used to find the boundary. Two rules resolve it:
///
/// - The search for the `@` is bounded to the left of the first `?` or `#`.
///   A query/fragment may legitimately contain `@` (e.g. fred accepts
///   `redis://host:6379/0?node=host:port`), and an unbounded `rfind('@')`
///   would mistake that `@` for the separator and silently drop the real
///   host. The bound is `?`/`#` and deliberately **not** `/`: the password
///   routinely contains `/` (that is this function's whole reason to exist),
///   so bounding at the first `/` would find a `/` *inside* the password,
///   truncate the authority before the real `@`, and skip encoding entirely.
///   This relies on the password containing no raw `?`/`#` — true for the
///   base64 (`A-Za-z0-9+/=`) and hex alphabets used to generate them.
/// - Within that bound, the separator is the *last* `@`: the host never
///   contains `@`, so a password that does is still split correctly.
///
/// The host then ends at the first `/`, `?` or `#` **at or after** that `@`;
/// everything from there on (path/query/fragment) is passed through verbatim
/// — never re-encoded or altered.
///
/// Within the userinfo, the *first* `:` separates `user` from `password`
/// (Valkey's typical `:password` form has an empty `user`), so a password
/// containing `:` is preserved intact.
///
/// URLs with no userinfo (no `@` before any `?`/`#`) are returned unchanged.
fn percent_encode_userinfo(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let (scheme, rest) = url.split_at(scheme_end + 3);

    // Bound the userinfo search to the left of any query/fragment.
    let search_end = rest.find(['?', '#']).unwrap_or(rest.len());
    let Some(at_pos) = rest[..search_end].rfind('@') else {
        return url.to_string();
    };

    let (userinfo, after_at) = rest.split_at(at_pos);
    let after_at = &after_at[1..]; // drop the leading '@'

    // The host runs from the '@' to the first '/', '?' or '#'.
    let host_end = after_at.find(['/', '?', '#']).unwrap_or(after_at.len());
    let (host_part, tail) = after_at.split_at(host_end);

    // Encode everything that is not an unreserved character (RFC 3986),
    // which in particular covers '%' itself (so an already-`%`-containing
    // raw password isn't double-decoded), '/', '+', '=', '@', ':', '#',
    // '?', and '&'.
    let encode_set: &percent_encoding::AsciiSet = percent_encoding::NON_ALPHANUMERIC;

    if let Some((user, pass)) = userinfo.split_once(':') {
        let enc_user = percent_encoding::utf8_percent_encode(user, encode_set);
        let enc_pass = percent_encoding::utf8_percent_encode(pass, encode_set);
        format!("{scheme}{enc_user}:{enc_pass}@{host_part}{tail}")
    } else {
        let enc_user = percent_encoding::utf8_percent_encode(userinfo, encode_set);
        format!("{scheme}{enc_user}@{host_part}{tail}")
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

    // `config.password` (typically from `VALKEY_PASSWORD`) is the robust
    // path and takes priority over any credentials embedded in the URL —
    // it's the only way to supply a password containing a raw `?`/`#`.
    if let Some(password) = &config.password {
        cfg.password = Some(password.clone());
    }

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
            password: None,
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
                password: None,
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
                password: None,
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
    fn percent_encode_userinfo_preserves_db_index_path() {
        // fred accepts the DB index as a path (`/0`). The password must be
        // encoded while the path is passed through verbatim.
        let raw = "redis://:ab/cd@127.0.0.1:6379/0";
        let sanitized = percent_encode_userinfo(raw);
        assert_eq!(sanitized, "redis://:ab%2Fcd@127.0.0.1:6379/0");
    }

    #[test]
    fn percent_encode_userinfo_ignores_at_sign_outside_the_authority() {
        // A path/query may legitimately contain '@'. Searching the whole
        // URL for the last '@' would treat `?note=a@b`'s '@' as the
        // userinfo separator and silently drop the real host (producing
        // host_part = "b"). The search must be bounded to the authority.
        let raw = "redis://:pw@127.0.0.1:6379/0?note=a@b";
        let sanitized = percent_encode_userinfo(raw);
        assert_eq!(sanitized, "redis://:pw@127.0.0.1:6379/0?note=a@b");

        // And the host actually survives a real parse.
        let parsed = RedisConfig::from_url(&sanitized).expect("should parse");
        let host = &parsed.server.hosts()[0];
        assert_eq!(&*host.host, "127.0.0.1");
        assert_eq!(host.port, 6379);
    }

    #[test]
    fn percent_encode_userinfo_handles_slash_password_together_with_path_and_query() {
        // The hard case, combining both hazards: the password contains '/'
        // (so the authority cannot be bounded at the first '/') AND the
        // query contains '@' (so the '@' search cannot be unbounded).
        let raw = "redis://:ab/cd+ef=gh@127.0.0.1:6379/0?note=a@b";
        let sanitized = percent_encode_userinfo(raw);
        assert_eq!(
            sanitized,
            "redis://:ab%2Fcd%2Bef%3Dgh@127.0.0.1:6379/0?note=a@b"
        );

        let parsed = RedisConfig::from_url(&sanitized).expect("should parse");
        let host = &parsed.server.hosts()[0];
        assert_eq!(&*host.host, "127.0.0.1");
        assert_eq!(host.port, 6379);
    }

    #[test]
    fn percent_encode_userinfo_leaves_url_without_userinfo_but_with_path_query_unchanged() {
        // No credentials at all: the '@' in the query must not be mistaken
        // for a userinfo separator — URL returned verbatim.
        let raw = "redis://127.0.0.1:6379/0?x=1@2";
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
            password: None,
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

    // -- VALKEY_PASSWORD: password supplied out-of-band, not in the URL --

    /// Gate: run only when a local Valkey with a "normal" (URL-safe-once-
    /// percent-encoded) password is available, reachable via a
    /// credential-free URL.
    ///
    /// `TEST_VALKEY_PASSWORD_URL` — e.g. `redis://127.0.0.1:<port>` (NO
    /// credentials in the URL).
    /// `TEST_VALKEY_PASSWORD` — the AUTH password `requirepass` is set to on
    /// that server.
    fn password_env() -> Option<(String, String)> {
        let url = std::env::var("TEST_VALKEY_PASSWORD_URL").ok()?;
        let password = std::env::var("TEST_VALKEY_PASSWORD").ok()?;
        Some((url, password))
    }

    #[tokio::test]
    async fn connects_with_password_supplied_out_of_band() {
        let Some((url, password)) = password_env() else {
            eprintln!("skipping: TEST_VALKEY_PASSWORD_URL / TEST_VALKEY_PASSWORD not set");
            return;
        };

        // The URL itself carries no credentials at all.
        let pool = connect(&CacheConfig {
            url,
            pool_size: 2,
            ca_cert_path: None,
            password: Some(password),
        })
        .await
        .expect("connect with password supplied via CacheConfig::password should succeed");

        pool.set::<(), _, _>(
            "ferrlabs-cache:password-field-test",
            "ok",
            None,
            None,
            false,
        )
        .await
        .expect("SET should succeed once AUTH has used the out-of-band password");
        let value: String = pool
            .get("ferrlabs-cache:password-field-test")
            .await
            .expect("GET should succeed");
        assert_eq!(value, "ok");
    }

    /// Gate: run only when a local Valkey whose password contains a raw `?`
    /// and `#` is available — the case the URL-with-credentials form cannot
    /// represent no matter how the userinfo is percent-encoded, because `?`
    /// and `#` are the URL's own query/fragment delimiters and the ambiguity
    /// is structural, not an encoding bug.
    ///
    /// `TEST_VALKEY_UNENCODABLE_PASSWORD_URL` — e.g. `redis://127.0.0.1:<port>`
    /// (NO credentials in the URL).
    /// `TEST_VALKEY_UNENCODABLE_PASSWORD` — the raw password, containing `?`
    /// and `#` (e.g. `pa?ss#word/x+y=z`).
    fn unencodable_password_env() -> Option<(String, String)> {
        let url = std::env::var("TEST_VALKEY_UNENCODABLE_PASSWORD_URL").ok()?;
        let password = std::env::var("TEST_VALKEY_UNENCODABLE_PASSWORD").ok()?;
        Some((url, password))
    }

    #[tokio::test]
    async fn url_with_credentials_cannot_represent_a_password_containing_question_mark_or_hash() {
        // The negative half of the proof: the existing (and still supported)
        // URL-with-credentials path cannot carry a raw '?'/'#' password, and
        // percent-encoding the userinfo cannot rescue it.
        //
        // The failure happens at parse time, before any network I/O — there
        // is no AUTH round-trip and no WRONGPASS here:
        //   1. `percent_encode_userinfo` bounds its '@' search to the left of
        //      the first '?'/'#'. In `redis://:pa?ss#word/x+y=z@host:port`
        //      that '?' sits *inside* the still-unencoded password, so no '@'
        //      is found within the bound and the URL is returned UNCHANGED
        //      (no encoding applied at all).
        //   2. `RedisConfig::from_url` then parses that raw URL, reads the
        //      authority as ending at the '?', finds no host, and rejects it
        //      with `Url Error: EmptyHost` — surfaced as `invalid VALKEY_URL`.
        //
        // Loosening the bound doesn't help either: the ambiguity is
        // structural. A raw '?' in a password is indistinguishable from the
        // URL's own query delimiter. Hence VALKEY_PASSWORD — this case is not
        // redundant with the percent-encoding fix.
        let Some((url, password)) = unencodable_password_env() else {
            eprintln!(
                "skipping: TEST_VALKEY_UNENCODABLE_PASSWORD_URL / TEST_VALKEY_UNENCODABLE_PASSWORD not set"
            );
            return;
        };

        // Build the raw URL-with-credentials form a naive caller might try,
        // exactly like Vault template rendering would (no pre-encoding).
        let scheme_end = url.find("://").expect("test URL must have a scheme");
        let (scheme, authority) = url.split_at(scheme_end + 3);
        let raw_url_with_creds = format!("{scheme}:{password}@{authority}");

        let result = connect(&CacheConfig {
            url: raw_url_with_creds,
            pool_size: 1,
            ca_cert_path: None,
            password: None,
        })
        .await;
        assert!(
            result.is_err(),
            "a raw '?'/'#'-containing password embedded in the URL must not \
             produce a working connection — this is exactly why VALKEY_PASSWORD exists"
        );
    }

    #[tokio::test]
    async fn valkey_password_handles_a_password_containing_question_mark_or_hash() {
        // The positive half: the same raw password, supplied out-of-band via
        // `CacheConfig::password` against a credential-free URL, connects
        // successfully. This is the feature's whole reason to exist.
        let Some((url, password)) = unencodable_password_env() else {
            eprintln!(
                "skipping: TEST_VALKEY_UNENCODABLE_PASSWORD_URL / TEST_VALKEY_UNENCODABLE_PASSWORD not set"
            );
            return;
        };

        let pool = connect(&CacheConfig {
            url,
            pool_size: 2,
            ca_cert_path: None,
            password: Some(password),
        })
        .await
        .expect("a password containing '?'/'#' supplied via VALKEY_PASSWORD should connect fine");

        pool.set::<(), _, _>(
            "ferrlabs-cache:unencodable-password-test",
            "ok",
            None,
            None,
            false,
        )
        .await
        .expect("SET should succeed");
        let value: String = pool
            .get("ferrlabs-cache:unencodable-password-test")
            .await
            .expect("GET should succeed");
        assert_eq!(value, "ok");
    }

    #[tokio::test]
    async fn config_password_takes_priority_over_url_credentials() {
        // If both are present, `password` wins: an intentionally wrong
        // password in the URL must not prevent a successful connection when
        // the correct password is supplied via `CacheConfig::password`.
        let Some((url, password)) = password_env() else {
            eprintln!("skipping: TEST_VALKEY_PASSWORD_URL / TEST_VALKEY_PASSWORD not set");
            return;
        };

        let scheme_end = url.find("://").expect("test URL must have a scheme");
        let (scheme, authority) = url.split_at(scheme_end + 3);
        let url_with_wrong_creds = format!("{scheme}:not-the-real-password@{authority}");

        let pool = connect(&CacheConfig {
            url: url_with_wrong_creds,
            pool_size: 2,
            ca_cert_path: None,
            password: Some(password),
        })
        .await
        .expect("CacheConfig::password must take priority over URL credentials");

        pool.set::<(), _, _>(
            "ferrlabs-cache:password-priority-test",
            "ok",
            None,
            None,
            false,
        )
        .await
        .expect("SET should succeed using the out-of-band password");
        let value: String = pool
            .get("ferrlabs-cache:password-priority-test")
            .await
            .expect("GET should succeed");
        assert_eq!(value, "ok");
    }

    // -- Debug redaction: the secret must never reach a log line --

    #[test]
    fn debug_redacts_password_and_url_credentials() {
        // A derived `Debug` would print both the `password` field and the
        // credentials embedded in `url` in the clear, which would defeat the
        // whole point of keeping the password out of the logs.
        let config = CacheConfig {
            url: "redis://:supersecret@host:6379".to_string(),
            pool_size: 6,
            ca_cert_path: None,
            password: Some("supersecret".to_string()),
        };

        let rendered = format!("{config:?}");

        assert!(
            !rendered.contains("supersecret"),
            "Debug must not leak the password (from the field or the URL), got: {rendered}"
        );
        assert!(
            rendered.contains("<redacted>"),
            "Debug should mark the password as redacted, got: {rendered}"
        );
        // The non-secret parts stay useful for debugging.
        assert!(
            rendered.contains("host:6379"),
            "Debug should keep the host for debuggability, got: {rendered}"
        );
        assert!(rendered.contains("pool_size: 6"), "got: {rendered}");
    }

    #[test]
    fn debug_renders_absent_password_as_none() {
        let config = CacheConfig {
            url: "redis://127.0.0.1:6379".to_string(),
            pool_size: 2,
            ca_cert_path: Some("/etc/ssl/ca.pem".to_string()),
            password: None,
        };

        let rendered = format!("{config:?}");

        assert!(
            rendered.contains("password: None"),
            "an absent password should render as None, got: {rendered}"
        );
        // A credential-free URL and the CA path are not secrets: keep them.
        assert!(
            rendered.contains("redis://127.0.0.1:6379"),
            "got: {rendered}"
        );
        assert!(rendered.contains("/etc/ssl/ca.pem"), "got: {rendered}");
    }

    #[test]
    fn debug_redacts_url_whose_password_contains_a_raw_question_mark() {
        // The pathological form: the '?' inside the password precedes the
        // real '@', so the userinfo boundary can't be located. `redact_url`
        // must bail out to a fully redacted value rather than print a prefix
        // of the password (e.g. "redis://:pa").
        let config = CacheConfig {
            url: "redis://:pa?ss#word/x+y=z@127.0.0.1:6379".to_string(),
            pool_size: 1,
            ca_cert_path: None,
            password: None,
        };

        let rendered = format!("{config:?}");

        // Note: assert on distinctive password substrings only — the field
        // name "password" itself contains e.g. "pa".
        for leak in ["pa?ss", "#word", "x+y=z", "pa?"] {
            assert!(
                !rendered.contains(leak),
                "Debug must not leak any part of an unparseable password \
                 (found {leak:?}), got: {rendered}"
            );
        }
        assert!(rendered.contains("<redacted>"), "got: {rendered}");
    }
}
