//! Hashicorp Vault KV v2 client used across the FerrLabs platform.
//!
//! Targets the KV v2 secrets engine and exposes the three operations
//! every product needs: read, write, delete. URLs follow the canonical
//! KV v2 layout (`{addr}/v1/{mount}/data/{path}` for reads/writes,
//! `{addr}/v1/{mount}/metadata/{path}` for deletes — which destroys
//! every version, the intended behaviour for secret rotation).
//!
//! ```no_run
//! # async fn run() -> anyhow::Result<()> {
//! use ferrlabs_vault::VaultClient;
//! let v = VaultClient::new("https://vault.example.com", "s.token", "secret");
//! v.write_secret("ferrfleet/token", "ghp_x").await?;
//! let got = v.read_secret("ferrfleet/token").await?;
//! assert_eq!(got.as_deref(), Some("ghp_x"));
//! v.delete_secret("ferrfleet/token").await?;
//! # Ok(()) }
//! ```

use std::fmt;

use anyhow::{Context, Result, anyhow, bail};
use reqwest::{Client, StatusCode, Url};
use serde_json::{Value, json};

const SECRET_FIELD: &str = "value";

#[derive(Clone)]
pub struct VaultClient {
    http: Client,
    addr: String,
    token: String,
    mount: String,
}

impl VaultClient {
    #[must_use]
    pub fn new(addr: &str, token: &str, mount: &str) -> Self {
        Self {
            http: Client::new(),
            addr: addr.trim_end_matches('/').to_string(),
            token: token.to_string(),
            mount: mount.trim_matches('/').to_string(),
        }
    }

    fn data_url(&self, path: &str) -> Result<Url> {
        self.kv_url("data", path)
    }

    fn metadata_url(&self, path: &str) -> Result<Url> {
        self.kv_url("metadata", path)
    }

    fn kv_url(&self, kind: &str, path: &str) -> Result<Url> {
        let secret_segments = validated_segments(path)?;
        let mut url = Url::parse(&self.addr).context("invalid vault address")?;
        url.path_segments_mut()
            .map_err(|()| anyhow!("vault address cannot be used as a base url"))?
            .pop_if_empty()
            .push("v1")
            .extend(self.mount.split('/'))
            .push(kind)
            .extend(secret_segments);
        Ok(url)
    }

    pub async fn write_secret(&self, path: &str, value: &str) -> Result<()> {
        let resp = self
            .http
            .post(self.data_url(path)?)
            .header("X-Vault-Token", &self.token)
            .json(&json!({ "data": { SECRET_FIELD: value } }))
            .send()
            .await
            .context("vault write request failed")?;
        if !resp.status().is_success() {
            bail!("vault write returned {}", resp.status());
        }
        Ok(())
    }

    pub async fn read_secret(&self, path: &str) -> Result<Option<String>> {
        let resp = self
            .http
            .get(self.data_url(path)?)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .context("vault read request failed")?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            bail!("vault read returned {}", resp.status());
        }
        let body: Value = resp.json().await.context("parsing vault response")?;
        Ok(parse_secret_value(&body))
    }

    pub async fn delete_secret(&self, path: &str) -> Result<()> {
        let resp = self
            .http
            .delete(self.metadata_url(path)?)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .context("vault delete request failed")?;
        if !resp.status().is_success() && resp.status() != StatusCode::NOT_FOUND {
            bail!("vault delete returned {}", resp.status());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidSecretPath {
    EmptySegment,
    DotSegment,
}

impl fmt::Display for InvalidSecretPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySegment => f.write_str("secret path contains an empty segment"),
            Self::DotSegment => f.write_str("secret path contains a `.` or `..` segment"),
        }
    }
}

impl std::error::Error for InvalidSecretPath {}

fn validated_segments(path: &str) -> Result<Vec<&str>, InvalidSecretPath> {
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    for segment in &segments {
        if segment.is_empty() {
            return Err(InvalidSecretPath::EmptySegment);
        }
        if is_dot_segment(segment) {
            return Err(InvalidSecretPath::DotSegment);
        }
    }
    Ok(segments)
}

fn is_dot_segment(segment: &str) -> bool {
    segment
        .to_ascii_lowercase()
        .replace("%2e", ".")
        .chars()
        .all(|c| c == '.')
}

fn parse_secret_value(body: &Value) -> Option<String> {
    body.get("data")?
        .get("data")?
        .get(SECRET_FIELD)?
        .as_str()
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> VaultClient {
        VaultClient::new("https://vault.example.com/", "t", "/secret/")
    }

    fn data(c: &VaultClient, path: &str) -> String {
        c.data_url(path).unwrap().to_string()
    }

    fn rejection(result: Result<Url>) -> InvalidSecretPath {
        result.unwrap_err().downcast::<InvalidSecretPath>().unwrap()
    }

    #[test]
    fn builds_kv_v2_urls() {
        let c = client();
        assert_eq!(
            data(&c, "/ferrfleet/connectors/org/id/"),
            "https://vault.example.com/v1/secret/data/ferrfleet/connectors/org/id"
        );
        assert_eq!(
            c.metadata_url("ferrfleet/connectors/org/id")
                .unwrap()
                .as_str(),
            "https://vault.example.com/v1/secret/metadata/ferrfleet/connectors/org/id"
        );
    }

    #[test]
    fn rejects_traversal_in_every_url_builder() {
        let c = client();
        for path in ["a/../../../sys/seal", "..", "../x", "a/..", "./a", "a/./b"] {
            assert_eq!(
                rejection(c.data_url(path)),
                InvalidSecretPath::DotSegment,
                "{path}"
            );
            assert_eq!(
                rejection(c.metadata_url(path)),
                InvalidSecretPath::DotSegment,
                "{path}"
            );
        }
    }

    #[test]
    fn rejects_percent_encoded_traversal() {
        let c = client();
        for path in ["a/%2e%2e/b", "a/%2E%2E/b", "a/.%2e/b", "a/%2e/b", "%2e%2e"] {
            assert_eq!(
                rejection(c.data_url(path)),
                InvalidSecretPath::DotSegment,
                "{path}"
            );
            assert_eq!(
                rejection(c.metadata_url(path)),
                InvalidSecretPath::DotSegment,
                "{path}"
            );
        }
    }

    #[test]
    fn rejects_empty_segments() {
        let c = client();
        for path in ["", "/", "a//b", "//double//slash//"] {
            assert_eq!(
                rejection(c.data_url(path)),
                InvalidSecretPath::EmptySegment,
                "{path}"
            );
        }
    }

    #[test]
    fn allows_dots_inside_segment_names() {
        let c = client();
        assert_eq!(
            data(&c, "a/.hidden/b..c/file.txt"),
            "https://vault.example.com/v1/secret/data/a/.hidden/b..c/file.txt"
        );
    }

    #[test]
    fn encodes_reserved_characters_within_a_segment() {
        let c = client();
        let url = c.data_url("a/b?x=1#frag/c d%2fe").unwrap();
        assert_eq!(url.query(), None);
        assert_eq!(url.fragment(), None);
        assert_eq!(
            url.as_str(),
            "https://vault.example.com/v1/secret/data/a/b%3Fx=1%23frag/c%20d%252fe"
        );
    }

    #[test]
    fn parses_kv_v2_value() {
        let body = json!({ "data": { "data": { "value": "ghp_x" }, "metadata": {} } });
        assert_eq!(parse_secret_value(&body), Some("ghp_x".to_string()));
    }

    #[test]
    fn parse_returns_none_when_missing() {
        assert_eq!(parse_secret_value(&json!({ "data": { "data": {} } })), None);
        assert_eq!(parse_secret_value(&json!({})), None);
    }

    #[test]
    fn url_building_trims_outer_slashes() {
        let c = client();
        assert_eq!(
            data(&c, "no-leading-slash"),
            "https://vault.example.com/v1/secret/data/no-leading-slash"
        );
        assert_eq!(
            data(&c, "//trailing//"),
            "https://vault.example.com/v1/secret/data/trailing"
        );
    }

    #[test]
    fn new_trims_trailing_addr_slash_and_mount_slashes() {
        let c = VaultClient::new("https://v.example.com///", "tok", "//kv//");
        assert_eq!(data(&c, "p"), "https://v.example.com/v1/kv/data/p");
    }

    #[test]
    fn keeps_address_path_prefix_and_nested_mount() {
        let c = VaultClient::new("https://v.example.com/proxy/", "tok", "team/kv");
        assert_eq!(
            data(&c, "p"),
            "https://v.example.com/proxy/v1/team/kv/data/p"
        );
    }

    #[test]
    fn parse_returns_none_when_value_not_a_string() {
        let body = json!({ "data": { "data": { "value": 42 } } });
        assert_eq!(parse_secret_value(&body), None);
    }

    #[test]
    fn parse_reads_only_the_value_field() {
        let body = json!({ "data": { "data": { "other": "x" } } });
        assert_eq!(parse_secret_value(&body), None);
    }
}
