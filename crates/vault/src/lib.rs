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

use anyhow::{Context, Result, bail};
use reqwest::{Client, StatusCode};
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

    fn data_url(&self, path: &str) -> String {
        format!(
            "{}/v1/{}/data/{}",
            self.addr,
            self.mount,
            path.trim_matches('/')
        )
    }

    fn metadata_url(&self, path: &str) -> String {
        format!(
            "{}/v1/{}/metadata/{}",
            self.addr,
            self.mount,
            path.trim_matches('/')
        )
    }

    pub async fn write_secret(&self, path: &str, value: &str) -> Result<()> {
        let resp = self
            .http
            .post(self.data_url(path))
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
            .get(self.data_url(path))
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
            .delete(self.metadata_url(path))
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

    #[test]
    fn builds_kv_v2_urls() {
        let c = client();
        assert_eq!(
            c.data_url("/ferrfleet/connectors/org/id/"),
            "https://vault.example.com/v1/secret/data/ferrfleet/connectors/org/id"
        );
        assert_eq!(
            c.metadata_url("ferrfleet/connectors/org/id"),
            "https://vault.example.com/v1/secret/metadata/ferrfleet/connectors/org/id"
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
    fn url_building_is_idempotent_on_slashes() {
        let c = client();
        assert_eq!(
            c.data_url("no-leading-slash"),
            "https://vault.example.com/v1/secret/data/no-leading-slash"
        );
        assert_eq!(
            c.data_url("//double//slash//"),
            "https://vault.example.com/v1/secret/data/double//slash"
        );
    }

    #[test]
    fn new_trims_trailing_addr_slash_and_mount_slashes() {
        let c = VaultClient::new("https://v.example.com///", "tok", "//kv//");
        assert_eq!(c.data_url("p"), "https://v.example.com/v1/kv/data/p");
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
