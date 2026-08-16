use ferrlabs_oauth::{OAuthClient, OAuthProvider};

use crate::GithubError;

/// Whether `installation_id` appears in a `GET /user/installations` payload.
///
/// Split out from the HTTP call so the shape handling is testable without a
/// network. A malformed, empty or unexpected body must read as "not owned"
/// rather than panic or, worse, default to true.
#[must_use]
pub fn owns_installation(payload: &serde_json::Value, installation_id: i64) -> bool {
    payload
        .get("installations")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|installations| {
            installations
                .iter()
                .filter_map(|entry| entry.get("id").and_then(serde_json::Value::as_i64))
                .any(|id| id == installation_id)
        })
}

/// GitHub's own answer to "does this user have this installation?".
#[derive(Clone)]
pub struct GithubOauth {
    oauth: OAuthClient,
    user_agent: String,
    http: reqwest::Client,
}

impl GithubOauth {
    /// Build from the App's user-authorization OAuth credentials.
    ///
    /// `redirect_uri` must match the one registered on the App, because GitHub
    /// validates it during the code exchange.
    #[must_use]
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
        user_agent: impl Into<String>,
    ) -> Self {
        Self {
            oauth: OAuthClient::new(
                OAuthProvider::GitHub,
                client_id,
                client_secret,
                redirect_uri,
                None,
            ),
            user_agent: user_agent.into(),
            http: reqwest::Client::new(),
        }
    }

    /// True when GitHub confirms this user has this installation.
    ///
    /// An error means ownership could not be established, which is not the same
    /// as a denial but must be treated the same way by the caller. Returning a
    /// bool for the settled case and an error otherwise keeps that from being
    /// read backwards.
    ///
    /// The `code` is exchanged for a user token that is used once and dropped.
    /// It is never persisted: it grants read access to the user's installations,
    /// and the answer wanted from it is a single boolean that stops being true
    /// the moment they uninstall.
    pub async fn user_owns_installation(
        &self,
        code: &str,
        installation_id: i64,
    ) -> Result<bool, GithubError> {
        let token = self
            .oauth
            .exchange_code(code, None)
            .await
            .map_err(GithubError::Exchange)?;

        let response = self
            .http
            .get("https://api.github.com/user/installations")
            .header("Authorization", format!("Bearer {token}"))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", &self.user_agent)
            .send()
            .await
            .map_err(GithubError::http("listing the user's installations"))?
            .error_for_status()
            .map_err(GithubError::http(
                "listing the user's installations returned an error status",
            ))?;

        let payload: serde_json::Value = response
            .json()
            .await
            .map_err(GithubError::http("decoding the user's installations"))?;

        Ok(owns_installation(&payload, installation_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn recognises_an_owned_installation() {
        let payload = json!({"total_count": 2, "installations": [{"id": 11}, {"id": 42}]});
        assert!(owns_installation(&payload, 42));
    }

    #[test]
    fn rejects_an_installation_the_user_does_not_have() {
        let payload = json!({"total_count": 1, "installations": [{"id": 11}]});
        assert!(!owns_installation(&payload, 42));
    }

    #[test]
    fn an_empty_list_owns_nothing() {
        let payload = json!({"total_count": 0, "installations": []});
        assert!(!owns_installation(&payload, 42));
    }

    /// The shapes we would see if the endpoint changed, the token were scoped
    /// away, or an error body were parsed as success. Each must read as "not
    /// owned": a verification step that fails open is worse than none, because
    /// it looks like it is protecting something.
    #[test]
    fn unexpected_shapes_never_grant_ownership() {
        for payload in [
            json!({}),
            json!({"installations": null}),
            json!({"installations": {}}),
            json!({"message": "Bad credentials"}),
            json!([{"id": 42}]),
            json!({"installations": [{"id": "42"}]}),
        ] {
            assert!(
                !owns_installation(&payload, 42),
                "unexpected payload granted ownership: {payload}"
            );
        }
    }

    /// `id` is an `i64` in the API and installation ids are already past 2^31,
    /// so a narrowing bug here would silently mismatch on real accounts.
    #[test]
    fn matches_ids_beyond_32_bits() {
        let big = 4_294_967_297_i64;
        let payload = json!({"installations": [{"id": big}]});
        assert!(owns_installation(&payload, big));
        assert!(!owns_installation(&payload, 1));
    }
}
