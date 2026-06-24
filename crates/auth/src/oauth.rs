//! OAuth 2.0 authorization-code login for Google and GitHub.
//!
//! Flow, provider-agnostic:
//! 1. [`OAuthClient::authorize_url`] builds the provider's authorize URL with a
//!    CSPRNG `state` (CSRF defence) and, where supported, a PKCE S256
//!    challenge. The returned [`AuthorizeRequest`] also carries the `state` and
//!    PKCE verifier the caller must stash in the session for step 3.
//! 2. The user authenticates at the provider and is redirected back with a
//!    `code` (and the `state` echoed back, which the caller must compare).
//! 3. [`OAuthClient::exchange_code`] swaps the `code` (plus the stored PKCE
//!    verifier) for an access token, then [`OAuthClient::fetch_user`] returns a
//!    normalized [`OAuthUser`].
//!
//! **PKCE.** Google supports PKCE S256 and we always use it there. GitHub's
//! web flow does not implement PKCE, so for GitHub we rely on `state` alone and
//! send no `code_verifier`. The provider config drives this difference.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ferrlabs_errors::ApiError;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::Url;

/// Which identity provider a flow targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthProvider {
    Google,
    GitHub,
}

impl OAuthProvider {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            OAuthProvider::Google => "google",
            OAuthProvider::GitHub => "github",
        }
    }

    fn authorize_endpoint(self) -> &'static str {
        match self {
            OAuthProvider::Google => "https://accounts.google.com/o/oauth2/v2/auth",
            OAuthProvider::GitHub => "https://github.com/login/oauth/authorize",
        }
    }

    fn token_endpoint(self) -> &'static str {
        match self {
            OAuthProvider::Google => "https://oauth2.googleapis.com/token",
            OAuthProvider::GitHub => "https://github.com/login/oauth/access_token",
        }
    }

    fn userinfo_endpoint(self) -> &'static str {
        match self {
            OAuthProvider::Google => "https://openidconnect.googleapis.com/v1/userinfo",
            OAuthProvider::GitHub => "https://api.github.com/user",
        }
    }

    fn default_scope(self) -> &'static str {
        match self {
            OAuthProvider::Google => "openid email profile",
            OAuthProvider::GitHub => "read:user user:email",
        }
    }

    fn supports_pkce(self) -> bool {
        matches!(self, OAuthProvider::Google)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    #[error("oauth provider request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("oauth provider returned an error: {0}")]
    Provider(String),
    #[error("oauth provider response was missing field: {0}")]
    MissingField(&'static str),
}

impl From<OAuthError> for ApiError {
    fn from(err: OAuthError) -> Self {
        match err {
            OAuthError::Provider(msg) => ApiError::BadRequest(msg),
            OAuthError::MissingField(field) => {
                ApiError::BadRequest(format!("oauth: missing {field}"))
            }
            OAuthError::Http(e) => ApiError::Internal(anyhow::anyhow!("oauth http: {e}")),
        }
    }
}

/// Per-provider OAuth client config. `client_id`/`client_secret` come from the
/// product's secrets; `redirect_uri` is the product's callback URL.
#[derive(Debug, Clone)]
pub struct OAuthClient {
    provider: OAuthProvider,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    scope: String,
    http: reqwest::Client,
}

/// What [`OAuthClient::authorize_url`] hands back: the URL to redirect the user
/// to, plus the `state` and (optional) PKCE verifier the caller must persist in
/// the pending-login session to validate the callback.
#[derive(Debug, Clone)]
pub struct AuthorizeRequest {
    pub url: String,
    pub state: String,
    pub pkce_verifier: Option<String>,
}

/// Normalized identity returned after a successful exchange + userinfo fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthUser {
    pub provider: OAuthProvider,
    /// Provider-stable subject id (`sub` for Google, numeric `id` for GitHub).
    pub provider_user_id: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
}

impl OAuthClient {
    /// Build a client. `scope` overrides the provider default when `Some`.
    #[must_use]
    pub fn new(
        provider: OAuthProvider,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
        scope: Option<String>,
    ) -> Self {
        Self {
            provider,
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            scope: scope.unwrap_or_else(|| provider.default_scope().to_string()),
            http: reqwest::Client::new(),
        }
    }

    #[must_use]
    pub fn provider(&self) -> OAuthProvider {
        self.provider
    }

    /// Build the provider authorize URL with a fresh `state` and, for providers
    /// that support it, a PKCE S256 challenge.
    #[must_use]
    pub fn authorize_url(&self) -> AuthorizeRequest {
        let state = random_token();
        let pkce_verifier = self.provider.supports_pkce().then(random_token);

        let mut url = Url::parse(self.provider.authorize_endpoint())
            .expect("provider authorize endpoint is a valid const URL");
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("client_id", &self.client_id);
            q.append_pair("redirect_uri", &self.redirect_uri);
            q.append_pair("response_type", "code");
            q.append_pair("scope", &self.scope);
            q.append_pair("state", &state);
            if let Some(verifier) = &pkce_verifier {
                q.append_pair("code_challenge", &pkce_challenge_s256(verifier));
                q.append_pair("code_challenge_method", "S256");
            }
        }

        AuthorizeRequest {
            url: url.into(),
            state,
            pkce_verifier,
        }
    }

    /// Exchange an authorization `code` for an access token.
    ///
    /// `pkce_verifier` must be the value stored alongside the `state` for
    /// PKCE providers; pass `None` for GitHub.
    ///
    /// # Errors
    /// - [`OAuthError::Http`] on transport failure.
    /// - [`OAuthError::Provider`] if the provider returns an `error` field.
    /// - [`OAuthError::MissingField`] if no `access_token` is present.
    pub async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: Option<&str>,
    ) -> Result<String, OAuthError> {
        let mut form = vec![
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("code", code),
            ("grant_type", "authorization_code"),
            ("redirect_uri", self.redirect_uri.as_str()),
        ];
        if let Some(verifier) = pkce_verifier {
            form.push(("code_verifier", verifier));
        }

        let resp = self
            .http
            .post(self.provider.token_endpoint())
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&form)
            .send()
            .await?
            .error_for_status()?;

        let token: TokenResponse = resp.json().await?;
        if let Some(err) = token.error {
            return Err(OAuthError::Provider(err));
        }
        token
            .access_token
            .ok_or(OAuthError::MissingField("access_token"))
    }

    /// Fetch and normalize the authenticated user's profile.
    ///
    /// # Errors
    /// - [`OAuthError::Http`] on transport failure.
    /// - [`OAuthError::MissingField`] if the provider omits the subject id.
    pub async fn fetch_user(&self, access_token: &str) -> Result<OAuthUser, OAuthError> {
        let resp = self
            .http
            .get(self.provider.userinfo_endpoint())
            .bearer_auth(access_token)
            .header(reqwest::header::USER_AGENT, "ferrlabs-auth")
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await?
            .error_for_status()?;

        let body = resp.text().await?;
        parse_user(self.provider, &body)
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct GoogleUserInfo {
    sub: String,
    email: Option<String>,
    #[serde(default)]
    email_verified: bool,
    name: Option<String>,
}

#[derive(Deserialize)]
struct GitHubUserInfo {
    id: u64,
    email: Option<String>,
    name: Option<String>,
    login: Option<String>,
}

fn parse_user(provider: OAuthProvider, body: &str) -> Result<OAuthUser, OAuthError> {
    match provider {
        OAuthProvider::Google => {
            let info: GoogleUserInfo = serde_json::from_str(body)
                .map_err(|e| OAuthError::Provider(format!("google userinfo: {e}")))?;
            Ok(OAuthUser {
                provider,
                provider_user_id: info.sub,
                email: info.email,
                email_verified: info.email_verified,
                name: info.name,
            })
        }
        OAuthProvider::GitHub => {
            let info: GitHubUserInfo = serde_json::from_str(body)
                .map_err(|e| OAuthError::Provider(format!("github user: {e}")))?;
            Ok(OAuthUser {
                provider,
                provider_user_id: info.id.to_string(),
                email: info.email,
                // GitHub's /user endpoint does not assert verification; the
                // caller must hit /user/emails for a verified primary if it
                // needs that guarantee.
                email_verified: false,
                name: info.name.or(info.login),
            })
        }
    }
}

/// 32 bytes of CSPRNG entropy, URL-safe base64 (no padding). Used for both the
/// `state` parameter and the PKCE verifier; both are opaque high-entropy
/// strings that round-trip through query params unchanged.
fn random_token() -> String {
    let bytes: [u8; 32] = rand::random();
    URL_SAFE_NO_PAD.encode(bytes)
}

/// PKCE S256 challenge: `base64url(sha256(verifier))`, no padding (RFC 7636).
fn pkce_challenge_s256(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn google_client() -> OAuthClient {
        OAuthClient::new(
            OAuthProvider::Google,
            "google-client-id",
            "google-secret",
            "https://app.ferrlabs.com/auth/google/callback",
            None,
        )
    }

    fn github_client() -> OAuthClient {
        OAuthClient::new(
            OAuthProvider::GitHub,
            "github-client-id",
            "github-secret",
            "https://app.ferrlabs.com/auth/github/callback",
            None,
        )
    }

    fn query_pairs(url: &str) -> std::collections::HashMap<String, String> {
        Url::parse(url)
            .unwrap()
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    #[test]
    fn google_authorize_url_has_pkce_and_required_params() {
        let req = google_client().authorize_url();
        assert!(
            req.url
                .starts_with("https://accounts.google.com/o/oauth2/v2/auth?")
        );
        let q = query_pairs(&req.url);

        assert_eq!(q.get("client_id").unwrap(), "google-client-id");
        assert_eq!(
            q.get("redirect_uri").unwrap(),
            "https://app.ferrlabs.com/auth/google/callback"
        );
        assert_eq!(q.get("response_type").unwrap(), "code");
        assert_eq!(q.get("scope").unwrap(), "openid email profile");
        assert_eq!(q.get("state").unwrap(), &req.state);
        assert_eq!(q.get("code_challenge_method").unwrap(), "S256");

        let verifier = req
            .pkce_verifier
            .expect("google flow must carry a verifier");
        assert_eq!(
            q.get("code_challenge").unwrap(),
            &pkce_challenge_s256(&verifier)
        );
    }

    #[test]
    fn github_authorize_url_omits_pkce() {
        let req = github_client().authorize_url();
        assert!(
            req.url
                .starts_with("https://github.com/login/oauth/authorize?")
        );
        let q = query_pairs(&req.url);

        assert_eq!(q.get("client_id").unwrap(), "github-client-id");
        assert_eq!(q.get("scope").unwrap(), "read:user user:email");
        assert_eq!(q.get("state").unwrap(), &req.state);
        assert!(q.get("code_challenge").is_none());
        assert!(q.get("code_challenge_method").is_none());
        assert!(req.pkce_verifier.is_none());
    }

    #[test]
    fn custom_scope_overrides_default() {
        let client = OAuthClient::new(
            OAuthProvider::Google,
            "id",
            "secret",
            "https://example.com/cb",
            Some("openid email".to_string()),
        );
        let q = query_pairs(&client.authorize_url().url);
        assert_eq!(q.get("scope").unwrap(), "openid email");
    }

    #[test]
    fn state_is_unique_per_request() {
        let client = google_client();
        let a = client.authorize_url();
        let b = client.authorize_url();
        assert_ne!(a.state, b.state);
        assert_ne!(a.pkce_verifier, b.pkce_verifier);
    }

    #[test]
    fn state_and_verifier_are_url_safe_high_entropy() {
        let req = google_client().authorize_url();
        for token in [Some(req.state), req.pkce_verifier].into_iter().flatten() {
            assert_eq!(token.len(), 43, "32 bytes base64url no-pad → 43 chars");
            assert!(
                token
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            );
        }
    }

    #[test]
    fn pkce_challenge_matches_rfc7636_vector() {
        // RFC 7636 Appendix B worked example.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = pkce_challenge_s256(verifier);
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn parses_google_userinfo() {
        let body = r#"{
            "sub": "10769150350006150715113082367",
            "email": "ada@example.com",
            "email_verified": true,
            "name": "Ada Lovelace"
        }"#;
        let user = parse_user(OAuthProvider::Google, body).unwrap();
        assert_eq!(user.provider, OAuthProvider::Google);
        assert_eq!(user.provider_user_id, "10769150350006150715113082367");
        assert_eq!(user.email.as_deref(), Some("ada@example.com"));
        assert!(user.email_verified);
        assert_eq!(user.name.as_deref(), Some("Ada Lovelace"));
    }

    #[test]
    fn google_userinfo_defaults_email_verified_false_when_absent() {
        let body = r#"{ "sub": "123", "email": "x@y.com" }"#;
        let user = parse_user(OAuthProvider::Google, body).unwrap();
        assert!(!user.email_verified);
        assert!(user.name.is_none());
    }

    #[test]
    fn parses_github_user_with_numeric_id() {
        let body = r#"{
            "id": 583231,
            "login": "octocat",
            "email": "octocat@github.com",
            "name": "The Octocat"
        }"#;
        let user = parse_user(OAuthProvider::GitHub, body).unwrap();
        assert_eq!(user.provider_user_id, "583231");
        assert_eq!(user.email.as_deref(), Some("octocat@github.com"));
        assert_eq!(user.name.as_deref(), Some("The Octocat"));
        assert!(!user.email_verified);
    }

    #[test]
    fn github_user_falls_back_to_login_when_name_null() {
        let body = r#"{ "id": 1, "login": "ghost", "email": null, "name": null }"#;
        let user = parse_user(OAuthProvider::GitHub, body).unwrap();
        assert_eq!(user.name.as_deref(), Some("ghost"));
        assert!(user.email.is_none());
    }

    #[test]
    fn malformed_userinfo_is_an_error() {
        assert!(parse_user(OAuthProvider::Google, "not json").is_err());
        assert!(parse_user(OAuthProvider::GitHub, "{}").is_err());
    }
}
