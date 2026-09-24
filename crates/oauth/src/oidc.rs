use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ferrlabs_http::{SafeFetchOpts, SafeHttpClient, safe_get, safe_post_form};
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation, decode, decode_header};
use serde::Deserialize;
use serde_json::{Map, Value};
use url::Url;

use super::{pkce_challenge_s256, random_token};

const JWKS_MIN_REFRESH: Duration = Duration::from_secs(60);
const CLOCK_LEEWAY_SECS: u64 = 60;
const DEFAULT_SCOPE: &str = "openid email profile";
const DISCOVERY_PATH: &str = "/.well-known/openid-configuration";
const ERROR_BODY_CHARS: usize = 300;

#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("issuer must be an absolute https url with no query or fragment: {0}")]
    IssuerUrl(String),
    #[error("discovery for {issuer} failed: {reason}")]
    Discovery { issuer: String, reason: String },
    #[error("discovery document names issuer {found}, expected {expected}")]
    IssuerMismatch { expected: String, found: String },
    #[error("{name} in the discovery document is not an https url: {value}")]
    Endpoint { name: &'static str, value: String },
    #[error("issuer advertises no id_token signing algorithm this build accepts")]
    NoUsableAlgorithm,
    #[error("token request failed: {0}")]
    TokenRequest(String),
    #[error("token endpoint returned {status}: {body}")]
    TokenEndpoint { status: u16, body: String },
    #[error("token response carried no id_token")]
    MissingIdToken,
    #[error("id_token is signed with {0}, which the issuer does not advertise")]
    UnexpectedAlgorithm(String),
    #[error("the issuer's jwks has no key {0}")]
    UnknownKey(String),
    #[error("jwks fetch for {issuer} failed: {reason}")]
    Jwks { issuer: String, reason: String },
    #[error("id_token rejected: {0}")]
    IdToken(String),
    #[error("id_token nonce does not match this login attempt")]
    NonceMismatch,
    #[error("id_token has several audiences and no azp naming this client")]
    AzpMismatch,
}

#[cfg(feature = "errors")]
impl From<OidcError> for ferrlabs_errors::ApiError {
    fn from(err: OidcError) -> Self {
        use ferrlabs_errors::ApiError;
        match err {
            OidcError::IssuerUrl(_)
            | OidcError::IssuerMismatch { .. }
            | OidcError::Endpoint { .. }
            | OidcError::NoUsableAlgorithm => ApiError::BadRequest(err.to_string()),
            OidcError::UnexpectedAlgorithm(_)
            | OidcError::UnknownKey(_)
            | OidcError::IdToken(_)
            | OidcError::NonceMismatch
            | OidcError::AzpMismatch
            | OidcError::MissingIdToken => ApiError::Unauthorized,
            OidcError::Discovery { .. }
            | OidcError::Jwks { .. }
            | OidcError::TokenRequest(_)
            | OidcError::TokenEndpoint { .. } => ApiError::Internal(anyhow::anyhow!("{err}")),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct IssuerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct OidcAuthorizeRequest {
    pub url: String,
    pub state: String,
    pub nonce: String,
    pub pkce_verifier: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcIdentity {
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
}

pub struct IdTokenExpectations<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub nonce: &'a str,
    pub algorithms: &'a [Algorithm],
}

pub fn normalize_issuer(raw: &str) -> Result<String, OidcError> {
    let parsed = Url::parse(raw.trim()).map_err(|_| OidcError::IssuerUrl(raw.to_string()))?;
    if parsed.scheme() != "https" || parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(OidcError::IssuerUrl(raw.to_string()));
    }
    if parsed.host_str().is_none() {
        return Err(OidcError::IssuerUrl(raw.to_string()));
    }
    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

#[must_use]
pub fn discovery_url(issuer: &str) -> String {
    format!("{issuer}{DISCOVERY_PATH}")
}

pub fn check_metadata(expected_issuer: &str, meta: &IssuerMetadata) -> Result<(), OidcError> {
    let found = meta.issuer.trim_end_matches('/');
    if found != expected_issuer {
        return Err(OidcError::IssuerMismatch {
            expected: expected_issuer.to_string(),
            found: meta.issuer.clone(),
        });
    }
    for (name, value) in [
        ("authorization_endpoint", &meta.authorization_endpoint),
        ("token_endpoint", &meta.token_endpoint),
        ("jwks_uri", &meta.jwks_uri),
    ] {
        let url = Url::parse(value).map_err(|_| OidcError::Endpoint {
            name,
            value: value.clone(),
        })?;
        if url.scheme() != "https" {
            return Err(OidcError::Endpoint {
                name,
                value: value.clone(),
            });
        }
    }
    Ok(())
}

pub fn signing_algorithms(meta: &IssuerMetadata) -> Result<Vec<Algorithm>, OidcError> {
    if meta.id_token_signing_alg_values_supported.is_empty() {
        return Ok(vec![Algorithm::RS256]);
    }
    let usable: Vec<Algorithm> = meta
        .id_token_signing_alg_values_supported
        .iter()
        .filter_map(|name| Algorithm::from_str(name).ok())
        .filter(|alg| is_asymmetric(*alg))
        .collect();
    if usable.is_empty() {
        return Err(OidcError::NoUsableAlgorithm);
    }
    Ok(usable)
}

fn is_asymmetric(alg: Algorithm) -> bool {
    !matches!(alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512)
}

pub fn select_key<'a>(jwks: &'a JwkSet, header: &Header) -> Result<&'a Jwk, OidcError> {
    let jwk = match &header.kid {
        Some(kid) => jwks
            .find(kid)
            .ok_or_else(|| OidcError::UnknownKey(kid.clone()))?,
        None => match jwks.keys.as_slice() {
            [only] => only,
            _ => return Err(OidcError::UnknownKey("<no kid>".to_string())),
        },
    };
    if let Some(key_alg) = jwk.common.key_algorithm {
        let declared = Algorithm::try_from(key_alg)
            .map_err(|_| OidcError::UnexpectedAlgorithm(key_alg.to_string()))?;
        if declared != header.alg {
            return Err(OidcError::UnexpectedAlgorithm(format!("{:?}", header.alg)));
        }
    }
    Ok(jwk)
}

pub fn check_claims(
    claims: &Map<String, Value>,
    expectations: &IdTokenExpectations<'_>,
) -> Result<(), OidcError> {
    let nonce = claims.get("nonce").and_then(Value::as_str);
    if nonce != Some(expectations.nonce) {
        return Err(OidcError::NonceMismatch);
    }
    let subject = claims.get("sub").and_then(Value::as_str).unwrap_or("");
    if subject.is_empty() {
        return Err(OidcError::IdToken(
            "sub is missing or is not a non-empty string".to_string(),
        ));
    }
    let several_audiences = claims
        .get("aud")
        .and_then(Value::as_array)
        .is_some_and(|auds| auds.len() > 1);
    if several_audiences {
        let azp = claims.get("azp").and_then(Value::as_str);
        if azp != Some(expectations.client_id) {
            return Err(OidcError::AzpMismatch);
        }
    }
    Ok(())
}

pub fn validate_id_token(
    token: &str,
    jwks: &JwkSet,
    expectations: &IdTokenExpectations<'_>,
) -> Result<Map<String, Value>, OidcError> {
    let header = decode_header(token).map_err(|e| OidcError::IdToken(e.to_string()))?;
    if !expectations.algorithms.contains(&header.alg) {
        return Err(OidcError::UnexpectedAlgorithm(format!("{:?}", header.alg)));
    }
    let jwk = select_key(jwks, &header)?;
    let key = DecodingKey::from_jwk(jwk).map_err(|e| OidcError::IdToken(e.to_string()))?;

    let mut validation = Validation::new(header.alg);
    validation.leeway = CLOCK_LEEWAY_SECS;
    validation.set_issuer(&[expectations.issuer]);
    validation.set_audience(&[expectations.client_id]);
    validation.set_required_spec_claims(&["iss", "aud", "exp", "sub"]);

    let data = decode::<Map<String, Value>>(token, &key, &validation)
        .map_err(|e| OidcError::IdToken(e.to_string()))?;
    check_claims(&data.claims, expectations)?;
    Ok(data.claims)
}

#[must_use]
pub fn identity_from_claims(issuer: &str, claims: &Map<String, Value>) -> OidcIdentity {
    let string = |key: &str| {
        claims
            .get(key)
            .and_then(Value::as_str)
            .map(ToString::to_string)
    };
    OidcIdentity {
        issuer: issuer.to_string(),
        subject: string("sub").unwrap_or_default(),
        email: string("email"),
        email_verified: claims
            .get("email_verified")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        name: string("name"),
    }
}

struct CachedJwks {
    set: JwkSet,
    fetched_at: Instant,
}

pub struct OidcClient {
    meta: IssuerMetadata,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    scope: String,
    algorithms: Vec<Algorithm>,
    http: SafeHttpClient,
    fetch: SafeFetchOpts,
    jwks: Mutex<Option<CachedJwks>>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
}

pub async fn discover(issuer: &str) -> Result<IssuerMetadata, OidcError> {
    let issuer = normalize_issuer(issuer)?;
    let client = SafeHttpClient::new();
    let opts = SafeFetchOpts::default();
    let response = safe_get(&client, &discovery_url(&issuer), &opts)
        .await
        .map_err(|e| OidcError::Discovery {
            issuer: issuer.clone(),
            reason: e.to_string(),
        })?;
    if response.status != 200 {
        return Err(OidcError::Discovery {
            issuer,
            reason: format!("status {}", response.status),
        });
    }
    let meta: IssuerMetadata =
        serde_json::from_slice(&response.body).map_err(|e| OidcError::Discovery {
            issuer: issuer.clone(),
            reason: e.to_string(),
        })?;
    check_metadata(&issuer, &meta)?;
    Ok(meta)
}

impl OidcClient {
    pub fn new(
        meta: IssuerMetadata,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
        scope: Option<String>,
    ) -> Result<Self, OidcError> {
        let algorithms = signing_algorithms(&meta)?;
        Ok(Self {
            meta,
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            scope: scope.unwrap_or_else(|| DEFAULT_SCOPE.to_string()),
            algorithms,
            http: SafeHttpClient::new(),
            fetch: SafeFetchOpts::default(),
            jwks: Mutex::new(None),
        })
    }

    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.meta.issuer
    }

    #[must_use]
    pub fn algorithms(&self) -> &[Algorithm] {
        &self.algorithms
    }

    #[must_use]
    pub fn authorize(&self) -> OidcAuthorizeRequest {
        let state = random_token();
        let nonce = random_token();
        let pkce_verifier = random_token();

        let mut url = Url::parse(&self.meta.authorization_endpoint)
            .expect("authorization_endpoint was checked at discovery");
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("client_id", &self.client_id);
            q.append_pair("redirect_uri", &self.redirect_uri);
            q.append_pair("response_type", "code");
            q.append_pair("scope", &self.scope);
            q.append_pair("state", &state);
            q.append_pair("nonce", &nonce);
            q.append_pair("code_challenge", &pkce_challenge_s256(&pkce_verifier));
            q.append_pair("code_challenge_method", "S256");
        }

        OidcAuthorizeRequest {
            url: url.into(),
            state,
            nonce,
            pkce_verifier,
        }
    }

    pub async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: &str,
        nonce: &str,
    ) -> Result<(OidcIdentity, Map<String, Value>), OidcError> {
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("code_verifier", pkce_verifier),
        ];
        let response = safe_post_form(&self.http, &self.meta.token_endpoint, &form, &self.fetch)
            .await
            .map_err(|e| OidcError::TokenRequest(e.to_string()))?;
        if response.status != 200 {
            return Err(OidcError::TokenEndpoint {
                status: response.status,
                body: truncate(&String::from_utf8_lossy(&response.body)),
            });
        }
        let token: TokenResponse =
            serde_json::from_slice(&response.body).map_err(|e| OidcError::TokenEndpoint {
                status: response.status,
                body: e.to_string(),
            })?;
        let id_token = token.id_token.ok_or(OidcError::MissingIdToken)?;

        let header = decode_header(&id_token).map_err(|e| OidcError::IdToken(e.to_string()))?;
        let jwks = self.keys_for(header.kid.as_deref()).await?;
        let expectations = IdTokenExpectations {
            issuer: self.meta.issuer.trim_end_matches('/'),
            client_id: &self.client_id,
            nonce,
            algorithms: &self.algorithms,
        };
        let claims = validate_id_token(&id_token, &jwks, &expectations)?;
        Ok((identity_from_claims(&self.meta.issuer, &claims), claims))
    }

    async fn keys_for(&self, kid: Option<&str>) -> Result<JwkSet, OidcError> {
        if let Some(cached) = self.cached_keys(kid) {
            return Ok(cached);
        }
        let set = self.fetch_keys().await?;
        {
            let mut guard = self.jwks.lock().expect("jwks mutex poisoned");
            *guard = Some(CachedJwks {
                set: set.clone(),
                fetched_at: Instant::now(),
            });
        }
        match kid {
            Some(kid) if set.find(kid).is_none() => Err(OidcError::UnknownKey(kid.to_string())),
            _ => Ok(set),
        }
    }

    fn cached_keys(&self, kid: Option<&str>) -> Option<JwkSet> {
        let guard = self.jwks.lock().expect("jwks mutex poisoned");
        let cached = guard.as_ref()?;
        let serves_kid = kid.is_none_or(|k| cached.set.find(k).is_some());
        if serves_kid || cached.fetched_at.elapsed() < JWKS_MIN_REFRESH {
            return Some(cached.set.clone());
        }
        None
    }

    async fn fetch_keys(&self) -> Result<JwkSet, OidcError> {
        let response = safe_get(&self.http, &self.meta.jwks_uri, &self.fetch)
            .await
            .map_err(|e| OidcError::Jwks {
                issuer: self.meta.issuer.clone(),
                reason: e.to_string(),
            })?;
        if response.status != 200 {
            return Err(OidcError::Jwks {
                issuer: self.meta.issuer.clone(),
                reason: format!("status {}", response.status),
            });
        }
        serde_json::from_slice(&response.body).map_err(|e| OidcError::Jwks {
            issuer: self.meta.issuer.clone(),
            reason: e.to_string(),
        })
    }
}

fn truncate(body: &str) -> String {
    body.chars().take(ERROR_BODY_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_N: &str = "xwXx0Ona_0YJRMXIJjxa1gkGAx3hcRfHg5pw6iw7vOxt7f7eRmoe1vZEAZwqcL2LaD7VG2y0mlaQ4IuNQmNi8De5hxziRZWZY6NsvvUFOTeAC0xo8WFj2w4WdUv3cqYlXH1YzbpGM-jQ2UtrLPkUgLJUWFoYaX1vyUMOZ0TpUtG388JtvvfvSw4ifUchS9dkYagHOor_oEjxYRMnx7tviB-wbmyo6WfqsE9fKE7dUJCTF5SUS-a_KZzO8hAn4LuhtGwND8BECM8IrRhSz2uaBAAbl9vVuUYOTNsOW77empH0tEdmurcBGIi-mJjiTOADitMdt5KpSWVOqxQNqGeRKQ";
    const KEY_E: &str = "AQAB";
    const VALID_ID_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSIsImF1ZCI6ImZlcnJsYWJzLWNsaWVudCIsInN1YiI6Im9rdGEtdXNlci00MiIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzU4MDAwMDAwLCJub25jZSI6Im5vbmNlLWZyb20tdGhlLWxvZ2luLWF0dGVtcHQiLCJlbWFpbCI6ImRldkBhY21lLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYW1lIjoiRGV2IEFjbWUifQ.P-Xt3Pl1mqSLQ8cmuXC6WTd1-UNHkAlKDJ9loJrsBAKiGpRMP8J2xUp82uP1k4E-n5aL9uNmut3Aia_SdjFKE2DWNk_LXlcrc8R1IgaOsBMBR0mrmrnVZrAeYryNTPe2B6iMVzE4PSQy8nM5FGhc42nFseqWbdfRIKdYk__-D7-BRbIQACYhfHI8EEX1cmgd9ImCPaIYGHDx4vltEmrUDdwx-FrIVXdVtQ-_hRCv36XAfoaHFbWvuoJEsm4-cAE9ONql44pMnuDzQRjHv70E5t1cfhvvMYWI_Zauto-JApCCouCB2cA0GBgyJiwTsAJq5Q0kA8d4YZw2HO1bApI6tQ";
    const TOKEN_WITH_TWO_AUDIENCES: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSIsImF1ZCI6WyJmZXJybGFicy1jbGllbnQiLCJvdGhlci1jbGllbnQiXSwic3ViIjoib2t0YS11c2VyLTQyIiwiZXhwIjo0MTAyNDQ0ODAwLCJpYXQiOjE3NTgwMDAwMDAsIm5vbmNlIjoibm9uY2UtZnJvbS10aGUtbG9naW4tYXR0ZW1wdCIsImVtYWlsIjoiZGV2QGFjbWUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJEZXYgQWNtZSIsImF6cCI6ImZlcnJsYWJzLWNsaWVudCJ9.wuU0z7qwEVl_5nzL9RnZx1DlS5xTESXziq5dX3RjAhxjolSBo-wCuV5sys-vruGANVEu8Iz3dLCecCEZ6Pq_idEm6DigxM7zadm9yQemhLor0Ynxqy3uD-6VRhQA1wXCYcSSNmYJ_GIiyah9eSdxHYEVm4xsxjDU9qZULq4bwCCDO1qfFfzSTJNlNKLvZMw9jmSxIfcjqrmMRCEAl80cjNsgvblFKxKlMWtCJ-GQFcgplVSYPvU_VyXClFkOtz9XMaqhc3A_rx5htEAN_Lgdft26lLKjfEAd1-jhTDzWkrdeX_RkBIXoTwAiPxPleMIejRnten5QHpVlXZ4KxQgI4w";
    const TOKEN_WITH_TWO_AUDIENCES_NO_AZP: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSIsImF1ZCI6WyJmZXJybGFicy1jbGllbnQiLCJvdGhlci1jbGllbnQiXSwic3ViIjoib2t0YS11c2VyLTQyIiwiZXhwIjo0MTAyNDQ0ODAwLCJpYXQiOjE3NTgwMDAwMDAsIm5vbmNlIjoibm9uY2UtZnJvbS10aGUtbG9naW4tYXR0ZW1wdCIsImVtYWlsIjoiZGV2QGFjbWUuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJEZXYgQWNtZSJ9.mL75GTBNt27rO7Z1LBluJLUsK0n2WJTDMkvzH02Iesmz_B1sRsezPkyjqpBaOmwT-xCFamTYtc5k5QRGlZIbd6KRfkeOBVOzEI1t2_lySnM5LUNAv_kRQO4sPbMgIkRcYXcAnYY_S_uSeT-PrpViYzNS5X8uPl2ru1BwMtB-Gkfp2ZV45K-E6A61MNNv8I5PtNNVVI7Qs80ItBfo5UCRVyMwQCaKJwyNmyVEu-V50YPUPRgVszwXagZDaWzNR9rsq76BwbVmW_Th03OyPLRuiPgucrxtOqMu3l4z35GYZIs3AmKIAAJLLPEHUJaaLvmWAUpChI2b02J5QSnXaPF5Qg";
    const EXPIRED_ID_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSIsImF1ZCI6ImZlcnJsYWJzLWNsaWVudCIsInN1YiI6Im9rdGEtdXNlci00MiIsImV4cCI6MTc1ODAwMDA2MCwiaWF0IjoxNzU4MDAwMDAwLCJub25jZSI6Im5vbmNlLWZyb20tdGhlLWxvZ2luLWF0dGVtcHQiLCJlbWFpbCI6ImRldkBhY21lLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYW1lIjoiRGV2IEFjbWUifQ.NM-z5fS2aMmeHlqehcX1nmqMLxTf8A6AhNhLBo_LAifQSs-0_dSS3cDY5Si9HKEFQewCM9ZX5Ovaz4Z0A39FdfnD89baedUZb9BQAOADfa4HqGHE1QwrHY7ZLuSk3ptKUUd1XSb5Ws2X-8Az31PZto6Dcxk7eVJ-WnT_x2MIL83v7cgRzO_leZBnRV6vEYWg8Hv_fo_pwbcLCS1vsshLIqQPFx1d4sjZnfuzRew03ccxhHd3NfszUXGSNJJGyGd8eXLtH5k1-_rKMkemZVMNLBX4i0_SJsJgWqdVrj6H-NzV2faKRUnZP3DL58hrlo0OdMuOOjB32U1RUaPdaNVO0g";
    const TOKEN_FROM_ANOTHER_ISSUER: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJodHRwczovL2V2aWwuZXhhbXBsZS5jb20iLCJhdWQiOiJmZXJybGFicy1jbGllbnQiLCJzdWIiOiJva3RhLXVzZXItNDIiLCJleHAiOjQxMDI0NDQ4MDAsImlhdCI6MTc1ODAwMDAwMCwibm9uY2UiOiJub25jZS1mcm9tLXRoZS1sb2dpbi1hdHRlbXB0IiwiZW1haWwiOiJkZXZAYWNtZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkRldiBBY21lIn0.cAludbzmc4N2lBmC6vgHRo_6TSuDOteA3uVF7s1-539D4o9hSOblGIfPxJu_ZEXYvs58nSs4qC1wG1Oh3RJvoGWMS_I118E6bLOxer7YzKxvwavzCQuxtzB7_CJyNJCPb6EN7oyTD4sczIK3rAt6lZWZyTdRZDbSmGaE1mZCJf81O12Sd2643xUmpT88lTxGH9xYAZihVEVLfgE0vYTIORFb4Nmo1BC3ukiBFCYsl15WijSRP73HZZkmxn-U1-JvNNBQwKKeOT8l3jBEdXHgXWQPdf3H5QhpwdQn51OXe4BZc39pVbzjQchAGia-E2gXSfvC_bk6qLX4lX919SxhHQ";
    const TOKEN_WITH_EMPTY_SUB: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSIsImF1ZCI6ImZlcnJsYWJzLWNsaWVudCIsInN1YiI6IiIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzU4MDAwMDAwLCJub25jZSI6Im5vbmNlLWZyb20tdGhlLWxvZ2luLWF0dGVtcHQiLCJlbWFpbCI6ImRldkBhY21lLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYW1lIjoiRGV2IEFjbWUifQ.DGJS5QbwD57k2Zo2WnWPwgcpJ25uLpGmwJFKM0L_593u4Yt_p3slNq7SRcc0gFnpwEVnA0BKB7ho8-yrh0O-YUcp-JwMUoyHo6bPuqfrO41-V3KaAt6PHUyiWnV5xsTaFBtDeSIvSrx0g2L7p82CPs5nWaDUxxqJwyUMRsk-_Pd7ujBqI95wyT478wjCk6NLrwzitNgVbi-nnw_zV7QBFnF8XczbjzOeVJ_xTh0knxwtXrbAGzMje47uGdNVoGNiF8LLLBFFL05XJBJI0ZFzo8XfuNXblHLki1otCQ_YJkd1r70XL86qX-t_K2IqcQxSOpK63mQCV-XjlIaWbcWBxA";
    const TOKEN_WITH_NUMERIC_SUB: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSIsImF1ZCI6ImZlcnJsYWJzLWNsaWVudCIsInN1YiI6NDIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzU4MDAwMDAwLCJub25jZSI6Im5vbmNlLWZyb20tdGhlLWxvZ2luLWF0dGVtcHQiLCJlbWFpbCI6ImRldkBhY21lLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYW1lIjoiRGV2IEFjbWUifQ.nDivX4Ey-7oi2uq8o7RvKK7LPQMYWTAEgb4UQYdNysET8LCkGyrJQ11BHw3CuV9QINJG-ZWOOi7KVy7lDT31hXGjLuxghoJJVHfY88iL4zPWpS5T3O7FLwIrT-iemXw-l-DeaMcVJDdF8SHdFsvgKuI0sD4HME4dyoQhtLP_2n06bZQTr38kyK9SIXvDN9g5EviURXWc9DLO2PT6MkK4cFUk1eawoWeUplB8tIpg9DVgmzGWf5dTS8BIwlsuf8U4AzmX0enue2N8bAkqQ8A2tBbU5Ge6-9lNg0PT2FzgdcGWvLn7RnklCNyuOHMxJuCtGRQD0UeF9BWIY46npYFJUA";
    const TOKEN_WITH_UNKNOWN_KID: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InJvdGF0ZWQtYXdheSJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSIsImF1ZCI6ImZlcnJsYWJzLWNsaWVudCIsInN1YiI6Im9rdGEtdXNlci00MiIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzU4MDAwMDAwLCJub25jZSI6Im5vbmNlLWZyb20tdGhlLWxvZ2luLWF0dGVtcHQiLCJlbWFpbCI6ImRldkBhY21lLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYW1lIjoiRGV2IEFjbWUifQ.V0XBwe4_YU4GfFh0wcCO_hWBd2UXoAX9Ja_eouMZz-1HbiupIPtrqVZ15UTmpboqfyCxFcZA1Hh6WlKTUdYW9LOX7z4wgoOZP56v5gEddvaoUMpNH7A0paPuZsGusVtmx5pIlYbJ2LzrXAZAcgQ6f2754VxklW8jIj1e6zNOMEy7XgmyciRuPSLb2YPx8b7DD2SogwLVjvjAzkoJoQ_-d29y2K-uuQXXMbPwSOvA92mUQ_FwOqKw0TLD-4yOoFwPMo_ksPpQ5CFtFh4pp2KBBDiXkC17A_AuJIZ5hgtvrE4q2MuXrpQnz64P4BXb2-V5uFa1OpD7nIiUS-2rM_0bnQ";

    fn jwks(kid: &str) -> JwkSet {
        serde_json::from_value(serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": KEY_N,
                "e": KEY_E,
            }]
        }))
        .expect("test jwks is valid")
    }

    fn metadata(algs: &[&str]) -> IssuerMetadata {
        IssuerMetadata {
            issuer: "https://idp.example.com".to_string(),
            authorization_endpoint: "https://idp.example.com/authorize".to_string(),
            token_endpoint: "https://idp.example.com/token".to_string(),
            jwks_uri: "https://idp.example.com/jwks".to_string(),
            id_token_signing_alg_values_supported: algs.iter().map(ToString::to_string).collect(),
        }
    }

    fn expectations(algorithms: &[Algorithm]) -> IdTokenExpectations<'_> {
        IdTokenExpectations {
            issuer: "https://idp.example.com",
            client_id: "ferrlabs-client",
            nonce: "nonce-from-the-login-attempt",
            algorithms,
        }
    }

    #[test]
    fn an_issuer_keeps_its_identity_whether_or_not_it_ends_in_a_slash() {
        for raw in [
            "https://idp.example.com",
            "https://idp.example.com/",
            "  https://idp.example.com  ",
        ] {
            let normalized = normalize_issuer(raw).unwrap_or_else(|e| panic!("{raw:?}: {e}"));
            assert_eq!(normalized, "https://idp.example.com", "{raw:?}");
        }
        assert_eq!(
            normalize_issuer("https://idp.example.com/tenant/9").unwrap(),
            "https://idp.example.com/tenant/9"
        );
    }

    #[test]
    fn an_issuer_that_is_not_plain_https_is_refused() {
        for raw in [
            "http://idp.example.com",
            "https://idp.example.com?tenant=9",
            "https://idp.example.com#frag",
            "idp.example.com",
            "file:///etc/passwd",
        ] {
            assert!(normalize_issuer(raw).is_err(), "{raw:?}");
        }
    }

    #[test]
    fn discovery_hangs_the_well_known_path_off_the_issuer() {
        assert_eq!(
            discovery_url("https://idp.example.com/tenant/9"),
            "https://idp.example.com/tenant/9/.well-known/openid-configuration"
        );
    }

    #[test]
    fn a_document_claiming_another_issuer_is_refused() {
        let mut meta = metadata(&["RS256"]);
        meta.issuer = "https://evil.example.com".to_string();
        assert!(matches!(
            check_metadata("https://idp.example.com", &meta),
            Err(OidcError::IssuerMismatch { .. })
        ));

        let mut trailing = metadata(&["RS256"]);
        trailing.issuer = "https://idp.example.com/".to_string();
        assert!(check_metadata("https://idp.example.com", &trailing).is_ok());
    }

    #[test]
    fn endpoints_must_be_https() {
        let cases = [
            ("authorization_endpoint", "http://idp.example.com/authorize"),
            ("token_endpoint", "http://idp.example.com/token"),
            ("jwks_uri", "not-a-url"),
        ];
        for (name, value) in cases {
            let mut meta = metadata(&["RS256"]);
            match name {
                "authorization_endpoint" => meta.authorization_endpoint = value.to_string(),
                "token_endpoint" => meta.token_endpoint = value.to_string(),
                _ => meta.jwks_uri = value.to_string(),
            }
            assert!(
                matches!(
                    check_metadata("https://idp.example.com", &meta),
                    Err(OidcError::Endpoint { .. })
                ),
                "{name} accepted {value}"
            );
        }
    }

    #[test]
    fn an_issuer_that_advertises_nothing_gets_the_algorithm_the_spec_requires() {
        assert_eq!(
            signing_algorithms(&metadata(&[])).unwrap(),
            vec![Algorithm::RS256]
        );
    }

    #[test]
    fn unknown_and_symmetric_algorithms_are_dropped() {
        assert_eq!(
            signing_algorithms(&metadata(&["RS256", "ES256", "PS999"])).unwrap(),
            vec![Algorithm::RS256, Algorithm::ES256]
        );
        for advertised in [vec!["HS256"], vec!["none"], vec!["HS512", "PS999"]] {
            assert!(
                matches!(
                    signing_algorithms(&metadata(&advertised)),
                    Err(OidcError::NoUsableAlgorithm)
                ),
                "{advertised:?} was accepted"
            );
        }
    }

    #[test]
    fn a_valid_id_token_yields_its_claims() {
        let algs = [Algorithm::RS256];
        let claims =
            validate_id_token(VALID_ID_TOKEN, &jwks("test-key"), &expectations(&algs)).unwrap();
        let identity = identity_from_claims("https://idp.example.com", &claims);
        assert_eq!(identity.subject, "okta-user-42");
        assert_eq!(identity.email.as_deref(), Some("dev@acme.com"));
        assert!(identity.email_verified);
        assert_eq!(identity.name.as_deref(), Some("Dev Acme"));
    }

    #[test]
    fn a_tampered_signature_is_refused() {
        let mut tampered = VALID_ID_TOKEN.to_string();
        let last = tampered.pop().expect("token is not empty");
        tampered.push(if last == 'a' { 'b' } else { 'a' });
        let algs = [Algorithm::RS256];
        assert!(matches!(
            validate_id_token(&tampered, &jwks("test-key"), &expectations(&algs)),
            Err(OidcError::IdToken(_))
        ));
    }

    #[test]
    fn a_token_for_another_issuer_or_past_its_expiry_is_refused() {
        let algs = [Algorithm::RS256];
        for token in [TOKEN_FROM_ANOTHER_ISSUER, EXPIRED_ID_TOKEN] {
            assert!(
                matches!(
                    validate_id_token(token, &jwks("test-key"), &expectations(&algs)),
                    Err(OidcError::IdToken(_))
                ),
                "accepted {token}"
            );
        }
    }

    #[test]
    fn a_replayed_token_from_another_login_attempt_is_refused() {
        let algs = [Algorithm::RS256];
        let other_attempt = IdTokenExpectations {
            nonce: "nonce-from-a-different-attempt",
            ..expectations(&algs)
        };
        assert!(matches!(
            validate_id_token(VALID_ID_TOKEN, &jwks("test-key"), &other_attempt),
            Err(OidcError::NonceMismatch)
        ));
    }

    #[test]
    fn a_token_for_a_different_client_is_refused() {
        let algs = [Algorithm::RS256];
        let other_client = IdTokenExpectations {
            client_id: "someone-elses-client",
            ..expectations(&algs)
        };
        assert!(matches!(
            validate_id_token(VALID_ID_TOKEN, &jwks("test-key"), &other_client),
            Err(OidcError::IdToken(_))
        ));
    }

    #[test]
    fn several_audiences_need_an_azp_naming_this_client() {
        let algs = [Algorithm::RS256];
        assert!(
            validate_id_token(
                TOKEN_WITH_TWO_AUDIENCES,
                &jwks("test-key"),
                &expectations(&algs)
            )
            .is_ok()
        );
        assert!(matches!(
            validate_id_token(
                TOKEN_WITH_TWO_AUDIENCES_NO_AZP,
                &jwks("test-key"),
                &expectations(&algs)
            ),
            Err(OidcError::AzpMismatch)
        ));
    }

    #[test]
    fn a_token_signed_with_an_unadvertised_algorithm_is_refused() {
        let algs = [Algorithm::ES256];
        assert!(matches!(
            validate_id_token(VALID_ID_TOKEN, &jwks("test-key"), &expectations(&algs)),
            Err(OidcError::UnexpectedAlgorithm(_))
        ));
    }

    #[test]
    fn a_token_naming_a_key_the_issuer_no_longer_publishes_is_refused() {
        let algs = [Algorithm::RS256];
        assert!(matches!(
            validate_id_token(
                TOKEN_WITH_UNKNOWN_KID,
                &jwks("test-key"),
                &expectations(&algs)
            ),
            Err(OidcError::UnknownKey(_))
        ));
    }

    #[test]
    fn a_token_without_a_usable_subject_is_refused() {
        let algs = [Algorithm::RS256];
        for token in [TOKEN_WITH_EMPTY_SUB, TOKEN_WITH_NUMERIC_SUB] {
            assert!(
                matches!(
                    validate_id_token(token, &jwks("test-key"), &expectations(&algs)),
                    Err(OidcError::IdToken(_))
                ),
                "an account would be linked to an empty subject: {token}"
            );
        }
    }

    #[test]
    fn a_rotated_key_is_refetched_once_the_refresh_window_has_passed() {
        let client = OidcClient::new(
            metadata(&["RS256"]),
            "ferrlabs-client",
            "secret",
            "https://auth.ferrlabs.com/sso/callback",
            None,
        )
        .unwrap();

        let seed = |age: Duration| {
            *client.jwks.lock().unwrap() = Some(CachedJwks {
                set: jwks("test-key"),
                fetched_at: Instant::now()
                    .checked_sub(age)
                    .expect("the test clock is past the epoch"),
            });
        };

        seed(Duration::from_secs(0));
        assert!(client.cached_keys(Some("test-key")).is_some());
        assert!(
            client.cached_keys(Some("rotated-away")).is_some(),
            "a fresh cache must serve an unknown kid rather than hammering the issuer"
        );

        seed(JWKS_MIN_REFRESH * 2);
        assert!(client.cached_keys(Some("test-key")).is_some());
        assert!(
            client.cached_keys(Some("rotated-away")).is_none(),
            "past the refresh window an unknown kid must trigger a refetch"
        );
    }

    #[test]
    fn the_authorize_url_carries_a_fresh_state_nonce_and_pkce_challenge() {
        let client = OidcClient::new(
            metadata(&["RS256"]),
            "ferrlabs-client",
            "secret",
            "https://auth.ferrlabs.com/sso/callback",
            None,
        )
        .unwrap();
        let first = client.authorize();
        let second = client.authorize();

        assert_ne!(first.state, second.state);
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.pkce_verifier, second.pkce_verifier);
        assert_ne!(first.state, first.nonce);

        let url = Url::parse(&first.url).unwrap();
        let query: std::collections::HashMap<_, _> = url.query_pairs().collect();
        assert_eq!(query["client_id"].as_ref(), "ferrlabs-client");
        assert_eq!(query["response_type"].as_ref(), "code");
        assert_eq!(query["scope"].as_ref(), "openid email profile");
        assert_eq!(query["state"].as_ref(), first.state.as_str());
        assert_eq!(query["nonce"].as_ref(), first.nonce.as_str());
        assert_eq!(query["code_challenge_method"].as_ref(), "S256");
        assert_eq!(
            query["code_challenge"].as_ref(),
            pkce_challenge_s256(&first.pkce_verifier).as_str()
        );
        assert!(!first.url.contains(&first.pkce_verifier));
    }

    #[test]
    fn a_client_is_refused_when_no_algorithm_can_be_used() {
        assert!(matches!(
            OidcClient::new(metadata(&["HS256"]), "id", "secret", "https://x/cb", None),
            Err(OidcError::NoUsableAlgorithm)
        ));
    }
}
