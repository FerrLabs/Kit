//! Axum extractor that pulls the authenticated user from a request.
//!
//! ```ignore
//! async fn handler(auth: AuthUser) -> ApiResult<Json<Profile>> {
//!     // auth.user_id is guaranteed non-null; middleware rejects otherwise.
//! }
//! ```
//!
//! The extractor verifies a `Bearer` JWT against the [`JwtConfig`] held in
//! the application state. Any app whose state can hand out a `JwtConfig`
//! (via [`FromRef`]) gets the extractor for free.

use std::future::{Future, ready};

use axum::extract::{FromRef, FromRequestParts};
use ferrlabs_errors::ApiError;
use http::header::AUTHORIZATION;
use http::request::Parts;
use uuid::Uuid;

use crate::jwt::{JwtConfig, verify_token};

pub struct AuthUser {
    pub user_id: Uuid,
    pub active_org: Option<Uuid>,
}

impl AuthUser {
    /// Return the active organization, or [`ApiError::Unauthorized`] if the
    /// caller is not acting on behalf of one.
    ///
    /// # Errors
    /// [`ApiError::Unauthorized`] when no active org is present on the token.
    pub fn require_org(&self) -> Result<Uuid, ApiError> {
        self.active_org.ok_or(ApiError::Unauthorized)
    }
}

fn bearer_token(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

impl AuthUser {
    fn extract<S>(parts: &mut Parts, state: &S) -> Result<Self, ApiError>
    where
        JwtConfig: FromRef<S>,
    {
        let token = bearer_token(parts).ok_or(ApiError::Unauthorized)?;
        let config = JwtConfig::from_ref(state);
        let claims = verify_token(&config, token).map_err(|_| ApiError::Unauthorized)?;

        Ok(AuthUser {
            user_id: claims.sub,
            active_org: claims.org,
        })
    }
}

impl<S> FromRequestParts<S> for AuthUser
where
    JwtConfig: FromRef<S>,
    S: Sync,
{
    type Rejection = ApiError;

    fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> {
        ready(Self::extract(parts, state))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use ed25519_dalek::pkcs8::spki::EncodePublicKey;
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
    use http::Request;

    use super::*;
    use crate::jwt::{DEFAULT_ACCESS_TTL, issue_token};

    #[derive(Clone)]
    struct TestState {
        jwt: JwtConfig,
    }

    impl FromRef<TestState> for JwtConfig {
        fn from_ref(state: &TestState) -> Self {
            state.jwt.clone()
        }
    }

    fn state_with_ttl(ttl: Duration) -> TestState {
        let seed: [u8; 32] = rand::random();
        let signing = SigningKey::from_bytes(&seed);
        let private_pem = signing.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let public_pem = signing
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let jwt = JwtConfig::from_ed25519_pems(
            private_pem.as_bytes(),
            public_pem.as_bytes(),
            "ferrlabs-test",
            ttl,
        )
        .unwrap();
        TestState { jwt }
    }

    fn test_state() -> TestState {
        state_with_ttl(DEFAULT_ACCESS_TTL)
    }

    fn parts_with_auth(value: Option<&str>) -> Parts {
        let mut builder = Request::builder();
        if let Some(v) = value {
            builder = builder.header(AUTHORIZATION, v);
        }
        builder.body(()).unwrap().into_parts().0
    }

    #[tokio::test]
    async fn extracts_user_and_org_from_valid_bearer_token() {
        let state = test_state();
        let user_id = Uuid::new_v4();
        let org_id = Uuid::new_v4();
        let token = issue_token(&state.jwt, user_id, Some(org_id)).unwrap();

        let mut parts = parts_with_auth(Some(&format!("Bearer {token}")));
        let auth = AuthUser::from_request_parts(&mut parts, &state)
            .await
            .expect("valid token should extract");

        assert_eq!(auth.user_id, user_id);
        assert_eq!(auth.active_org, Some(org_id));
    }

    #[tokio::test]
    async fn rejects_missing_header() {
        let state = test_state();
        let mut parts = parts_with_auth(None);
        assert!(matches!(
            AuthUser::from_request_parts(&mut parts, &state).await,
            Err(ApiError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn rejects_non_bearer_scheme() {
        let state = test_state();
        let mut parts = parts_with_auth(Some("Basic dXNlcjpwYXNz"));
        assert!(matches!(
            AuthUser::from_request_parts(&mut parts, &state).await,
            Err(ApiError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn rejects_token_signed_by_a_different_key() {
        let signer = test_state();
        let verifier = test_state();
        let token = issue_token(&signer.jwt, Uuid::new_v4(), None).unwrap();

        let mut parts = parts_with_auth(Some(&format!("Bearer {token}")));
        assert!(matches!(
            AuthUser::from_request_parts(&mut parts, &verifier).await,
            Err(ApiError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn rejects_expired_token() {
        let state = state_with_ttl(Duration::from_secs(0));
        let token = issue_token(&state.jwt, Uuid::new_v4(), None).unwrap();
        std::thread::sleep(Duration::from_millis(1100));

        let mut parts = parts_with_auth(Some(&format!("Bearer {token}")));
        assert!(matches!(
            AuthUser::from_request_parts(&mut parts, &state).await,
            Err(ApiError::Unauthorized)
        ));
    }

    #[test]
    fn require_org_returns_present_org() {
        let org = Uuid::new_v4();
        let auth = AuthUser {
            user_id: Uuid::new_v4(),
            active_org: Some(org),
        };
        assert_eq!(auth.require_org().unwrap(), org);
    }

    #[test]
    fn require_org_rejects_when_absent() {
        let auth = AuthUser {
            user_id: Uuid::new_v4(),
            active_org: None,
        };
        assert!(matches!(auth.require_org(), Err(ApiError::Unauthorized)));
    }
}
