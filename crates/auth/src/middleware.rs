//! Axum extractor that pulls the authenticated user from a request.
//!
//! ```ignore
//! async fn handler(auth: AuthUser) -> ApiResult<Json<Profile>> {
//!     // auth.user_id is guaranteed non-null; middleware rejects otherwise.
//! }
//! ```

use ferrlabs_errors::ApiError;
use uuid::Uuid;

pub struct AuthUser {
    pub user_id: Uuid,
    pub active_org: Option<Uuid>,
}

// TODO: FromRequestParts impl that pulls the Authorization header, verifies the JWT,
// and populates AuthUser. Returns ApiError::Unauthorized on any failure.

impl AuthUser {
    pub fn require_org(&self) -> Result<Uuid, ApiError> {
        self.active_org.ok_or(ApiError::Unauthorized)
    }
}
