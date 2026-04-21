use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;

use crate::error_code;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Internal server error: {0}")]
    Internal(#[from] anyhow::Error),

    /// Client error with an explicit code + status + message. Use this for any
    /// 4xx that callers may want to branch on. Prefer the helper constructors
    /// (`ApiError::not_found`, `ApiError::bad_request`, …) so the status stays
    /// canonical per family.
    #[error("{message}")]
    Coded {
        code: &'static str,
        status: StatusCode,
        message: String,
    },

    // Legacy catch-alls. Prefer `Coded` (or the helpers) for new code paths —
    // these keep working so unmigrated call-sites don't have to change in
    // lockstep with this refactor.
    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Plan limit exceeded: {0}")]
    PlanLimitExceeded(String),

    #[error("Gone: {0}")]
    Gone(String),

    #[error("Email not verified")]
    EmailNotVerified,
}

impl ApiError {
    /// Generic coded error — pick the status yourself.
    pub fn coded(code: &'static str, status: StatusCode, message: impl Into<String>) -> Self {
        ApiError::Coded {
            code,
            status,
            message: message.into(),
        }
    }

    /// 404 with a domain code (e.g. `ORG_NOT_FOUND`).
    pub fn not_found(code: &'static str, message: impl Into<String>) -> Self {
        ApiError::Coded {
            code,
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    /// 400 with a domain code.
    pub fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        ApiError::Coded {
            code,
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    /// 403 with a domain code.
    pub fn forbidden(code: &'static str, message: impl Into<String>) -> Self {
        ApiError::Coded {
            code,
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }

    /// 409 with a domain code — the typical shape for "already exists".
    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        ApiError::Coded {
            code,
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }

    /// 410 with a domain code.
    pub fn gone(code: &'static str, message: impl Into<String>) -> Self {
        ApiError::Coded {
            code,
            status: StatusCode::GONE,
            message: message.into(),
        }
    }

    /// Resolve (status, code, message) for an error — used by `IntoResponse`
    /// and the tests in this module. The message is borrowed from `self` so
    /// moving the error isn't required for inspection in tests.
    fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            ApiError::Database(e) => {
                tracing::error!("Database error: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error_code::INTERNAL_DATABASE,
                    "Database error occurred".to_string(),
                )
            }
            ApiError::Internal(e) => {
                tracing::error!("Internal error: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error_code::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
            ApiError::Coded {
                code,
                status,
                message,
            } => (*status, *code, message.clone()),
            ApiError::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                error_code::BAD_REQUEST,
                msg.clone(),
            ),
            ApiError::Validation(msg) => (
                StatusCode::BAD_REQUEST,
                error_code::VALIDATION_FAILED,
                msg.clone(),
            ),
            ApiError::RateLimitExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                error_code::RATE_LIMIT_EXCEEDED,
                "Rate limit exceeded".to_string(),
            ),
            ApiError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                error_code::AUTH_UNAUTHORIZED,
                "Unauthorized".to_string(),
            ),
            ApiError::Forbidden(msg) => (
                StatusCode::FORBIDDEN,
                error_code::AUTH_FORBIDDEN,
                msg.clone(),
            ),
            // Call sites that still use the legacy `NotFound` variant have not
            // been migrated to a domain code. Default to BAD_REQUEST per the
            // design notes — a follow-up should push each remaining site onto
            // `ApiError::not_found(DOMAIN_CODE, ..)`.
            ApiError::NotFound(msg) => {
                (StatusCode::NOT_FOUND, error_code::BAD_REQUEST, msg.clone())
            }
            ApiError::PlanLimitExceeded(msg) => (
                StatusCode::FORBIDDEN,
                error_code::PLAN_LIMIT_EXCEEDED,
                msg.clone(),
            ),
            ApiError::Gone(msg) => (StatusCode::GONE, error_code::GONE, msg.clone()),
            ApiError::EmailNotVerified => (
                StatusCode::FORBIDDEN,
                error_code::AUTH_EMAIL_NOT_VERIFIED,
                "email_not_verified".to_string(),
            ),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = self.parts();
        let body = Json(json!({
            "code": code,
            "error": message,
        }));
        (status, body).into_response()
    }
}

impl From<validator::ValidationErrors> for ApiError {
    fn from(err: validator::ValidationErrors) -> Self {
        ApiError::Validation(err.to_string())
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

#[cfg(test)]
mod tests {
    use super::*;

    fn check(err: ApiError, expected_status: StatusCode, expected_code: &str) {
        let (status, code, _) = err.parts();
        assert_eq!(status, expected_status, "status mismatch for {code}");
        assert_eq!(code, expected_code);
    }

    #[test]
    fn database_error_maps_to_internal_database() {
        check(
            ApiError::Database(sqlx::Error::PoolClosed),
            StatusCode::INTERNAL_SERVER_ERROR,
            error_code::INTERNAL_DATABASE,
        );
    }

    #[test]
    fn internal_error_maps_to_internal_server_error() {
        check(
            ApiError::Internal(anyhow::anyhow!("boom")),
            StatusCode::INTERNAL_SERVER_ERROR,
            error_code::INTERNAL_SERVER_ERROR,
        );
    }

    #[test]
    fn bad_request_default_code() {
        check(
            ApiError::BadRequest("nope".into()),
            StatusCode::BAD_REQUEST,
            error_code::BAD_REQUEST,
        );
    }

    #[test]
    fn validation_default_code() {
        check(
            ApiError::Validation("bad".into()),
            StatusCode::BAD_REQUEST,
            error_code::VALIDATION_FAILED,
        );
    }

    #[test]
    fn rate_limit_exceeded_code() {
        check(
            ApiError::RateLimitExceeded,
            StatusCode::TOO_MANY_REQUESTS,
            error_code::RATE_LIMIT_EXCEEDED,
        );
    }

    #[test]
    fn unauthorized_code() {
        check(
            ApiError::Unauthorized,
            StatusCode::UNAUTHORIZED,
            error_code::AUTH_UNAUTHORIZED,
        );
    }

    #[test]
    fn forbidden_code() {
        check(
            ApiError::Forbidden("no".into()),
            StatusCode::FORBIDDEN,
            error_code::AUTH_FORBIDDEN,
        );
    }

    #[test]
    fn not_found_legacy_code() {
        check(
            ApiError::NotFound("x".into()),
            StatusCode::NOT_FOUND,
            error_code::BAD_REQUEST,
        );
    }

    #[test]
    fn plan_limit_exceeded_code() {
        check(
            ApiError::PlanLimitExceeded("plan".into()),
            StatusCode::FORBIDDEN,
            error_code::PLAN_LIMIT_EXCEEDED,
        );
    }

    #[test]
    fn gone_code() {
        check(
            ApiError::Gone("expired".into()),
            StatusCode::GONE,
            error_code::GONE,
        );
    }

    #[test]
    fn email_not_verified_code() {
        check(
            ApiError::EmailNotVerified,
            StatusCode::FORBIDDEN,
            error_code::AUTH_EMAIL_NOT_VERIFIED,
        );
    }

    #[test]
    fn coded_helper_preserves_code_and_status() {
        check(
            ApiError::not_found(error_code::ORG_NOT_FOUND, "nope"),
            StatusCode::NOT_FOUND,
            error_code::ORG_NOT_FOUND,
        );
        check(
            ApiError::bad_request(error_code::USER_EMAIL_TAKEN, "taken"),
            StatusCode::BAD_REQUEST,
            error_code::USER_EMAIL_TAKEN,
        );
        check(
            ApiError::forbidden(error_code::ADMIN_STAFF_ONLY, "staff"),
            StatusCode::FORBIDDEN,
            error_code::ADMIN_STAFF_ONLY,
        );
        check(
            ApiError::conflict(error_code::CLUSTER_NAME_TAKEN, "dup"),
            StatusCode::CONFLICT,
            error_code::CLUSTER_NAME_TAKEN,
        );
        check(
            ApiError::gone(error_code::AUTH_VERIFICATION_CODE_EXPIRED, "expired"),
            StatusCode::GONE,
            error_code::AUTH_VERIFICATION_CODE_EXPIRED,
        );
    }
}
