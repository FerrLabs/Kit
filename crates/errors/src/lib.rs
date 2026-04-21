//! Common error types for FerrLabs APIs.
//!
//! Every FerrLabs Rust backend converts its errors through [`ApiError`] so
//! responses have a consistent shape (JSON body, stable error codes, no leaked
//! internals).

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

/// Top-level API error. Wraps internal errors with a stable code and
/// user-safe message.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("not found")]
    NotFound,

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden")]
    Forbidden,

    #[error("validation failed: {0}")]
    Validation(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("rate limit exceeded")]
    RateLimit,

    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Debug, Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::Validation(_) => (StatusCode::UNPROCESSABLE_ENTITY, "validation_failed"),
            Self::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            Self::RateLimit => (StatusCode::TOO_MANY_REQUESTS, "rate_limit"),
            Self::Internal(err) => {
                tracing::error!(error = %err, "internal server error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
            }
        };

        let message = match &self {
            // Don't leak internal error details to clients.
            Self::Internal(_) => "An internal error occurred".to_string(),
            other => other.to_string(),
        };

        let body = ErrorBody {
            error: ErrorDetail { code, message },
        };

        (status, Json(body)).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
