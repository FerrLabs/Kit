use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{AppState, error::ApiError};

type HmacSha256 = Hmac<Sha256>;

const MAX_TIMESTAMP_DRIFT_SECS: u64 = 300;

pub async fn verify_hmac(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let (parts, body) = request.into_parts();

    let signature = parts
        .headers
        .get("X-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::Unauthorized)?;

    let timestamp_str = parts
        .headers
        .get("X-Timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::Unauthorized)?;

    let timestamp: u64 = timestamp_str.parse().map_err(|_| ApiError::Unauthorized)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if now.abs_diff(timestamp) > MAX_TIMESTAMP_DRIFT_SECS {
        return Err(ApiError::Unauthorized);
    }

    let body_bytes = axum::body::to_bytes(body, 1024 * 16)
        .await
        .map_err(|_| ApiError::BadRequest("Invalid body".into()))?;

    let body_str = std::str::from_utf8(&body_bytes)
        .map_err(|_| ApiError::BadRequest("Invalid UTF-8".into()))?;

    let message = format!("{timestamp_str}.{body_str}");

    let mut mac = HmacSha256::new_from_slice(state.hmac_secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(message.as_bytes());

    let provided = hex::decode(signature).map_err(|_| ApiError::Unauthorized)?;
    mac.verify_slice(&provided)
        .map_err(|_| ApiError::Unauthorized)?;

    let request = Request::from_parts(parts, axum::body::Body::from(body_bytes));
    Ok(next.run(request).await)
}
