//! CORS layer for `FerrLabs` APIs.
//!
//! Decoupled from any app state: build a [`CorsConfig`] from the API's own
//! configuration (allowed origins, whether credentials are permitted) and
//! turn it into a [`CorsLayer`] with [`cors_layer`].

use std::time::Duration;

use http::{HeaderValue, Method, header};
use tower_http::cors::{AllowOrigin, CorsLayer};

const PREFLIGHT_MAX_AGE: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone)]
pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
    pub allow_credentials: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum CorsError {
    #[error("invalid CORS origin {origin:?}: {source}")]
    InvalidOrigin {
        origin: String,
        source: http::header::InvalidHeaderValue,
    },
    #[error("wildcard origin `*` cannot be combined with allow_credentials")]
    WildcardWithCredentials,
}

/// Build a [`CorsLayer`] from a [`CorsConfig`].
///
/// Allows the standard verbs plus the headers FerrLabs APIs accept
/// (`content-type`, `authorization`, `accept`, and the HMAC webhook headers
/// `x-signature` / `x-timestamp`). Preflight responses are cached for one
/// hour.
///
/// # Errors
/// - [`CorsError::InvalidOrigin`] if any configured origin is not a valid
///   header value.
/// - [`CorsError::WildcardWithCredentials`] if `*` is configured together
///   with `allow_credentials`, which the CORS spec forbids.
pub fn cors_layer(config: &CorsConfig) -> Result<CorsLayer, CorsError> {
    if config.allow_credentials && config.allowed_origins.iter().any(|o| o == "*") {
        return Err(CorsError::WildcardWithCredentials);
    }

    let origins = config
        .allowed_origins
        .iter()
        .map(|origin| {
            origin
                .parse::<HeaderValue>()
                .map_err(|source| CorsError::InvalidOrigin {
                    origin: origin.clone(),
                    source,
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::ACCEPT,
            header::HeaderName::from_static("x-signature"),
            header::HeaderName::from_static("x-timestamp"),
        ])
        .allow_credentials(config.allow_credentials)
        .max_age(PREFLIGHT_MAX_AGE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_layer_for_valid_origins() {
        let config = CorsConfig {
            allowed_origins: vec![
                "https://app.ferrlabs.com".to_owned(),
                "https://ferrvault.com".to_owned(),
            ],
            allow_credentials: true,
        };
        assert!(cors_layer(&config).is_ok());
    }

    #[test]
    fn rejects_invalid_origin() {
        let config = CorsConfig {
            allowed_origins: vec!["not a header value\n".to_owned()],
            allow_credentials: false,
        };
        match cors_layer(&config) {
            Err(CorsError::InvalidOrigin { origin, .. }) => {
                assert_eq!(origin, "not a header value\n");
            }
            other => panic!("expected InvalidOrigin, got {other:?}"),
        }
    }

    #[test]
    fn rejects_wildcard_with_credentials() {
        let config = CorsConfig {
            allowed_origins: vec!["*".to_owned()],
            allow_credentials: true,
        };
        assert!(matches!(
            cors_layer(&config),
            Err(CorsError::WildcardWithCredentials)
        ));
    }
}
