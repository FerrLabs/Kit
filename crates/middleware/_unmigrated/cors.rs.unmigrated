use crate::config::ServerConfig;
use axum::http::header;
use tower_http::cors::CorsLayer;

pub fn create_cors_layer(config: &ServerConfig) -> CorsLayer {
    CorsLayer::new()
        .allow_origin(
            config
                .allowed_origins
                .iter()
                .map(|origin| origin.parse().expect("Invalid origin"))
                .collect::<Vec<_>>(),
        )
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::PATCH,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::ACCEPT,
            header::HeaderName::from_static("x-signature"),
            header::HeaderName::from_static("x-timestamp"),
        ])
        .allow_credentials(true)
        .max_age(std::time::Duration::from_secs(3600))
}
