//! PostgreSQL connection pool and helpers for FerrLabs APIs.
//!
//! Provides a shared `sqlx::PgPool` setup and a `Tx` type alias for
//! transaction-scoped queries. Per-product migrations live in each Cloud
//! repo; the shared `users` / `organizations` / `billing_*` tables are
//! owned by the migrations shipped under `ferrlabs-db` itself.

use anyhow::Context;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;

/// Type alias for a transaction on the shared FerrLabs Postgres pool.
pub type Tx<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

/// Configuration for the shared Postgres pool.
#[derive(Debug, Clone)]
pub struct DbConfig {
    pub url: String,
    pub max_connections: u32,
    pub acquire_timeout: Duration,
}

impl DbConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            url: std::env::var("DATABASE_URL").context("DATABASE_URL not set")?,
            max_connections: std::env::var("DATABASE_MAX_CONNECTIONS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(20),
            acquire_timeout: Duration::from_secs(
                std::env::var("DATABASE_ACQUIRE_TIMEOUT_SECS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(10),
            ),
        })
    }
}

/// Connect to Postgres with the given config.
pub async fn connect(config: &DbConfig) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(config.max_connections)
        .acquire_timeout(config.acquire_timeout)
        .connect(&config.url)
        .await
        .context("failed to connect to Postgres")?;
    Ok(pool)
}

/// Run migrations from `migrations/` at the consumer's crate root.
///
/// Call from each Cloud API's startup. The shared migrations (users,
/// organizations, billing) live here; product-specific migrations live
/// in the consumer.
pub async fn migrate_shared(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::migrate!()
        .run(pool)
        .await
        .context("shared migration failed")?;
    Ok(())
}
