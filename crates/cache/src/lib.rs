//! Shared Valkey (Redis-compatible) connection pool for FerrLabs APIs.
//!
//! Mirrors `ferrlabs-db`: config-from-env plus a `connect` factory that returns
//! an initialised `fred` pool. Consumers run commands against `fred` directly —
//! it is re-exported here so they don't take a separate `fred` dependency.

use fred::prelude::*;

pub use fred;

mod swr;
pub use swr::Swr;

#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub url: String,
    pub pool_size: usize,
}

impl CacheConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let url = std::env::var("VALKEY_URL")
            .or_else(|_| std::env::var("REDIS_URL"))
            .map_err(|_| anyhow::anyhow!("VALKEY_URL (or REDIS_URL) not set"))?;
        let pool_size = std::env::var("VALKEY_POOL_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(6);
        Ok(Self { url, pool_size })
    }
}

pub type CachePool = RedisPool;

pub async fn connect(config: &CacheConfig) -> anyhow::Result<CachePool> {
    let cfg = RedisConfig::from_url(&config.url)
        .map_err(|e| anyhow::anyhow!("invalid VALKEY_URL: {e}"))?;
    let pool = RedisPool::new(cfg, None, None, None, config.pool_size)
        .map_err(|e| anyhow::anyhow!("failed to build Valkey pool: {e}"))?;
    let _handle = pool.connect();
    pool.wait_for_connect()
        .await
        .map_err(|e| anyhow::anyhow!("Valkey connect failed: {e}"))?;
    tracing::info!(pool_size = config.pool_size, "connected to Valkey");
    Ok(pool)
}
