use crate::CachePool;
use fred::prelude::*;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize)]
struct Envelope<T> {
    ts_ms: u64,
    payload: T,
}

fn now_ms() -> u64 {
    // ms-since-epoch overflows u64 only ~584 million years from now.
    #[allow(clippy::cast_possible_truncation)]
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    ms
}

pub struct Swr<'a> {
    pub pool: &'a CachePool,
    pub key: &'a str,
    pub fresh_ttl: Duration,
    pub hard_ttl: Duration,
    pub lock_ttl: Duration,
    pub bypass: bool,
}

impl Swr<'_> {
    async fn store<T: Serialize>(&self, value: &T) -> anyhow::Result<()> {
        let env = Envelope {
            ts_ms: now_ms(),
            payload: value,
        };
        let json = serde_json::to_string(&env)?;
        // hard_ttl is caller-configured and expected to be a small, sane duration
        // (seconds-to-hours range), far below i64::MAX milliseconds.
        #[allow(clippy::cast_possible_truncation)]
        let px = self.hard_ttl.as_millis() as i64;
        self.pool
            .set::<(), _, _>(self.key, json, Some(Expiration::PX(px)), None, false)
            .await?;
        Ok(())
    }

    pub async fn get_or_load<T, F, Fut>(&self, loader: F) -> anyhow::Result<T>
    where
        T: Serialize + for<'de> Deserialize<'de> + Send + 'static,
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = anyhow::Result<T>> + Send + 'static,
    {
        if self.bypass {
            let v = loader().await?;
            let _ = self.store(&v).await;
            return Ok(v);
        }

        // Lecture ; toute erreur Valkey => dégrade en load inline.
        let raw: Option<String> = match self.pool.get(self.key).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, key = self.key, "Valkey GET échoué, load direct");
                return loader().await;
            }
        };

        if let Some(raw) = raw {
            if let Ok(env) = serde_json::from_str::<Envelope<T>>(&raw) {
                let age = Duration::from_millis(now_ms().saturating_sub(env.ts_ms));
                if age < self.fresh_ttl {
                    return Ok(env.payload); // frais
                }
                // stale : géré en Task B2. Pour l'instant, recharge inline.
                let v = loader().await?;
                let _ = self.store(&v).await;
                return Ok(v);
            }
        }

        // miss : load inline + store (single-flight ajouté en B2).
        let v = loader().await?;
        let _ = self.store(&v).await;
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    async fn pool() -> Option<crate::CachePool> {
        let url = std::env::var("TEST_VALKEY_URL").ok()?;
        crate::connect(&crate::CacheConfig { url, pool_size: 2 })
            .await
            .ok()
    }

    #[tokio::test]
    async fn miss_then_fresh_hit_calls_loader_once() {
        let Some(pool) = pool().await else {
            return;
        };
        let key = "test:swr:fresh";
        let _: Result<(), _> = pool.del(key).await;
        let calls = Arc::new(AtomicU32::new(0));
        let mk = |calls: Arc<AtomicU32>| {
            move || {
                let calls = calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok::<u32, anyhow::Error>(42)
                }
            }
        };
        let swr = || Swr {
            pool: &pool,
            key,
            fresh_ttl: Duration::from_secs(60),
            hard_ttl: Duration::from_secs(120),
            lock_ttl: Duration::from_secs(30),
            bypass: false,
        };
        assert_eq!(swr().get_or_load(mk(calls.clone())).await.unwrap(), 42); // miss
        assert_eq!(swr().get_or_load(mk(calls.clone())).await.unwrap(), 42); // fresh hit
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "loader appelé une seule fois"
        );
    }

    #[tokio::test]
    async fn bypass_forces_reload() {
        let Some(pool) = pool().await else {
            return;
        };
        let key = "test:swr:bypass";
        let _: Result<(), _> = pool.del(key).await;
        let calls = Arc::new(AtomicU32::new(0));
        let mk = |calls: Arc<AtomicU32>| {
            move || {
                let calls = calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok::<u32, anyhow::Error>(7)
                }
            }
        };
        let mut s = Swr {
            pool: &pool,
            key,
            fresh_ttl: Duration::from_secs(60),
            hard_ttl: Duration::from_secs(120),
            lock_ttl: Duration::from_secs(30),
            bypass: false,
        };
        s.get_or_load(mk(calls.clone())).await.unwrap();
        s.bypass = true;
        s.get_or_load(mk(calls.clone())).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
