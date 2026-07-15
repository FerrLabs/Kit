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

    /// `SET lock NX PX lock_ttl` — true si on a acquis le verrou.
    async fn try_lock(&self, lock_key: &str) -> bool {
        // lock_ttl is caller-configured and expected to be a small, sane duration
        // (seconds-to-minutes range), far below i64::MAX milliseconds.
        #[allow(clippy::cast_possible_truncation)]
        let px = self.lock_ttl.as_millis() as i64;
        match self
            .pool
            .set::<fred::types::RedisValue, _, _>(
                lock_key,
                "1",
                Some(Expiration::PX(px)),
                Some(SetOptions::NX),
                false,
            )
            .await
        {
            Ok(v) => !v.is_null(),
            Err(_) => false,
        }
    }

    pub async fn get_or_load<T, F, Fut>(&self, loader: F) -> anyhow::Result<T>
    where
        T: Serialize + for<'de> Deserialize<'de> + Send + 'static,
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = anyhow::Result<T>> + Send + 'static,
    {
        let loader = std::sync::Arc::new(loader);

        if self.bypass {
            let v = (loader)().await?;
            let _ = self.store(&v).await;
            return Ok(v);
        }

        // Lecture ; toute erreur Valkey => dégrade en load inline.
        let raw: Option<String> = match self.pool.get(self.key).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, key = self.key, "Valkey GET échoué, load direct");
                return (loader)().await;
            }
        };

        let lock_key = format!("{}:lock", self.key);

        if let Some(raw) = raw {
            if let Ok(env) = serde_json::from_str::<Envelope<T>>(&raw) {
                let age = Duration::from_millis(now_ms().saturating_sub(env.ts_ms));
                if age < self.fresh_ttl {
                    return Ok(env.payload); // frais
                }
                // stale : sert l'ancien immédiatement, rafraîchit en fond
                // (single-flight cluster-wide via lock Valkey).
                spawn_refresh::<T, F, Fut>(
                    self.pool.clone(),
                    self.key.to_string(),
                    lock_key,
                    self.hard_ttl,
                    self.lock_ttl,
                    loader.clone(),
                );
                return Ok(env.payload);
            }
        }

        // miss : single-flight. Le gagnant du lock charge et stocke ; les
        // perdants attendent brièvement (poll) que la valeur apparaisse,
        // sinon rechargent en dernier recours (jamais d'attente infinie).
        if self.try_lock(&lock_key).await {
            // Libère le lock que le loader réussisse OU échoue, sinon il fuit
            // pendant tout lock_ttl et bloque les lecteurs concurrents.
            return match (loader)().await {
                Ok(v) => {
                    let _ = self.store(&v).await;
                    let _: Result<(), _> = self.pool.del(&lock_key).await;
                    Ok(v)
                }
                Err(e) => {
                    let _: Result<(), _> = self.pool.del(&lock_key).await;
                    Err(e)
                }
            };
        }

        let poll_interval = Duration::from_millis(25);
        let max_polls = (self.lock_ttl.as_millis() / poll_interval.as_millis().max(1)).max(1);
        for _ in 0..max_polls {
            tokio::time::sleep(poll_interval).await;
            if let Ok(Some(raw)) = self.pool.get::<Option<String>, _>(self.key).await {
                if let Ok(env) = serde_json::from_str::<Envelope<T>>(&raw) {
                    let age = Duration::from_millis(now_ms().saturating_sub(env.ts_ms));
                    if age < self.fresh_ttl {
                        return Ok(env.payload);
                    }
                }
            }
        }

        // Dernier recours : le détenteur du verrou n'a pas fini à temps.
        let v = (loader)().await?;
        let _ = self.store(&v).await;
        Ok(v)
    }
}

/// Rafraîchit `key` en fond, avec single-flight cluster-wide via `lock_key`
/// (`SET NX PX`). Seul le gagnant du verrou recharge ; les autres renvoient
/// immédiatement sans rien faire.
fn spawn_refresh<T, F, Fut>(
    pool: CachePool,
    key: String,
    lock_key: String,
    hard_ttl: Duration,
    lock_ttl: Duration,
    loader: std::sync::Arc<F>,
) where
    T: Serialize + for<'de> Deserialize<'de> + Send + 'static,
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = anyhow::Result<T>> + Send + 'static,
{
    tokio::spawn(async move {
        // single-flight : seul le gagnant du lock rafraîchit.
        // lock_ttl/hard_ttl are caller-configured and expected to be small,
        // sane durations, far below i64::MAX milliseconds.
        #[allow(clippy::cast_possible_truncation)]
        let px = lock_ttl.as_millis() as i64;
        let got = matches!(
            pool.set::<fred::types::RedisValue, _, _>(
                &lock_key,
                "1",
                Some(Expiration::PX(px)),
                Some(SetOptions::NX),
                false,
            )
            .await,
            Ok(v) if !v.is_null()
        );
        if !got {
            return;
        }
        match (loader)().await {
            Ok(v) => {
                let json = serde_json::to_string(&Envelope {
                    ts_ms: now_ms(),
                    payload: &v,
                })
                .ok();
                if let Some(json) = json {
                    #[allow(clippy::cast_possible_truncation)]
                    let hard_px = hard_ttl.as_millis() as i64;
                    let _ = pool
                        .set::<(), _, _>(&key, json, Some(Expiration::PX(hard_px)), None, false)
                        .await;
                }
            }
            Err(e) => tracing::warn!(error = %e, key = %key, "refresh SWR en fond échoué"),
        }
        let _: Result<(), _> = pool.del(&lock_key).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    async fn pool() -> Option<crate::CachePool> {
        let url = std::env::var("TEST_VALKEY_URL").ok()?;
        crate::connect(&crate::CacheConfig {
            url,
            pool_size: 2,
            ca_cert_path: None,
            password: None,
        })
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

    #[tokio::test]
    async fn stale_serves_old_and_refreshes_once() {
        let Some(pool) = pool().await else {
            return;
        };
        let key = "test:swr:stale";
        let _: Result<(), _> = pool.del(key).await;
        let calls = Arc::new(AtomicU32::new(0));
        let mk = |calls: Arc<AtomicU32>, val: u32| {
            move || {
                let calls = calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok::<u32, anyhow::Error>(val)
                }
            }
        };
        // fresh_ttl très court => l'entrée devient stale quasi immédiatement.
        let swr = |b: bool| Swr {
            pool: &pool,
            key,
            fresh_ttl: Duration::from_millis(1),
            hard_ttl: Duration::from_secs(120),
            lock_ttl: Duration::from_secs(30),
            bypass: b,
        };
        assert_eq!(
            swr(false).get_or_load(mk(calls.clone(), 1)).await.unwrap(),
            1
        ); // miss => 1 call
        tokio::time::sleep(Duration::from_millis(5)).await;
        // 3 lectures concurrentes en stale : renvoient l'ancien, 1 SEUL refresh.
        // (liées à des variables nommées : `swr(false)` en position d'argument
        // inline de `tokio::join!` serait un temporaire droppé avant d'être
        // pollé, cf. E0716.)
        let (s1, s2, s3) = (swr(false), swr(false), swr(false));
        let (a, b, c) = tokio::join!(
            s1.get_or_load(mk(calls.clone(), 2)),
            s2.get_or_load(mk(calls.clone(), 2)),
            s3.get_or_load(mk(calls.clone(), 2)),
        );
        assert_eq!(
            (a.unwrap(), b.unwrap(), c.unwrap()),
            (1, 1, 1),
            "stale servi immédiatement"
        );
        tokio::time::sleep(Duration::from_millis(50)).await; // laisse le refresh finir
        assert_eq!(calls.load(Ordering::SeqCst), 2, "1 miss + 1 refresh unique");
    }

    #[tokio::test]
    async fn miss_loader_error_releases_lock() {
        let Some(pool) = pool().await else {
            return;
        };
        let key = "test:swr:miss-err";
        let lock_key = format!("{key}:lock");
        let _: Result<(), _> = pool.del(key).await;
        let _: Result<(), _> = pool.del(lock_key.as_str()).await;
        let swr = || Swr {
            pool: &pool,
            key,
            fresh_ttl: Duration::from_secs(60),
            hard_ttl: Duration::from_secs(120),
            // court : même en cas de régression le poll de secours ne bloque pas trop.
            lock_ttl: Duration::from_secs(5),
            bypass: false,
        };
        // miss + loader qui échoue => Err renvoyée, mais le lock DOIT être libéré.
        let err = swr()
            .get_or_load(|| async { Err::<u32, anyhow::Error>(anyhow::anyhow!("boom")) })
            .await;
        assert!(err.is_err(), "loader échoue => Err propagée");
        // Preuve directe : le lock single-flight ne fuit pas.
        let exists: i64 = pool.exists(lock_key.as_str()).await.unwrap();
        assert_eq!(
            exists, 0,
            "lock libéré après erreur du loader (pas de fuite)"
        );
        // Preuve indirecte : un second appel (loader OK) charge immédiatement,
        // sans devoir attendre l'expiration de lock_ttl.
        let start = std::time::Instant::now();
        let v = swr()
            .get_or_load(|| async { Ok::<u32, anyhow::Error>(99) })
            .await
            .unwrap();
        assert_eq!(v, 99);
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "seconde lecture immédiate (lock non fuité)"
        );
    }
}
