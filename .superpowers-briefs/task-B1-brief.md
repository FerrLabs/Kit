### Task B1 : Enveloppe + chemins frais/miss (sans background refresh)

**Files:**
- Create: `crates/cache/src/swr.rs`
- Modify: `crates/cache/src/lib.rs` (ajouter `mod swr; pub use swr::Swr;`)
- Modify: `crates/cache/Cargo.toml` (deps)
- Test: `crates/cache/src/swr.rs` (`#[cfg(test)]` en fin de fichier)

**Interfaces:**
- Consumes : `crate::CachePool` (= `fred::prelude::RedisPool`).
- Produces :
  ```rust
  pub struct Swr<'a> {
      pub pool: &'a CachePool,
      pub key: &'a str,
      pub fresh_ttl: Duration,
      pub hard_ttl: Duration,
      pub lock_ttl: Duration,
      pub bypass: bool,
  }
  impl Swr<'_> {
      pub async fn get_or_load<T, F, Fut>(&self, loader: F) -> anyhow::Result<T>
      where
          T: serde::Serialize + serde::de::DeserializeOwned + Send + 'static,
          F: Fn() -> Fut + Send + Sync + 'static,
          Fut: std::future::Future<Output = anyhow::Result<T>> + Send + 'static;
  }
  ```

- [ ] **Step 1 : Dépendances**

Ajouter à `crates/cache/Cargo.toml` sous `[dependencies]` :

```toml
serde = { workspace = true, features = ["derive"] }
serde_json = { workspace = true }
tokio = { workspace = true }   # workspace tokio = features ["full"] (couvre rt + time + spawn)

[dev-dependencies]
tokio = { workspace = true }   # pour #[tokio::test]
```

(Ces crates sont déjà dans `[workspace.dependencies]` de `Kit/Cargo.toml` : `serde`, `serde_json`, `tokio = features ["full"]`, `anyhow`, `fred = "9"`. NE PAS ajouter de crate `futures` — le helper n'en a pas besoin.)

- [ ] **Step 2 : Écrire le test frais/miss (échoue)**

Créer `crates/cache/src/swr.rs`. En fin de fichier, le module de test (nécessite un Valkey local ; le test se `skip` proprement si `TEST_VALKEY_URL` absent) :

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    async fn pool() -> Option<crate::CachePool> {
        let url = std::env::var("TEST_VALKEY_URL").ok()?;
        crate::connect(&crate::CacheConfig { url, pool_size: 2 }).await.ok()
    }

    #[tokio::test]
    async fn miss_then_fresh_hit_calls_loader_once() {
        let Some(pool) = pool().await else { return; };
        let key = "test:swr:fresh";
        let _: Result<(), _> = pool.del(key).await;
        let calls = Arc::new(AtomicU32::new(0));
        let mk = |calls: Arc<AtomicU32>| move || {
            let calls = calls.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok::<u32, anyhow::Error>(42)
            }
        };
        let swr = || Swr {
            pool: &pool, key,
            fresh_ttl: Duration::from_secs(60),
            hard_ttl: Duration::from_secs(120),
            lock_ttl: Duration::from_secs(30),
            bypass: false,
        };
        assert_eq!(swr().get_or_load(mk(calls.clone())).await.unwrap(), 42); // miss
        assert_eq!(swr().get_or_load(mk(calls.clone())).await.unwrap(), 42); // fresh hit
        assert_eq!(calls.load(Ordering::SeqCst), 1, "loader appelé une seule fois");
    }

    #[tokio::test]
    async fn bypass_forces_reload() {
        let Some(pool) = pool().await else { return; };
        let key = "test:swr:bypass";
        let _: Result<(), _> = pool.del(key).await;
        let calls = Arc::new(AtomicU32::new(0));
        let mk = |calls: Arc<AtomicU32>| move || {
            let calls = calls.clone();
            async move { calls.fetch_add(1, Ordering::SeqCst); Ok::<u32, anyhow::Error>(7) }
        };
        let mut s = Swr { pool: &pool, key,
            fresh_ttl: Duration::from_secs(60), hard_ttl: Duration::from_secs(120),
            lock_ttl: Duration::from_secs(30), bypass: false };
        s.get_or_load(mk(calls.clone())).await.unwrap();
        s.bypass = true;
        s.get_or_load(mk(calls.clone())).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
```

- [ ] **Step 3 : Implémenter enveloppe + frais/miss (sans stale background)**

En tête de `crates/cache/src/swr.rs` :

```rust
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
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
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
        let env = Envelope { ts_ms: now_ms(), payload: value };
        let json = serde_json::to_string(&env)?;
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
```

Dans `crates/cache/src/lib.rs`, ajouter après les imports :

```rust
mod swr;
pub use swr::Swr;
```

- [ ] **Step 4 : Lancer les tests**

Run: `cd /home/bryan/kit && TEST_VALKEY_URL=redis://127.0.0.1:6379 cargo test -p ferrlabs-cache`
(Démarrer un Valkey local au préalable : `docker run --rm -p 6379:6379 valkey/valkey` ou équivalent.)
Expected: `miss_then_fresh_hit_calls_loader_once` et `bypass_forces_reload` PASS. Sans `TEST_VALKEY_URL`, les tests retournent early (skip) et le build passe.

- [ ] **Step 5 : Commit**

```bash
git add crates/cache/src/swr.rs crates/cache/src/lib.rs crates/cache/Cargo.toml
git commit -m "feat(cache): helper SWR get_or_load (frais/miss/bypass)"
```

