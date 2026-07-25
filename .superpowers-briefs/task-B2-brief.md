### Task B2 : Stale-while-revalidate + single-flight

**Files:**
- Modify: `crates/cache/src/swr.rs`

**Interfaces:**
- Consumes : `Swr` (Task B1).
- Produces : comportement stale (renvoie l'ancien + refresh en fond) et single-flight sur miss/stale.

- [ ] **Step 1 : Écrire le test single-flight (échoue)**

Ajouter au module `tests` :

```rust
#[tokio::test]
async fn stale_serves_old_and_refreshes_once() {
    let Some(pool) = pool().await else { return; };
    let key = "test:swr:stale";
    let _: Result<(), _> = pool.del(key).await;
    let calls = std::sync::Arc::new(AtomicU32::new(0));
    let mk = |calls: std::sync::Arc<AtomicU32>, val: u32| move || {
        let calls = calls.clone();
        async move { calls.fetch_add(1, Ordering::SeqCst); Ok::<u32, anyhow::Error>(val) }
    };
    // fresh_ttl très court => l'entrée devient stale quasi immédiatement.
    let swr = |b: bool| Swr {
        pool: &pool, key,
        fresh_ttl: Duration::from_millis(1),
        hard_ttl: Duration::from_secs(120),
        lock_ttl: Duration::from_secs(30),
        bypass: b,
    };
    assert_eq!(swr(false).get_or_load(mk(calls.clone(), 1)).await.unwrap(), 1); // miss => 1 call
    tokio::time::sleep(Duration::from_millis(5)).await;
    // 3 lectures concurrentes en stale : renvoient l'ancien, 1 SEUL refresh.
    let (a, b, c) = tokio::join!(
        swr(false).get_or_load(mk(calls.clone(), 2)),
        swr(false).get_or_load(mk(calls.clone(), 2)),
        swr(false).get_or_load(mk(calls.clone(), 2)),
    );
    assert_eq!((a.unwrap(), b.unwrap(), c.unwrap()), (1, 1, 1), "stale servi immédiatement");
    tokio::time::sleep(Duration::from_millis(50)).await; // laisse le refresh finir
    assert_eq!(calls.load(Ordering::SeqCst), 2, "1 miss + 1 refresh unique");
}
```

- [ ] **Step 2 : Implémenter single-flight + spawn**

Ajouter à `impl Swr` un helper de lock et un spawn de refresh. Remplacer la branche `stale` et la branche `miss` de `get_or_load`.

Helper (méthode privée) :

```rust
/// `SET lock NX PX lock_ttl` — true si on a acquis le verrou.
async fn try_lock(&self, lock_key: &str) -> bool {
    let px = self.lock_ttl.as_millis() as i64;
    match self
        .pool
        .set::<fred::types::RedisValue, _, _>(
            lock_key, "1", Some(Expiration::PX(px)), Some(SetOptions::NX), false,
        )
        .await
    {
        Ok(v) => !v.is_null(),
        Err(_) => false,
    }
}
```

Le spawn de refresh en fond (owned : clone le pool, la key, les TTL) — factorisé en fonction libre du module pour éviter les soucis de durée de vie :

```rust
fn spawn_refresh<T, F, Fut>(
    pool: CachePool, key: String, lock_key: String, hard_ttl: Duration,
    lock_ttl: Duration, loader: std::sync::Arc<F>,
)
where
    T: Serialize + for<'de> Deserialize<'de> + Send + 'static,
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = anyhow::Result<T>> + Send + 'static,
{
    tokio::spawn(async move {
        // single-flight : seul le gagnant du lock rafraîchit.
        let px = lock_ttl.as_millis() as i64;
        let got = matches!(
            pool.set::<fred::types::RedisValue, _, _>(
                &lock_key, "1", Some(Expiration::PX(px)), Some(SetOptions::NX), false).await,
            Ok(v) if !v.is_null()
        );
        if !got { return; }
        match loader().await {
            Ok(v) => {
                if let Ok(json) = serde_json::to_string(&Envelope { ts_ms: now_ms(), payload: &v }) {
                    let _ = pool.set::<(), _, _>(
                        &key, json, Some(Expiration::PX(hard_ttl.as_millis() as i64)), None, false).await;
                }
            }
            Err(e) => tracing::warn!(error = %e, key = %key, "refresh SWR en fond échoué"),
        }
        let _: Result<(), _> = pool.del(&lock_key).await;
    });
}
```

Modifier `get_or_load` pour :
- exiger `F: ... ` déjà `Send + Sync + 'static` (OK) et envelopper le loader dans `let loader = std::sync::Arc::new(loader);` en début de fonction ;
- branche **stale** : appeler l'ancien payload d'abord, puis
  ```rust
  spawn_refresh::<T, F, Fut>(
      self.pool.clone(), self.key.to_string(), format!("{}:lock", self.key),
      self.hard_ttl, self.lock_ttl, loader.clone(),
  );
  return Ok(env.payload);
  ```
- branche **miss** : tenter `self.try_lock(&lock_key)`. Si acquis → `let v = (loader)().await?; self.store(&v).await.ok(); del(lock); return`. Sinon → poll court (jusqu'à ~`lock_ttl`, pas au-delà, ex. boucle de `get` toutes les 25 ms avec un plafond d'itérations) ; si une valeur fraîche apparaît la renvoyer, sinon `(loader)().await` inline en dernier recours.

Le loader étant maintenant un `Arc`, l'appel inline se fait via `(loader)()`.

- [ ] **Step 3 : Lancer les tests**

Run: `cd /home/bryan/kit && TEST_VALKEY_URL=redis://127.0.0.1:6379 cargo test -p ferrlabs-cache`
Expected: `stale_serves_old_and_refreshes_once` PASS (calls == 2), les tests B1 restent verts.

- [ ] **Step 4 : Clippy**

Run: `cargo clippy -p ferrlabs-cache --all-targets -- -D warnings`
Expected: aucun warning.

- [ ] **Step 5 : Commit**

```bash
git add crates/cache/src/swr.rs
git commit -m "feat(cache): stale-while-revalidate + single-flight cluster-wide"
```

