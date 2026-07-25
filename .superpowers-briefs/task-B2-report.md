# Task B2 report — stale-while-revalidate + single-flight

## Implementation

File modified: `crates/cache/src/swr.rs`.

- `Swr::try_lock(&self, lock_key)` — new private method, `SET lock_key "1" NX PX lock_ttl`,
  returns `true` iff the value returned by Valkey is non-null (lock acquired). Any error
  degrades to "not acquired" (`false`).
- `spawn_refresh<T, F, Fut>(pool, key, lock_key, hard_ttl, lock_ttl, loader: Arc<F>)` — new
  free function in the module. `tokio::spawn`s a background task that:
  1. attempts the same `SET NX PX` lock; losers return immediately (no-op);
  2. winner calls `loader()`, serializes an `Envelope` and `SET`s it with `PX = hard_ttl`;
  3. always releases the lock (`DEL lock_key`) at the end, win or lose on the loader;
  4. logs `tracing::warn!` if the loader errors, without propagating (background task).
- `get_or_load`:
  - wraps `loader` in `Arc::new(loader)` at the very top, so it can be cloned into the
    spawned task while the inline path keeps calling it via `(loader)()`.
  - **stale branch** (`fresh_ttl <= age < hard_ttl`, i.e. any parseable envelope that
    isn't fresh): calls `spawn_refresh(...)` (fire-and-forget) and returns
    `Ok(env.payload)` immediately — no inline reload, no await on the refresh.
  - **miss branch** (no key, or unparseable payload): `try_lock(&lock_key)`;
    - winner: loads inline, stores, deletes the lock, returns the fresh value;
    - loser: polls `GET key` every 25 ms, up to `lock_ttl / 25ms` iterations (bounded,
      never infinite), returns as soon as a *fresh* envelope shows up; if the winner
      never finishes in time, falls back to an inline `loader()` call as last resort
      (no `store` skipped — it stores via `self.store(&v)`).

## TDD proof (RED → GREEN)

### RED

Added the brief's `stale_serves_old_and_refreshes_once` test verbatim, then ran it against
the still-unmodified (B1 placeholder) implementation:

```
$ TEST_VALKEY_URL=redis://127.0.0.1:6379 cargo test -p ferrlabs-cache stale_serves_old_and_refreshes_once
...
running 1 test
test swr::tests::stale_serves_old_and_refreshes_once ... FAILED

thread 'swr::tests::stale_serves_old_and_refreshes_once' panicked at crates/cache/src/swr.rs:210:9:
assertion `left == right` failed: stale servi immédiatement
  left: (2, 2, 2)
 right: (1, 1, 1)

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.02s
```

Confirms the placeholder ("stale reloads inline") returns the *new* value to all 3
concurrent readers instead of serving the stale one, as expected.

**Deviation from the brief's test code (compile-only, no semantic change):** the brief's
snippet calls `swr(false).get_or_load(...)` inline three times as direct arguments to
`tokio::join!`. This does not compile (`E0716: temporary value dropped while borrowed`):
`get_or_load(&self, …)` returns a future borrowing `self`, and `tokio::join!` expands each
argument into its own inner `let` binding, whose temporary-value drop scope ends before the
macro's poll loop runs — so the temporary `Swr` returned by `swr(false)` is freed while the
future returned by `.get_or_load()` still borrows it. Fixed by binding the three `Swr`
values to named locals (`let (s1, s2, s3) = (swr(false), swr(false), swr(false));`) before
passing `s1.get_or_load(...)`, `s2.get_or_load(...)`, `s3.get_or_load(...)` to `tokio::join!`
— same runtime semantics (3 independent `Swr` configs, all `bypass: false`), purely a
lifetime-scoping fix.

### GREEN

```
$ TEST_VALKEY_URL=redis://127.0.0.1:6379 cargo test -p ferrlabs-cache
running 3 tests
test swr::tests::miss_then_fresh_hit_calls_loader_once ... ok
test swr::tests::bypass_forces_reload ... ok
test swr::tests::stale_serves_old_and_refreshes_once ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s
```

Re-ran 5x in a row (lib tests, no flakiness observed):

```
test result: ok. 3 passed; 0 failed; ... finished in 0.09s
test result: ok. 3 passed; 0 failed; ... finished in 0.07s
test result: ok. 3 passed; 0 failed; ... finished in 0.09s
test result: ok. 3 passed; 0 failed; ... finished in 0.07s
test result: ok. 3 passed; 0 failed; ... finished in 0.09s
```

### Clippy

```
$ cargo clippy -p ferrlabs-cache --all-targets -- -D warnings
    Checking ferrlabs-cache v0.2.0 (/home/bryan/kit/crates/cache)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.69s
```

No warnings. Had to add `#[allow(clippy::cast_possible_truncation)]` (with a justification
comment, same pattern as B1's `store()`) on the three new `as_millis() as i64` casts in
`try_lock` and `spawn_refresh` — `lock_ttl`/`hard_ttl` are caller-configured small durations,
far below `i64::MAX` ms.

## Files changed

- `crates/cache/src/swr.rs` (+171/-8): `try_lock`, `spawn_refresh`, rewritten `get_or_load`
  stale/miss branches, new test.
- `crates/cache/Cargo.toml`: untouched (verified via `git diff` before commit — `version`
  field not modified, per FerrFlow constraint).

Commit: `e1fc483` — `feat(cache): stale-while-revalidate + single-flight cluster-wide`
(subject-only, no body/trailer, on branch `feat/cache-swr`, on top of B1's `ed8cb4c`).

## Self-review

- Stale branch never blocks on the refresh — verified by the test's tight timing (3
  concurrent readers return `1` before the 50 ms grace sleep).
- Single-flight is enforced by the *same* Valkey `SET NX PX` lock in both the stale
  background-refresh path and the miss inline path — cluster-wide, not just per-process
  (any pod losing the race backs off).
- Miss-branch losers never wait unboundedly: poll loop is capped at
  `lock_ttl / 25ms` iterations. If the lock holder crashes without releasing/writing, the
  lock's own `PX` expiry (not the poll cap) is what ultimately bounds recovery — a losing
  reader that exhausts its poll budget still falls back to an inline `loader()` call rather
  than erroring out.
- `store()` (used by the miss winner and the last-resort fallback) and `spawn_refresh`'s
  own `SET` both apply `PX = hard_ttl`, consistent with B1's envelope-freshness contract
  (`age` measured against `ts_ms` written at store time, not against Valkey TTL).
- Lock cleanup (`DEL lock_key`) happens on both the loader-success and loader-error paths
  in `spawn_refresh`, so a failed background refresh doesn't strand the lock until its PX
  expiry only — it's freed immediately, allowing a prompt retry on the next stale read.

## Concerns

1. **Test snippet deviation.** As documented above, the brief's exact
   `tokio::join!(swr(false).get_or_load(...), ...)` form doesn't compile under current
   Rust/tokio (E0716). I fixed it by binding to named locals — same coverage and
   assertions, zero logic change, but flagging in case another task/report assumed the
   brief's snippet was used byte-for-byte.
2. **Miss-branch poll fallback can cause a second concurrent load.** If the lock holder is
   simply slow (not crashed) and a loser's poll budget (`lock_ttl / 25ms` iterations)
   expires first, the loser calls `loader()` itself as "last resort" while the original
   holder may still be mid-load. This is called out explicitly as acceptable in the brief
   ("sinon `(loader)()` inline en dernier recours") but is worth flagging as a place where
   single-flight isn't airtight under slow loaders relative to `lock_ttl`. Not something I
   changed — matches the brief's spec.
3. **No test added for the miss-branch single-flight/poll-then-fallback path itself**
   (only the stale-branch single-flight is covered, per the brief's Step 1). Given B2's
   scope was TDD against exactly that one test, I did not add extra tests beyond what was
   asked; a follow-up task could add coverage for "loser sees the winner's fresh value via
   polling" and "loser times out and reloads inline" if desired.

---

## B2 review fix — lock leak on loader error (miss-winner path)

**Critical bug (found in review):** in `get_or_load`'s miss branch, the lock winner ran
`let v = (loader)().await?;` — the `?` short-circuited `self.pool.del(&lock_key)` on loader
error, leaking the Valkey lock for the whole `lock_ttl` (~30s). Concurrent readers then
polled a key that would never appear before falling back inline. The twin `spawn_refresh`
path already released the lock on both Ok and Err; the fix aligns the miss path.

### Fix

`crates/cache/src/swr.rs`, miss-winner path — replaced the `?` early-return with an explicit
`match` that `DEL`s the lock on both arms:

```rust
if self.try_lock(&lock_key).await {
    return match (loader)().await {
        Ok(v) => { let _ = self.store(&v).await; let _: Result<(), _> = self.pool.del(&lock_key).await; Ok(v) }
        Err(e) => { let _: Result<(), _> = self.pool.del(&lock_key).await; Err(e) }
    };
}
```

### New focused test — `miss_loader_error_releases_lock`

Fresh-`del` key, miss + loader returning `Err` → asserts `get_or_load` returns `Err`, then
proves the lock is released two ways: `pool.exists("<key>:lock") == 0`, and a second call
(loader OK) on the same key returns immediately (`elapsed < 1s`, not blocked on `lock_ttl`).
`lock_ttl` kept short (5s) so a regression can't hang the suite.

#### RED (before fix)

```
$ TEST_VALKEY_URL=redis://127.0.0.1:6379 cargo test -p ferrlabs-cache miss_loader_error_releases_lock
running 1 test
test swr::tests::miss_loader_error_releases_lock ... FAILED

thread '...' panicked at crates/cache/src/swr.rs:357:9:
assertion `left == right` failed: lock libéré après erreur du loader (pas de fuite)
  left: 1
 right: 0

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.01s
```

`exists == 1` ⇒ lock leaked, exactly the reported bug.

#### GREEN (after fix)

```
$ TEST_VALKEY_URL=redis://127.0.0.1:6379 cargo test -p ferrlabs-cache
running 4 tests
test swr::tests::miss_then_fresh_hit_calls_loader_once ... ok
test swr::tests::bypass_forces_reload ... ok
test swr::tests::miss_loader_error_releases_lock ... ok
test swr::tests::stale_serves_old_and_refreshes_once ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s
```

#### Clippy

```
$ cargo clippy -p ferrlabs-cache --all-targets -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.99s
```

Commit: `2f3129d` — `fix(cache): libère le lock single-flight sur erreur loader (miss)`
(subject-only, on `feat/cache-swr`, on top of B2's `e1fc483`).

**Note on concern #2 from the original report:** the last-resort inline fallback (miss losers
whose poll budget expires) still uses `let v = (loader)().await?;` — but that path holds *no*
lock, so its `?` early-return leaks nothing. Only the lock-winner path needed the fix.
