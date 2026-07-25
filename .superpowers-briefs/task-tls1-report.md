# Phase 1 — TLS client support (rustls) for `ferrlabs-cache`

Branch: `feat/cache-tls` (from `origin/main` @ `641c4a4`)

## fred 9.4.0 API used (verified from vendored sources)

Source root: `~/.cargo/registry/src/index.crates.io-*/fred-9.4.0/`

- Feature flags (`Cargo.toml` lines 63-64, 409-426): `enable-rustls` pulls in
  `tokio-rustls/aws_lc_rs`; `enable-rustls-ring` pulls in `tokio-rustls/ring`.
  Chose **`enable-rustls-ring`** — pure-Rust `ring` backend, no extra build
  toolchain (cmake/nasm) requirement that `aws-lc-rs` can carry.
- `fred` re-exports the exact `rustls` crate it compiled against as
  `pub extern crate rustls` (`src/lib.rs:37`, gated on
  `enable-rustls`/`enable-rustls-ring`). We use `fred::rustls::{ClientConfig,
  RootCertStore}` directly instead of adding our own `rustls` dependency —
  this makes a version mismatch between "our" `ClientConfig` and fred's
  `TlsConnector` structurally impossible (same crate instance).
- `fred::types::{TlsConfig, TlsConnector, TlsHostMapping}` (also re-exported
  at `fred::prelude`/`fred::rustls`) — from `src/protocol/tls.rs`:
  - `impl From<RustlsClientConfig> for TlsConnector` (wraps in
    `tokio_rustls::TlsConnector::from(Arc::new(config))`).
  - `impl<C: Into<TlsConnector>> From<C> for TlsConfig` (blanket), so
    `let cfg: TlsConfig = client_config.into();` works directly — no need to
    go through `TlsConnector` explicitly (`src/protocol/tls.rs:101-108`).
  - `RedisConfig.tls: Option<TlsConfig>` field, publicly settable.
  - `TlsConnector::default_rustls()` builds a connector using system roots
    via `rustls-native-certs`, full verification, `with_no_client_auth()` —
    confirms fred's default posture has no accept-invalid-certs escape
    hatch (`src/protocol/tls.rs:170-182`).
- `RedisConfig::from_url("rediss://...")` (`src/types/config.rs:920-936`,
  helper `utils::tls_config_from_url` at `src/utils.rs:683-714`): **does**
  auto-enable TLS when the URL scheme is `rediss(-cluster|-sentinel)`,
  defaulting `cfg.tls` to `Some(TlsConnector::default_rustls().into())`
  (system roots) when only rustls features are compiled in. We call
  `from_url` first (so `redis://` behaviour is 100% untouched — the field
  stays `None`), then overwrite `cfg.tls` with our own `ClientConfig`
  (custom CA root store) **only** when `ca_cert_path` is provided. If
  `rediss://` is used without a CA path, we deliberately leave fred's
  system-roots default in place (still fully verified, just not pinned to
  our internal CA) rather than failing hard — documented in code as the
  fallback path; the prod case (cert-manager CA) always sets
  `VALKEY_CA_CERT`.

No accept-invalid-certs option is exposed anywhere in the new code —
`rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()`
is the only construction path, and it panics/errors rather than silently
degrading if the CA file has zero valid certs.

## Dependencies added (`crates/cache/Cargo.toml`)

```toml
fred = { workspace = true, features = ["enable-rustls-ring"] }
rustls-pemfile = "2"
```

No direct `rustls` dependency was added — `fred::rustls` (fred 9.4.0 →
`rustls 0.23.41`, confirmed via `Cargo.lock` after `cargo build`) is used
throughout `rustls_config_with_ca`, so there is exactly one `rustls` in the
dependency graph; no version-alignment risk. `rustls-pemfile 2.2.0` depends
on `rustls-pki-types 1.x`, matching what `rustls 0.23` consumes
(`rustls-0.23.41/Cargo.toml` declares `pki-types` as `rustls-pki-types`).
Crate `version` in `Cargo.toml` was **not** bumped (FerrFlow handles it at
merge).

## Code changes

- `crates/cache/src/lib.rs`:
  - `CacheConfig` gained `pub ca_cert_path: Option<String>`.
  - `CacheConfig::from_env()` reads `VALKEY_CA_CERT` (optional).
  - New private `rustls_config_with_ca(path) -> anyhow::Result<fred::rustls::ClientConfig>`:
    reads the PEM, parses certs with `rustls_pemfile::certs`, adds each to a
    `RootCertStore`, builds a `ClientConfig` with full verification and no
    client auth.
  - `connect()`: unchanged for `redis://` URLs (no branch taken, `cfg.tls`
    stays whatever `from_url` produced, i.e. `None`). For `rediss://` URLs
    with `ca_cert_path` set, `cfg.tls` is overwritten with the custom CA
    connector. Structured log line now includes `tls = bool` in addition to
    the existing `pool_size` field.
- `crates/cache/src/swr.rs`: **only** a mechanical one-field addition
  (`ca_cert_path: None`) to the existing test helper's `CacheConfig`
  literal so it keeps compiling, plus the `cargo fmt` re-indentation that
  followed from that edit. No SWR logic touched.

## TDD proof (self-hosted TLS Valkey)

Set up under `/tmp/.../scratchpad/valkey-tls/`:

```
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.pem -subj "/CN=ferrlabs-test-ca"
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=localhost"
# san.ext: subjectAltName = DNS:localhost,IP:127.0.0.1
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.pem -days 3650 -sha256 -extfile san.ext

valkey-server --tls-port 6380 --port 0 \
  --tls-cert-file server.pem --tls-key-file server.key --tls-ca-cert-file ca.pem \
  --tls-auth-clients no --dir <scratchpad>
```

Sanity check: `valkey-cli -h 127.0.0.1 -p 6380 --tls --cacert ca.pem PING` → `PONG`.

Tests added in `crates/cache/src/lib.rs::tests`, gated on
`TEST_VALKEY_TLS_URL` / `TEST_VALKEY_TLS_CA` (skip-with-message if unset,
mirroring the existing `TEST_VALKEY_URL` gate pattern in `swr.rs`):

- `connects_over_tls_with_valid_ca` — Test 1 (success): `connect()` with
  `url=rediss://127.0.0.1:6380`, `ca_cert_path=<ca.pem>` → pool built, then a
  real `SET`/`GET` round-trip over the TLS connection.
- `rejects_tls_connection_without_trusted_ca` — Test 2 (real verification):
  same `rediss://` URL, `ca_cert_path=None` → falls back to fred's
  system-roots connector, which does **not** trust the self-signed test CA
  → `connect()` must return `Err` (or, if the peer resets before a TCP-level
  error surfaces, the 10s timeout wrapper catches the hang — both outcomes
  prove no handshake ever completed).
- Test 3 (non-regression): existing `swr::tests::*` (gated on
  `TEST_VALKEY_URL=redis://127.0.0.1:6379`, plaintext) — unchanged, still
  pass.

Run (real execution, not skipped — env vars set):

```
$ TEST_VALKEY_TLS_URL="rediss://127.0.0.1:6380" \
  TEST_VALKEY_TLS_CA="/tmp/.../scratchpad/valkey-tls/ca.pem" \
  TEST_VALKEY_URL="redis://127.0.0.1:6379" \
  cargo test -p ferrlabs-cache -- --test-threads=1

running 6 tests
test swr::tests::bypass_forces_reload ... ok
test swr::tests::miss_loader_error_releases_lock ... ok
test swr::tests::miss_then_fresh_hit_calls_loader_once ... ok
test swr::tests::stale_serves_old_and_refreshes_once ... ok
test tests::connects_over_tls_with_valid_ca ... ok
test tests::rejects_tls_connection_without_trusted_ca ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.20s
```

Without the env vars (`cargo test -p ferrlabs-cache`), all 6 still report
`ok` — the two TLS tests early-return via the skip gate rather than
asserting nothing, matching the existing SWR test convention.

### Review follow-up — direct coverage of the custom-CA path (Important finding)

Review noted that `rejects_tls_connection_without_trusted_ca` only exercises
the *system-roots fallback* (`ca_cert_path: None`), not the new
`rustls_config_with_ca` + custom `RootCertStore` code path. Added
`rejects_wrong_explicit_ca` to cover it directly:

- Generated a **second, unrelated** self-signed CA (CA_B) that signed
  nothing on the server (server cert is signed by CA_A):
  ```
  openssl genrsa -out ca_b.key 2048
  openssl req -x509 -new -nodes -key ca_b.key -sha256 -days 3650 \
    -out ca_b.pem -subj "/CN=ferrlabs-test-ca-B"
  ```
- Test calls `connect()` with `url=rediss://127.0.0.1:6380` +
  `ca_cert_path=<ca_b.pem>` and asserts `Err` — proving the custom
  `RootCertStore` (built from CA_B) rejects the CA_A-signed server cert
  rather than accepting anything. Gated on `TEST_VALKEY_TLS_WRONG_CA`
  (plus the existing `TEST_VALKEY_TLS_*`), skips cleanly if unset. The
  "fix" here is the test itself; it PASSES (expected connection failure)
  against the current code.

Run (real execution against the local TLS Valkey on 6380, CA_A server):

```
$ TEST_VALKEY_TLS_URL="rediss://127.0.0.1:6380" \
  TEST_VALKEY_TLS_CA="/tmp/.../scratchpad/valkey-tls/ca.pem" \
  TEST_VALKEY_TLS_WRONG_CA="/tmp/.../scratchpad/valkey-tls/ca_b.pem" \
  TEST_VALKEY_URL="redis://127.0.0.1:6379" \
  cargo test -p ferrlabs-cache -- --test-threads=1

running 7 tests
test swr::tests::bypass_forces_reload ... ok
test swr::tests::miss_loader_error_releases_lock ... ok
test swr::tests::miss_then_fresh_hit_calls_loader_once ... ok
test swr::tests::stale_serves_old_and_refreshes_once ... ok
test tests::connects_over_tls_with_valid_ca ... ok
test tests::rejects_tls_connection_without_trusted_ca ... ok
test tests::rejects_wrong_explicit_ca ... ok

test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.25s
```

`cargo clippy -p ferrlabs-cache --all-targets -- -D warnings` → clean;
`cargo fmt -p ferrlabs-cache -- --check` → clean.

`cargo clippy -p ferrlabs-cache --all-targets -- -D warnings` → clean.
`cargo fmt -p ferrlabs-cache -- --check` → clean (after one auto-fix pass).

Local TLS Valkey instance was killed after the test run; scratchpad
certs/keys left under `/tmp/claude-1001/.../scratchpad/valkey-tls/` (ephemeral,
not part of the repo).

## Concerns / follow-ups for Phase 2+

1. **`rediss://` without `ca_cert_path` silently falls back to system
   roots** rather than erroring. This matches "prod always sets
   VALKEY_CA_CERT" but means a misconfigured deployment (missing the env
   var) degrades to "trust the OS CA bundle" instead of failing loudly. If
   the intended prod posture is "TLS always means our CA, never system
   roots," `connect()` should instead `anyhow::bail!` when `rediss://` is
   used without `ca_cert_path`. Flagging for a product decision rather than
   guessing.
2. No client-certificate (mTLS) support added — Valkey's `--tls-auth-clients
   no` matches the current prod expectation per the task brief, but if
   mTLS is needed later, `ClientConfig` would need
   `.with_client_auth_cert(...)` instead of `.with_no_client_auth()`.
3. `enable-rustls-ring` was chosen over `enable-rustls` (aws-lc-rs) purely
   for build simplicity in this sandbox; both are cryptographically sound.
   Worth confirming this matches how other FerrLabs Rust services pin their
   rustls crypto provider (for consistency / dependency dedup across the
   workspace) before merge.
4. Did not add a hostname-verification test (SAN mismatch) — Test 2 proves
   "wrong/absent CA trust" fails, but a valid-CA + wrong-hostname scenario
   would more precisely exercise SAN checking. Considered out of scope for
   Phase 1's "does TLS + custom CA work at all" goal; flagging in case
   Phase 2 wants that coverage.
