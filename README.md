<div align="center">

# Kit

**The shared Rust crates every FerrLabs API is built on.**

Auth, permissions, database, errors, telemetry, billing, queues.<br />
Written once here, consumed everywhere, never copy-pasted between products.

[![Quality Gate](https://sonar.ferrlabs.com/api/project_badges/measure?project=Kit&metric=alert_status&token=sqb_2dd78d2cae70099a99721c5cdbf22eaa02f5ee4c)](https://sonar.ferrlabs.com/dashboard?id=Kit)
[![Coverage](https://sonar.ferrlabs.com/api/project_badges/measure?project=Kit&metric=coverage&token=sqb_2dd78d2cae70099a99721c5cdbf22eaa02f5ee4c)](https://sonar.ferrlabs.com/dashboard?id=Kit)
[![License](https://img.shields.io/badge/license-MPL--2.0-blue)](LICENSE)

[FerrLabs](https://github.com/FerrLabs) | [Changelog](https://ferrlabs.com/changelog/)

</div>

## Crates

21 crates, all real code in production use. Versions are independent, published to the
private Kellnr registry.

### Platform

| Crate | Role |
|---|---|
| [`auth`](crates/auth) | JWT, sessions, password hashing (argon2id), TOTP |
| [`oauth`](crates/oauth) | Authorization-code clients for Google, GitHub and Discord, PKCE S256 with CSRF state |
| [`github`](crates/github) | GitHub App auth: scoped installation access tokens, and verifying a user actually owns the installation they are claiming |
| [`permissions`](crates/permissions) | Typed scope and capability checks. A closed enum of every scope on the platform, so adding one is a crate change rather than a typo in a string literal |
| [`id`](crates/id) | Typed id newtypes over UUID, turning cross-tenant and IDOR mistakes into compile errors |
| [`types`](crates/types) | Shared domain types: `User`, `Organization`, `Membership`, `Plan` |
| [`license`](crates/license) | Offline ed25519-signed license keys for self-host editions: mint, verify, gate |

### Data

| Crate | Role |
|---|---|
| [`db`](crates/db) | Postgres pool, transaction helpers, migration runner |
| [`cache`](crates/cache) | Shared Valkey pool and config |
| [`queue`](crates/queue) | Postgres-backed durable job queue: SKIP LOCKED, LISTEN/NOTIFY, retries, idempotency |
| [`audit`](crates/audit) | Append-only audit log with typed actions and actors |

### HTTP

| Crate | Role |
|---|---|
| [`errors`](crates/errors) | Error types, domain error codes, axum `IntoResponse` |
| [`middleware`](crates/middleware) | Rate limit, CORS, request ID, security headers |
| [`ratelimit`](crates/ratelimit) | Token-bucket limiting and trusted-proxy client-IP extraction |
| [`http`](crates/http) | Outbound client with SSRF defenses: IP allowlist, DNS pinning, redirect re-checks, bounded body and deadline |
| [`api-version`](crates/api-version) | Date-based contract versioning, rendering older shapes to older clients |
| [`webhooks`](crates/webhooks) | Inbound HMAC-SHA256 verification and idempotent delivery dedup |

### Security and operations

| Crate | Role |
|---|---|
| [`crypto`](crates/crypto) | Envelope encryption and GCP Cloud KMS integration |
| [`vault`](crates/vault) | HashiCorp Vault KV v2 client |
| [`billing`](crates/billing) | Stripe customers, subscriptions, webhooks |
| [`telemetry`](crates/telemetry) | Tracing and OTLP setup, Prometheus metrics, product analytics event registry |
| [`testkit`](crates/testkit) | Ephemeral Postgres for integration tests, via testcontainers |

## Consumption

Crates are published to the private Kellnr registry, not crates.io:

```toml
[dependencies]
ferrlabs-auth   = { version = "2.2.1", registry = "kellnr" }
ferrlabs-db     = { version = "2.2.1", registry = "kellnr" }
ferrlabs-errors = { version = "2.2.1", registry = "kellnr" }
```

Consumed by the FerrVault, FerrTrack, FerrGrowth, FerrFleet, FerrLens and FerrLabs-Cloud APIs.
FerrGames is the exception and depends on none of it, by design: its gameplay is stateful and
real-time over WebSocket, which does not fit a stateless REST backend.

> [!IMPORTANT]
> Renovate does not currently update these crates ([.github#205](https://github.com/FerrLabs/.github/issues/205)).
> Every `ferrlabs-*` lookup comes back with no result, so a product can sit two majors behind
> what Kit publishes without anything flagging it. Check both sides by hand before assuming a
> gap is in the crate rather than in the pin.

## Adding to a crate

If a product needs something a crate almost does, add it here in its own PR, then consume it.
Copying a struct or a function into a product API is not an option, including as a temporary
measure, because the migration back never happens.

## Schema ownership

`users`, `organizations`, `memberships` and `subscriptions` live in `crates/db/migrations/` and
are applied by `ferrlabs-db::migrate_shared`. Product tables (releases, secrets, issues, runs)
live in each product API's own migrations and version independently.

## Develop

```bash
cargo check
cargo test
cargo clippy -- -D warnings
cargo fmt --check
```

Building locally needs a Kellnr token for the private registry. Without one, `cargo fmt` is the
only command that runs, and the real gate is the `Check API` job in CI.

## License

[MPL-2.0](LICENSE)
