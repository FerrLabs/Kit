# Kit

Shared Rust crate workspace for [FerrLabs](https://github.com/FerrLabs) product backends.

Consumed by:
- [FerrLabs-Cloud](https://github.com/FerrLabs/FerrLabs-Cloud) — the unified platform API (auth, orgs, billing, product APIs)
- Any future product backend that lands in the FerrLabs ecosystem

## Crates

| Crate | Status | Role |
|-------|--------|------|
| [`crates/types`](crates/types) | shipped | Shared domain types — `User`, `Organization`, `Membership`, `Plan`, `Role`, `Product` |
| [`crates/errors`](crates/errors) | shipped | `ApiError` + axum `IntoResponse` with stable error codes |
| [`crates/db`](crates/db) | shipped | Postgres pool, transactions, shared migrations (`users`, `organizations`, `subscriptions`) |
| [`crates/crypto`](crates/crypto) | shipped | Envelope encryption (AES-GCM-256 DEK, in-memory cache); `KeyProvider` trait with `LocalKek` + `GcpKmsKek` impls. AWS KMS and Vault Transit are planned, not implemented. |
| [`crates/permissions`](crates/permissions) | shipped | Typed `Scope` enum + `ScopeSet` with implication-aware checks; `Resource` trait for tenant-scoped extractors (DB-backed extractor lands separately) |
| [`crates/auth`](crates/auth) | partial | `session`, `jwt`, `password` (argon2id) shipped; `oauth` (Google/GitHub), `totp`, and the `axum` `FromRequestParts` extractor are stubs |
| [`crates/queue`](crates/queue) | shipped | Postgres-backed durable job queue (worker, retries, schema migrations) |
| [`crates/telemetry`](crates/telemetry) | partial | `events` shipped; `init` (tracing / metrics / OTLP export wiring) is a stub |
| [`crates/billing`](crates/billing) | stub | Stripe integration (customers, subscriptions, webhooks) — planned |
| [`crates/middleware`](crates/middleware) | stub | HTTP layers (CORS, rate limit, request ID, security headers) — `request_id` declared only; CORS / rate limit / security headers live in `_unmigrated/` |

## Status

**Pre-1.0** — the `types`, `errors`, `db`, `crypto`, `permissions`, `queue`, and `telemetry::events` crates are production-shape and consumed by [FerrLabs-Cloud](https://github.com/FerrLabs/FerrLabs-Cloud). `auth::{oauth,totp,middleware}`, `billing`, `middleware`, and `telemetry::init` are still stubs and ship as APIs land. Treat the `Status` column above as the source of truth — do not wire against a `stub` crate.

## Schema ownership

The `users`, `organizations`, `memberships`, and `subscriptions` tables live in `crates/db/migrations/` and are migrated by `ferrlabs-db::migrate_shared`. Product-specific tables (releases, secrets, clusters, …) live in each Cloud API's own migrations and are versioned independently.

## Develop

```bash
cargo check               # sanity check the whole workspace
cargo test                # run tests
cargo clippy -- -D warnings
cargo fmt --check
```

## Consumption

In a Cloud API's `Cargo.toml`:

```toml
[dependencies]
ferrlabs-auth = { git = "ssh://git@github.com/FerrLabs/Kit.git", branch = "main" }
ferrlabs-db = { git = "ssh://git@github.com/FerrLabs/Kit.git", branch = "main" }
# ... etc
```

Once stable, publish to a private Cargo registry.

## License

[MPL-2.0](LICENSE) — matches `license = "MPL-2.0"` in the workspace `Cargo.toml`.
