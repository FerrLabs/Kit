# Kit

Shared Rust crate workspace for [FerrLabs](https://github.com/FerrLabs) product backends.

Consumed by:
- [FerrLabs-Cloud](https://github.com/FerrLabs/FerrLabs-Cloud) — the unified platform API (auth, orgs, billing, product APIs)
- Any future product backend that lands in the FerrLabs ecosystem

## Crates

| Crate | Role |
|-------|------|
| [`crates/types`](crates/types) | Shared domain types — `User`, `Organization`, `Membership`, `Plan`, `Role`, `Product` |
| [`crates/errors`](crates/errors) | `ApiError` + axum `IntoResponse` with stable error codes |
| [`crates/db`](crates/db) | Postgres pool, transactions, shared migrations (`users`, `organizations`, `subscriptions`) |
| [`crates/crypto`](crates/crypto) | Envelope encryption, pluggable `KekProvider` (GCP/AWS/Vault/Static) |
| [`crates/auth`](crates/auth) | JWT, sessions, OAuth (Google/GitHub), password (argon2id), TOTP 2FA, axum extractor |
| [`crates/billing`](crates/billing) | Stripe integration — customers, subscriptions, webhooks |
| [`crates/middleware`](crates/middleware) | HTTP layers — CORS, rate limit, request ID, security headers |
| [`crates/telemetry`](crates/telemetry) | Tracing, metrics, OTLP export |

## Status

**Bootstrap** — crates are scaffolded with their interface; most implementations are `TODO`. They get fleshed out as they're needed by [FerrLabs-Cloud](https://github.com/FerrLabs/FerrLabs-Cloud).

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

Proprietary.
