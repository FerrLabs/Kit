# Kit

Shared Rust crate for [FerrLabs](https://ferrlabs.com) product backends.

Provides the server-side building blocks — authentication middleware, error types, structured logging, DB helpers, Stripe integration, JWT utilities, rate limiting — consumed by:
- [FerrFlow-Cloud/api](https://github.com/FerrLabs/FerrFlow-Cloud) (FerrFlow backend)
- [FerrVault-Cloud/api](https://github.com/FerrLabs/FerrVault-Cloud) (FerrVault backend)

## Crate layout

```
crates/
├── auth/           JWT, sessions, OAuth providers
├── errors/         Common error types, axum extractor
├── db/             Postgres connection pool, transaction helpers, migration runner
├── billing/        Stripe wrapper, subscription state machine
├── telemetry/      Tracing, metrics, logging setup
└── types/          Shared domain types (User, Organization, etc.)
```

## Schema ownership

The DB schema for shared tables (`users`, `organizations`, `billing_*`) lives here under `crates/db/migrations/`. Both FerrFlow-Cloud and FerrVault-Cloud run these migrations against the shared Postgres instance.

Product-specific tables (`releases`, `secrets`, etc.) live in each Cloud repo's own migrations.

## Usage

Consumed via git dep in each Cloud repo's `Cargo.toml`:
```toml
[dependencies]
ferrlabs-auth = { git = "ssh://git@github.com/FerrLabs/Kit.git", branch = "main" }
```

Or once stable, published to a private Cargo registry.

## Status

**In development.** Extracted from the existing `packages/api` in FerrFlow-Cloud.

## License

Proprietary.
