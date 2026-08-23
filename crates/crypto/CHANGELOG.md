# Changelog

All notable changes to `ferrlabs-crypto` will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [2.4.0] - 2026-08-23

### Features

- feat(middleware): ship the security-headers layer (#226)

### Bug Fixes

- perf(bench): add benchmarks for ferrlabs-crypto and ferrlabs-permissions (#239)

## [2.3.0] - 2026-08-16

## [2.2.0] - 2026-08-07

## [2.1.1] - 2026-08-07

## [2.1.0] - 2026-08-05

## [2.0.2] - 2026-08-05

## [2.0.1] - 2026-08-04

## [2.0.0] - 2026-08-01

### Breaking Changes

- feat!: passe les crates en 1.0.0 et bascule en semver (#180)

## [0.4.8] - 2026-08-01

## [0.4.7] - 2026-07-25

### Bug Fixes

- fix(deps): update rust crate jsonwebtoken to v11 (#170)

## [0.4.6] - 2026-07-24

## [0.4.5] - 2026-07-15

## [0.4.4] - 2026-07-13

## [0.4.3] - 2026-07-07

## [0.4.2] - 2026-06-25

## [0.4.1] - 2026-06-24

## [0.4.0] - 2026-06-15

### Breaking Changes

- feat!: upgrade to sqlx 0.9 across sqlx-exposing crates (#117)

### Features

- feat(middleware): land decoupled CORS layer (#114)
- feat(telemetry): implement init() with tracing-subscriber + OTLP export (#113)
- feat(license): add licensegen minting tool behind the cli feature (#111)
- feat(license): add ferrlabs-license crate for offline self-host license gating (#109)
- feat: make workspace crates publishable to the Kellnr registry (#97)
- feat(testkit): use TEST_DATABASE_URL when set (no-Docker integration tests) (#91)

### Bug Fixes

- fix(deps): update rust crate reqwest to 0.13 (#62)
- fix(auth): implement AuthUser FromRequestParts JWT extractor (#115)
- fix(deps): update rust crate opentelemetry-otlp to 0.32 (#86)
- fix(deps): update rust crate opentelemetry_sdk to 0.32 (#85)

### Refactoring

- refactor(queue): extract helpers to cut worker-loop cognitive complexity (#95)

## [0.3.0] - 2026-06-05

### Features

- feat: scaffold ratelimit, webhooks, id, and audit crates (#82)
- feat: scaffold ferrlabs-vault, ferrlabs-http and ferrlabs-testkit crates (#79)
- feat(queue): add ferrlabs-queue crate — Postgres-backed durable job queue (#76)
- feat(permissions): scaffold ferrlabs-permissions crate (closes #30) (#53)
- feat(ci): trigger ad-hoc Renovate scan after release (#51)
- feat(telemetry): add events module + dispatch consumer APIs on release (#39)
- feat(types): add full Product enum + rename Plan::Business to Pro + Subscription type (#36)
- feat(auth): JWT (ed25519) + session store with rotation-based theft detection (#29)

### Bug Fixes

- fix(permissions): align Scope serde with as_str + add Resource trait; sync README (#77)
- fix(deps): update rust crate tracing-opentelemetry to 0.33 (#63)

## [0.2.0] - 2026-04-23

### Features

- feat(ci): add FerrFlow release workflow for Kit monorepo (#23)
- feat: port errors, crypto, middleware, auth, telemetry modules from FerrFlow-Cloud api (#3)
- feat: bootstrap Cargo workspace with 8 crates (#2)

### Bug Fixes

- fix(deps): update rust crate tracing-opentelemetry to 0.32 (#22)
- fix(deps): update rust crate jsonwebtoken to v10 [security] (#21)
- fix(deps): update opentelemetry-rust monorepo to 0.31 (#18)
- fix(errors): pass ApiError by reference in test helper (#13)
- fix(auth): convert argon2 password_hash errors via map_err instead of context (#12)
- fix(kit): unblock telemetry + crypto compilation, disable async-stripe temporarily (#11)
- fix(errors): declare validator dep (#10)
- fix(ci): cargo fmt --all (#9)
- fix(ci): exclude unmigrated Application ports from compilation (#8)
- fix: bump rust-version to 1.85 (required by edition 2024) (#7)
