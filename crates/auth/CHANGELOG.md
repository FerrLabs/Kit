# Changelog

All notable changes to `ferrlabs-auth` will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [2.6.2] - 2026-09-21

### Bug Fixes

- fix(deps): update rust crate totp-rs to v6 (#199)

## [2.6.1] - 2026-09-07

### Bug Fixes

- fix(auth): port password hashing to argon2 0.6 (#271)

## [2.6.0] - 2026-09-04

### Features

- feat(mail): crate de signature DKIM (#264)

## [2.5.0] - 2026-08-23

### Features

- feat(middleware): ship the security-headers layer (#226)

### Bug Fixes

- perf(bench): add benchmarks for ferrlabs-crypto and ferrlabs-permissions (#239)

## [2.4.0] - 2026-08-16

### Features

- feat(github): add a crate for App tokens and installation ownership (#220)

### Bug Fixes

- fix(ci): accorde pull-requests write au job appelant les reusables (#207)

## [2.3.0] - 2026-08-07

### Features

- feat(oauth): add Discord provider and extract the OAuth client into ferrlabs-oauth (#195)

## [2.2.1] - 2026-08-07

### Bug Fixes

- fix(queue): retire la version de la dependance de dev testkit (#193)

## [2.2.0] - 2026-08-05

### Features

- feat(testkit): golden-test harness for api-version transform chains (#189)

### Bug Fixes

- fix(release): valide l'ordre topologique de ferrflow.json en CI (#191)

## [2.1.1] - 2026-08-05

### Bug Fixes

- fix(release): publie ferrlabs-id avant ferrlabs-audit qui en dépend (#188)
- fix(release): publie les huit crates absentes de ferrflow.json (#187)
- perf(ci): retire apt-packages, les runners portent déjà ces paquets (#186)

## [2.1.0] - 2026-08-04

### Features

- feat(api-version): versionnement de contrat par date avec transformations (#185)

## [2.0.0] - 2026-08-01

### Breaking Changes

- feat!: passe les crates en 1.0.0 et bascule en semver (#180)

## [0.12.2] - 2026-08-01

### Bug Fixes

- fix(testkit): rend les bases de test uniques et les supprime (#178)

## [0.12.1] - 2026-07-25

### Bug Fixes

- fix(deps): update rust crate jsonwebtoken to v11 (#170)

## [0.12.0] - 2026-07-24

### Features

- feat(ci): dispatch Renovate when the rebase box is ticked (#149)

### Bug Fixes

- fix(ci): repair renovate-rebase.yml truncated by the pin sweep (#168)

## [0.11.0] - 2026-07-15

### Features

- feat(cache): VALKEY_PASSWORD + URL robuste aux mots de passe non-URL-safe (#148)
- feat(cache): support TLS client (rustls) avec vérification CA (#147)
- feat(cache): helper SWR stale-while-revalidate + single-flight (#146)

### Bug Fixes

- fix(deps): update rust crate prometheus to 0.14 (#145)
- fix(telemetry): mark gather() #[must_use] (#144)
- fix(telemetry): document serve() error contract (re-release 0.7.x — 0.7.0 tagged but not published to kellnr) (#142)

## [0.10.1] - 2026-07-13

## [0.10.0] - 2026-07-13

### Features

- feat(telemetry): Prometheus HTTP metrics middleware + /metrics server (Kit#4) (#141)

## [0.9.0] - 2026-07-07

### Features

- feat(cache): add ferrlabs-cache crate (shared Valkey pool + config) (#136)

## [0.8.1] - 2026-06-25

## [0.8.0] - 2026-06-24

### Features

- feat(auth): TOTP 2FA with envelope-encrypted seeds and recovery codes (#128)

## [0.7.0] - 2026-06-24

### Features

- feat(billing): Stripe client + webhook signature verification (#126)

## [0.6.0] - 2026-06-15

### Breaking Changes

- feat!: upgrade to sqlx 0.9 across sqlx-exposing crates (#117)

## [0.5.0] - 2026-06-15

### Features

- feat(middleware): land decoupled CORS layer (#114)
- feat(telemetry): implement init() with tracing-subscriber + OTLP export (#113)
- feat(license): add licensegen minting tool behind the cli feature (#111)
- feat(license): add ferrlabs-license crate for offline self-host license gating (#109)

### Bug Fixes

- fix(auth): implement AuthUser FromRequestParts JWT extractor (#115)

## [0.4.0] - 2026-06-08

### Features

- feat: make workspace crates publishable to the Kellnr registry (#97)
- feat(testkit): use TEST_DATABASE_URL when set (no-Docker integration tests) (#91)

### Bug Fixes

- fix(deps): update rust crate opentelemetry-otlp to 0.32 (#86)
- fix(deps): update rust crate opentelemetry_sdk to 0.32 (#85)

## [0.3.3] - 2026-06-05

## [0.3.2] - 2026-05-05

## [0.3.1] - 2026-05-02

## [0.3.0] - 2026-04-23

### Features

- feat(auth): JWT (ed25519) + session store with rotation-based theft detection (#29)

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
