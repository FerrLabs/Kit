# Changelog

All notable changes to `ferrlabs-github` will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [2.2.0] - 2026-09-04

## [2.1.0] - 2026-08-23

## [2.0.0] - 2026-08-16

### Breaking Changes

- feat!: passe les crates en 1.0.0 et bascule en semver (#180)
- feat!: upgrade to sqlx 0.9 across sqlx-exposing crates (#117)

### Features

- feat(github): add a crate for App tokens and installation ownership (#220)
- feat(oauth): add Discord provider and extract the OAuth client into ferrlabs-oauth (#195)
- feat(testkit): golden-test harness for api-version transform chains (#189)
- feat(api-version): versionnement de contrat par date avec transformations (#185)
- feat(ci): dispatch Renovate when the rebase box is ticked (#149)
- feat(cache): VALKEY_PASSWORD + URL robuste aux mots de passe non-URL-safe (#148)
- feat(cache): support TLS client (rustls) avec vérification CA (#147)
- feat(cache): helper SWR stale-while-revalidate + single-flight (#146)
- feat(telemetry): Prometheus HTTP metrics middleware + /metrics server (Kit#4) (#141)
- feat(cache): add ferrlabs-cache crate (shared Valkey pool + config) (#136)
- feat(auth): TOTP 2FA with envelope-encrypted seeds and recovery codes (#128)
- feat(auth): Google + GitHub OAuth authorization-code flow with PKCE (#127)
- feat(billing): Stripe client + webhook signature verification (#126)
- feat(middleware): land decoupled CORS layer (#114)
- feat(telemetry): implement init() with tracing-subscriber + OTLP export (#113)
- feat(license): add licensegen minting tool behind the cli feature (#111)
- feat(license): add ferrlabs-license crate for offline self-host license gating (#109)
- feat: make workspace crates publishable to the Kellnr registry (#97)
- feat(testkit): use TEST_DATABASE_URL when set (no-Docker integration tests) (#91)
- feat: scaffold ratelimit, webhooks, id, and audit crates (#82)
- feat: scaffold ferrlabs-vault, ferrlabs-http and ferrlabs-testkit crates (#79)
- feat(queue): add ferrlabs-queue crate — Postgres-backed durable job queue (#76)
- feat(permissions): scaffold ferrlabs-permissions crate (closes #30) (#53)
- feat(ci): trigger ad-hoc Renovate scan after release (#51)
- feat(telemetry): add events module + dispatch consumer APIs on release (#39)
- feat(types): add full Product enum + rename Plan::Business to Pro + Subscription type (#36)
- feat(auth): JWT (ed25519) + session store with rotation-based theft detection (#29)
- feat(ci): add FerrFlow release workflow for Kit monorepo (#23)
- feat: port errors, crypto, middleware, auth, telemetry modules from FerrFlow-Cloud api (#3)
- feat: bootstrap Cargo workspace with 8 crates (#2)

### Bug Fixes

- fix(ci): accorde pull-requests write au job appelant les reusables (#207)
- fix(queue): retire la version de la dependance de dev testkit (#193)
- fix(release): valide l'ordre topologique de ferrflow.json en CI (#191)
- fix(release): publie ferrlabs-id avant ferrlabs-audit qui en dépend (#188)
- fix(release): publie les huit crates absentes de ferrflow.json (#187)
- perf(ci): retire apt-packages, les runners portent déjà ces paquets (#186)
- fix(testkit): rend les bases de test uniques et les supprime (#178)
- fix(deps): update rust crate jsonwebtoken to v11 (#170)
- fix(ci): repair renovate-rebase.yml truncated by the pin sweep (#168)
- fix(deps): update rust crate prometheus to 0.14 (#145)
- fix(telemetry): mark gather() #[must_use] (#144)
- fix(telemetry): document serve() error contract (re-release 0.7.x — 0.7.0 tagged but not published to kellnr) (#142)
- fix(deps): update rust crate reqwest to 0.13 (#62)
- fix(auth): implement AuthUser FromRequestParts JWT extractor (#115)
- fix(deps): update rust crate opentelemetry-otlp to 0.32 (#86)
- fix(deps): update rust crate opentelemetry_sdk to 0.32 (#85)
- fix(permissions): align Scope serde with as_str + add Resource trait; sync README (#77)
- fix(deps): update rust crate tracing-opentelemetry to 0.33 (#63)
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

### Refactoring

- refactor(queue): extract helpers to cut worker-loop cognitive complexity (#95)
