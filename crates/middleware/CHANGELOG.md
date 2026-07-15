# Changelog

All notable changes to `ferrlabs-middleware` will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.3.8] - 2026-07-15

## [0.3.7] - 2026-07-13

## [0.3.6] - 2026-07-13

## [0.3.5] - 2026-07-07

## [0.3.4] - 2026-06-25

## [0.3.3] - 2026-06-24

## [0.3.2] - 2026-06-24

## [0.3.1] - 2026-06-15

## [0.3.0] - 2026-06-15

### Features

- feat(middleware): land decoupled CORS layer (#114)
- feat(telemetry): implement init() with tracing-subscriber + OTLP export (#113)
- feat(license): add licensegen minting tool behind the cli feature (#111)
- feat(license): add ferrlabs-license crate for offline self-host license gating (#109)

### Bug Fixes

- fix(auth): implement AuthUser FromRequestParts JWT extractor (#115)

## [0.2.5] - 2026-06-08

## [0.2.4] - 2026-06-05

## [0.2.3] - 2026-05-05

## [0.2.2] - 2026-05-02

## [0.2.1] - 2026-04-23

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
