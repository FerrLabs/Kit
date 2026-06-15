# Changelog

All notable changes to `ferrlabs-types` will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.4.1] - 2026-06-15

## [0.4.0] - 2026-05-05

### Features

- feat(telemetry): add events module + dispatch consumer APIs on release (#39)

## [0.3.0] - 2026-05-02

### Features

- feat(types): add full Product enum + rename Plan::Business to Pro + Subscription type (#36)
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
