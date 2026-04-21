# _unmigrated/

Modules ported wholesale from FerrFlow-Cloud's `api/` that still reference Application-specific types (`AppState`, `SharedKeyProvider`) and therefore don't compile standalone in the Kit workspace.

Files are kept with a `.rs.unmigrated` extension so `cargo` ignores them but they stay reviewable in git. They'll be promoted back to `src/*.rs` one at a time as part of [Kit#4 — parameterization](https://github.com/FerrLabs/Kit/issues/4):

- `hmac.rs.unmigrated` — HMAC middleware (needs `HmacState` trait)
- `jwt_middleware.rs.unmigrated` — JWT extractor (needs `AuthState` trait)
