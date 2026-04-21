# _unmigrated/

Modules ported wholesale from FerrFlow-Cloud's `api/` that still reference Application-specific metric collectors and therefore don't compile standalone in the Kit workspace.

Files are kept with a `.rs.unmigrated` extension so `cargo` ignores them. They'll be promoted back to `src/*.rs` as part of [Kit#4 — parameterization](https://github.com/FerrLabs/Kit/issues/4):

- `metrics.rs.unmigrated` — Prometheus counters + histograms (needs registry injection instead of global statics)
