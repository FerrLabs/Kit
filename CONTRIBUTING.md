# Contributing to FerrLabs Kit

## Git hooks

Run once after cloning:

```bash
./.githooks/install.sh
```

That sets `git config core.hooksPath .githooks` so:
- **pre-commit** runs `cargo fmt --check` + `cargo clippy -D warnings` on every commit that touches Rust files.
- **pre-push** runs `cargo test --workspace --all-features` so broken code never reaches the remote.
