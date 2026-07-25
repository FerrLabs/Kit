# Fix — percent-encode Valkey password in `ferrlabs-cache`

Branch: `fix/cache-url-safe-password` (from `origin/main` @ `ed70a80`)

## Bug

`RedisConfig::from_url` (fred → `url` crate) parses `redis://:<password>@host:port`
per RFC 3986: the first unescaped `/` after the authority ends it. A raw
base64-generated password containing `/` (e.g. `ab/cd+ef=gh`) truncates the
authority before the host, producing `invalid VALKEY_URL: Url Error: EmptyHost`.

## Fix

New private `percent_encode_userinfo(url: &str) -> String` in
`crates/cache/src/lib.rs`, called at the top of `connect()` before
`RedisConfig::from_url`:

1. Split at `://`; if absent, return the URL unchanged.
2. Find the **last** `@` in the remainder (host never contains `@`) →
   userinfo/host split even when the password itself contains `@`. No `@` →
   no userinfo → return unchanged. **(Superseded — see "Review follow-up"
   below: this search is now bounded to the left of any `?`/`#`, because a
   path/query may also contain `@`.)**
3. Split userinfo at the **first** `:` → `user` / `password` (Valkey's
   `:password` form has an empty `user`). No `:` → treat the whole userinfo
   as `user`, no password.
4. Percent-encode `user` and `password` with `percent_encoding::NON_ALPHANUMERIC`
   (only ASCII alphanumerics pass through unescaped — covers `%`, `/`, `+`,
   `=`, `@`, `:`, `#`, `?`, `&`, everything non-unreserved per RFC 3986).
5. Reconstruct `scheme://<enc_user>:<enc_pass>@<rest>` (or `scheme://<enc_user>@<rest>`
   when there was no `:`).

Applies uniformly to `redis://` and `rediss://` — the split happens on the
generic `scheme://` prefix, no scheme-specific branching, so the TLS path
added in 0.4.0 is untouched.

## Confirmed: `from_url` decodes the percent-encoded userinfo back to the raw password

Proven end-to-end, not just asserted: started a local `valkey-server --port 6382
--requirepass '0wqbH0O+mYGqq2Jd870N9pmR+V5k6T23MIVp3oaRbrc='` (real
`openssl rand -base64 32` output, containing `+` and `=`), called `connect()`
with the **raw, unencoded** URL
`redis://:0wqbH0O+mYGqq2Jd870N9pmR+V5k6T23MIVp3oaRbrc=@127.0.0.1:6382`, and
did a real `SET`/`GET` round-trip. This only succeeds if:
- the pre-processing step percent-encodes the userinfo so `from_url` parses
  a valid authority (host = `127.0.0.1`, port = `6382`), AND
- `from_url` (via the `url` crate) decodes that percent-encoding back to the
  *exact* raw password for the AUTH handshake — the server only accepts the
  literal `requirepass` value, not a percent-encoded variant.

Both held: `SET`/`GET` succeeded, i.e. AUTH succeeded with the raw password.
No workaround/separate `VALKEY_PASSWORD` field was needed.

## TDD: RED → GREEN

RED (fix temporarily reverted — `RedisConfig::from_url(&config.url)` instead
of `from_url(&sanitized_url)`), password `ab/cd+ef=gh` on `valkey-server
--port 6381 --requirepass 'ab/cd+ef=gh'`:

```
$ TEST_VALKEY_URL_SAFE_PASSWORD_URL='redis://:ab/cd+ef=gh@127.0.0.1:6381' \
  cargo test -p ferrlabs-cache --lib connects_with_raw_password_containing_url_breaking_characters

thread '...' panicked: connect with a raw URL-breaking password should succeed:
invalid VALKEY_URL: Url Error: EmptyHost
test result: FAILED. 0 passed; 1 failed
```

Exactly reproduces the 2026-07-14 prod error. Fix restored → GREEN:

```
test tests::connects_with_raw_password_containing_url_breaking_characters ... ok
test result: ok. 1 passed; 0 failed
```

## Tests added (`crates/cache/src/lib.rs::tests`)

Pure unit tests (no network, `percent_encode_userinfo` directly):
- `percent_encode_userinfo_splits_on_last_at_for_password_containing_at`
- `percent_encode_userinfo_splits_on_first_colon_for_password_containing_colon`
- `percent_encode_userinfo_encodes_percent_sign_itself`
- `percent_encode_userinfo_covers_slash_plus_equals`
- `percent_encode_userinfo_leaves_url_without_userinfo_unchanged`
- `percent_encode_userinfo_preserves_rediss_scheme`

Integration (gated on `TEST_VALKEY_URL_SAFE_PASSWORD_URL`, skips cleanly if
unset, same pattern as existing `TEST_VALKEY_URL`/`TEST_VALKEY_TLS_URL`
gates):
- `connects_with_raw_password_containing_url_breaking_characters` — real
  connect + SET/GET against a local Valkey with a `/+=`-containing password.

## Full real run (all gates satisfied, nothing skipped)

Local Valkey instances used:
- `:6379` plaintext, no password (existing `TEST_VALKEY_URL`, SWR tests)
- `:6381` / `:6382` plaintext, URL-breaking passwords (new test)
- `:6383` TLS, self-signed CA_A + unrelated CA_B (existing TLS tests,
  regenerated per the recipe from the prior TLS-support task report)

```
$ TEST_VALKEY_URL_SAFE_PASSWORD_URL="redis://:0wqbH0O+mYGqq2Jd870N9pmR+V5k6T23MIVp3oaRbrc=@127.0.0.1:6382" \
  TEST_VALKEY_URL="redis://127.0.0.1:6379" \
  TEST_VALKEY_TLS_URL="rediss://127.0.0.1:6383" \
  TEST_VALKEY_TLS_CA=".../ca.pem" \
  TEST_VALKEY_TLS_WRONG_CA=".../ca_b.pem" \
  cargo test -p ferrlabs-cache --lib -- --test-threads=1

running 14 tests
test swr::tests::bypass_forces_reload ... ok
test swr::tests::miss_loader_error_releases_lock ... ok
test swr::tests::miss_then_fresh_hit_calls_loader_once ... ok
test swr::tests::stale_serves_old_and_refreshes_once ... ok
test tests::connects_over_tls_with_valid_ca ... ok
test tests::connects_with_raw_password_containing_url_breaking_characters ... ok
test tests::percent_encode_userinfo_covers_slash_plus_equals ... ok
test tests::percent_encode_userinfo_encodes_percent_sign_itself ... ok
test tests::percent_encode_userinfo_leaves_url_without_userinfo_unchanged ... ok
test tests::percent_encode_userinfo_preserves_rediss_scheme ... ok
test tests::percent_encode_userinfo_splits_on_first_colon_for_password_containing_colon ... ok
test tests::percent_encode_userinfo_splits_on_last_at_for_password_containing_at ... ok
test tests::rejects_tls_connection_without_trusted_ca ... ok
test tests::rejects_wrong_explicit_ca ... ok

test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

`cargo clippy -p ferrlabs-cache --all-targets -- -D warnings` → clean.
`cargo fmt -p ferrlabs-cache -- --check` → clean.

Test Valkey instances (ports 6381/6382/6383) killed after the run;
scratchpad certs/keys left under
`/tmp/claude-1001/.../scratchpad/valkey-tls/` (ephemeral, not part of the repo).

## Dependency

`percent-encoding = "2"` added to `[workspace.dependencies]` in the root
`Cargo.toml`, and `percent-encoding = { workspace = true }` to
`crates/cache/Cargo.toml`. Not a new transitive dependency in practice — the
workspace's `url = "2"` already pulls in `percent-encoding 2.3.2`
(confirmed in `Cargo.lock`), so this pins the version already resolved and
used elsewhere in the graph, no new crate actually enters the dependency
tree.

`crates/cache/Cargo.toml` `version` field left untouched at `0.4.0`
(FerrFlow bumps at merge). `Cargo.lock`'s pre-existing `ferrlabs-cache
0.3.0 → 0.4.0` line is drift from the last release commit already on this
branch, unrelated to this change (I did not edit the `version` field).

## Review follow-up — userinfo search bounded to the authority (Important finding)

Review found that `rfind('@')` searched the **whole** remainder after
`scheme://`, not just the authority. The documented invariant ("the host
never contains `@`") is true but covers neither the path nor the query,
which may. Confirmed by direct demonstration on
`redis://:pw@127.0.0.1:6379/0?note=a@b`:

```
scheme    = "redis://"
userinfo  = ":pw@127.0.0.1:6379/0?note=a"
host_part = "b"
```

The real host is silently swallowed into the "userinfo" and lost. Real and
demonstrable (fred accepts a DB index in the path `/0` and query params like
`?node=host:port`), though not triggered by the current prod URL.

### The prescribed fix was itself wrong — RED proved it

The review prescribed bounding the authority at the **first `/`, `?` or `#`**.
That regresses the primary fix: the password *contains* `/`, so the first `/`
is found **inside the password**, truncating the authority to `:ab` — which
holds no `@` — so the function returns the URL unencoded and the original
`EmptyHost` bug returns. Implementing it literally and running the suite:

```
test tests::percent_encode_userinfo_covers_slash_plus_equals ... FAILED
  left:  "redis://:ab/cd@127.0.0.1:6379"      (unchanged — bug back)
  right: "redis://:ab%2Fcd@127.0.0.1:6379"
test tests::percent_encode_userinfo_preserves_db_index_path ... FAILED
test tests::percent_encode_userinfo_preserves_rediss_scheme ... FAILED
test result: FAILED. 6 passed; 3 failed
```

So the boundary cannot be `/`. The finding is valid; its prescribed
algorithm is not.

### Corrected algorithm

Chicken-and-egg: the password may contain the very delimiters used to locate
it. Resolved with two rules:

1. Bound the `@` search to the left of the first **`?` or `#`** — *not* `/`.
   A query/fragment may contain `@`; the password may contain `/` but not
   `?`/`#` (base64 `A-Za-z0-9+/=` and hex alphabets exclude them).
2. Within that bound, the separator is the **last** `@` (host never contains
   `@`, so a password that does still splits correctly).

The host then ends at the first `/`, `?` or `#` **at or after** that `@`;
path/query/fragment are appended verbatim, never re-encoded.

### RED → GREEN for the requested test 2

RED (unbounded `rfind`, i.e. the pre-correction code) — worse than predicted,
the whole host is swallowed *and* percent-encoded:

```
$ cargo test -p ferrlabs-cache --lib percent_encode_userinfo
test tests::percent_encode_userinfo_ignores_at_sign_outside_the_authority ... FAILED
  left:  "redis://:pw%40127%2E0%2E0%2E1%3A6379%2F0%3Fnote%3Da@b"
  right: "redis://:pw@127.0.0.1:6379/0?note=a@b"
test tests::percent_encode_userinfo_leaves_url_without_userinfo_but_with_path_query_unchanged ... FAILED
  left:  "redis://127%2E0%2E0%2E1:6379%2F0%3Fx%3D1@2"
  right: "redis://127.0.0.1:6379/0?x=1@2"
test result: FAILED. 7 passed; 2 failed
```

GREEN (corrected algorithm) — all 9 encode tests pass, including the ones the
prescribed fix broke:

```
test result: ok. 9 passed; 0 failed
```

### Tests added in this follow-up

- `percent_encode_userinfo_preserves_db_index_path` — `redis://:ab/cd@host:6379/0`
  → password encoded, `/0` verbatim.
- `percent_encode_userinfo_ignores_at_sign_outside_the_authority` —
  `redis://:pw@127.0.0.1:6379/0?note=a@b` → returned verbatim, plus a real
  `RedisConfig::from_url` parse asserting host `127.0.0.1` / port `6379`
  actually survive.
- `percent_encode_userinfo_leaves_url_without_userinfo_but_with_path_query_unchanged`
  — `redis://127.0.0.1:6379/0?x=1@2` → verbatim.
- `percent_encode_userinfo_handles_slash_password_together_with_path_and_query`
  — added beyond the request: `redis://:ab/cd+ef=gh@127.0.0.1:6379/0?note=a@b`
  pins **both** hazards at once (password with `/` + query with `@`), the exact
  combination the prescribed algorithm would have broken. Asserts the encoded
  output *and* a real parse of host/port.

Full real run (all gates satisfied, nothing skipped; Valkey on :6379 plain,
:6382 base64-password, :6383 TLS):

```
running 18 tests
... all 18 ...
test result: ok. 18 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

`cargo clippy -p ferrlabs-cache --all-targets -- -D warnings` → clean.
`cargo fmt -p ferrlabs-cache -- --check` → clean.

## Concerns

0. **Residual assumption**: the corrected algorithm assumes the raw password
   contains no unencoded `?` or `#`. Guaranteed for base64/hex-generated
   passwords (the only sources in use), and documented in the function's
   doc comment. A hand-typed password containing `?`/`#` would still
   mis-split. Fully removing the assumption is impossible while accepting
   non-RFC-conforming URLs: `redis://a/b@c` is genuinely ambiguous (userinfo
   `a/b` + host `c`, vs. host `a` + path `/b@c`). The robust long-term fix is
   a separate `VALKEY_PASSWORD` env var rather than in-band credentials —
   worth considering if password generation ever moves off base64/hex.
1. `percent_encoding::NON_ALPHANUMERIC` is broader than strictly necessary
   (also escapes `-`, `.`, `_`, `~`... wait, those ARE in NON_ALPHANUMERIC's
   allow-list — it actually only *escapes* non-alphanumerics, so `-._~` get
   escaped too, which is stricter than RFC 3986 "unreserved" but still
   round-trips correctly through percent-decoding). No functional issue,
   just slightly more `%XX` noise in the encoded URL than the theoretical
   minimum — harmless.
2. The doc comment's original claim that the host/userinfo split was
   "unambiguous" was too strong; it is now stated with its actual bounds
   and the reason the `/` boundary cannot be used.
3. This function is a small hand-rolled URL surgeon rather than using the
   `url` crate's own userinfo setters (`Url::parse` + `set_username`/
   `set_password`) — deliberately avoided because `url::Url::parse` itself
   would choke on the raw unencoded URL for the same `EmptyHost` reason
   before we ever got a `Url` to mutate. The string-splitting approach must
   run *before* any structured URL parsing. This is inherent to the
   problem, not a shortcut.
4. Did not add a test for a password containing a literal space or other
   non-ASCII byte (e.g. a manually-typed password) — out of scope per the
   brief (base64/hex-generated passwords are ASCII by construction), but
   flagging in case a future password source introduces non-ASCII chars;
   `utf8_percent_encode` already handles that case correctly (encodes any
   byte outside the allow-list, UTF-8 safe), just untested here.
