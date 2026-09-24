# ferrlabs-http

An outbound HTTP client for the case every API eventually has: fetch a URL a user supplied, without
that becoming SSRF against your own cluster.

```rust
use ferrlabs_http::{SafeFetchOpts, SafeHttpClient, safe_get};

let client = SafeHttpClient::new();
let response = safe_get(&client, user_supplied_url, &SafeFetchOpts::default()).await?;
```

`SafeFetchOpts::default()` gives a 15 second total deadline and a 5 MiB body cap.

## What it defends against

1. Scheme allowlist, so only `http` and `https` are followed.
2. IP allowlist on every resolved A and AAAA record. Loopback, RFC1918, link-local, ULA, multicast,
   broadcast and unspecified are all rejected, which catches the cloud metadata endpoint at
   `169.254.169.254` as an ordinary link-local address rather than as a special case.
3. DNS pinning, so the resolved address is pinned into the connection pool and the TCP connect
   cannot race a second lookup that returns an internal IP. This is the DNS-rebinding case, and it
   is the one a naive allowlist check misses.
4. Manual redirect following. Automatic redirects are disabled and each `Location` is revalidated
   through the same allowlist before being followed.
5. A total deadline around the whole fetch, and a streamed body that aborts past the cap instead of
   buffering quietly.

`is_public_unicast` is exported on its own if you need the address check without the client.

## Posting

`safe_post_form` sends a form-encoded POST through the same checks, for the flows where the URL is
still customer-supplied but the request is not a fetch. The OIDC token endpoint is the case it was
written for: it arrives inside a discovery document the customer's issuer serves, so it deserves the
same address check as the issuer itself.

```rust
use ferrlabs_http::{SafeFetchOpts, SafeHttpClient, safe_post_form};

let response = safe_post_form(
    &client,
    token_endpoint,
    &[("grant_type", "authorization_code"), ("code", code)],
    &SafeFetchOpts::default(),
)
.await?;
```

One difference from `safe_get`: redirects are not followed. A body cannot be replayed across a hop
whose target has not been through the address check, and token endpoints do not redirect. A 3xx
comes back as a `SafeResponse` carrying that status, for the caller to reject.

## Status

Part of [FerrLabs Kit](https://github.com/FerrLabs/Kit). MPL-2.0.
