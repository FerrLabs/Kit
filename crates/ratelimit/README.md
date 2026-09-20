# ferrlabs-ratelimit

Token-bucket rate limiting, plus the part people get wrong: working out which IP the request
actually came from when there is a proxy in front.

```rust
use ferrlabs_ratelimit::{InMemoryRateLimiter, Quota, RateLimiter, ip_key};

let limiter = InMemoryRateLimiter::new(Quota::new(30, 10.0));

if !limiter.check(&ip_key(addr)) {
    // 429
}
```

`Quota::new(30, 10.0)` is a bucket of 30 that refills at 10 per second, so a client can burst to 30
and then sustain 10.

## Client IP behind a proxy

`TrustedProxies` is a count of how many proxy hops sit in front of you, because each one appends
exactly one `X-Forwarded-For` entry. `client_ip` counts that many positions from the right and takes
what it finds.

```rust
use ferrlabs_ratelimit::{TrustedProxies, client_ip};

let ip = client_ip(peer_addr, xff_header_value, TrustedProxies::count(1));
```

Reading the leftmost entry instead is the common mistake, and it is worse than having no rate limit
at all: everything to the left of your own proxies is attacker-controlled, so every request can
claim a fresh address and the bucket never fills. Trusting the socket address alone is the other
failure, since behind a proxy every request shares one address and one abusive client locks out
everybody.

`TrustedProxies::none()` ignores the header entirely and is the right default when nothing is in
front of the process.

## Testing

`RateLimiter` and `Clock` are traits, and `MonotonicClock` is the default. Inject your own clock to
test refill behaviour without sleeping.

## Status

Part of [FerrLabs Kit](https://github.com/FerrLabs/Kit). MPL-2.0.
