//! Trusted-proxy aware client-IP extraction from `X-Forwarded-For`.

use std::net::IpAddr;

/// How many proxy hops in front of the application are trusted to append
/// honest `X-Forwarded-For` entries.
#[derive(Debug, Clone, Copy, Default)]
pub struct TrustedProxies(pub usize);

impl TrustedProxies {
    /// No proxies are trusted; `X-Forwarded-For` is ignored entirely.
    #[must_use]
    pub const fn none() -> Self {
        Self(0)
    }

    /// Trust exactly `count` proxy hops.
    #[must_use]
    pub const fn count(count: usize) -> Self {
        Self(count)
    }
}

/// Resolve the real client IP.
///
/// `peer` is the socket peer address (the immediate connection). `xff` is the
/// raw `X-Forwarded-For` header value, if present.
///
/// With `trusted.0 == 0`, `X-Forwarded-For` is untrusted and `peer` is
/// returned. With `n` trusted hops, the entry `n` positions from the right of
/// the `XFF` chain is the real client (each trusted proxy appends one entry).
/// If the chain is shorter than `n`, the leftmost entry is taken, falling back
/// to `peer` when the header is empty or unparseable.
#[must_use]
pub fn client_ip(peer: IpAddr, xff: Option<&str>, trusted: TrustedProxies) -> IpAddr {
    let hops = trusted.0;
    if hops == 0 {
        return peer;
    }

    let Some(raw) = xff else {
        return peer;
    };

    let chain: Vec<IpAddr> = raw
        .split(',')
        .filter_map(|part| part.trim().parse::<IpAddr>().ok())
        .collect();

    if chain.is_empty() {
        return peer;
    }

    if hops >= chain.len() {
        return chain[0];
    }

    chain[chain.len() - hops]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn no_trusted_proxies_ignores_xff() {
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let got = client_ip(peer, Some("1.2.3.4, 5.6.7.8"), TrustedProxies::none());
        assert_eq!(got, peer);
    }

    #[test]
    fn one_trusted_hop_takes_rightmost_xff() {
        let peer = ip("10.0.0.1");
        let got = client_ip(
            peer,
            Some("203.0.113.7, 198.51.100.2"),
            TrustedProxies::count(1),
        );
        assert_eq!(got, ip("198.51.100.2"));
    }

    #[test]
    fn two_trusted_hops_skip_two_from_right() {
        let peer = ip("10.0.0.1");
        let got = client_ip(
            peer,
            Some("203.0.113.7, 198.51.100.2, 198.51.100.9"),
            TrustedProxies::count(2),
        );
        assert_eq!(got, ip("198.51.100.2"));
    }

    #[test]
    fn spoofed_extra_left_entries_are_ignored_with_one_hop() {
        let peer = ip("10.0.0.1");
        let got = client_ip(
            peer,
            Some("9.9.9.9, 8.8.8.8, 203.0.113.7"),
            TrustedProxies::count(1),
        );
        assert_eq!(got, ip("203.0.113.7"));
    }

    #[test]
    fn chain_shorter_than_hops_falls_back_to_leftmost() {
        let peer = ip("10.0.0.1");
        let got = client_ip(peer, Some("203.0.113.7"), TrustedProxies::count(3));
        assert_eq!(got, ip("203.0.113.7"));
    }

    #[test]
    fn empty_or_garbage_header_falls_back_to_peer() {
        let peer = ip("10.0.0.1");
        assert_eq!(client_ip(peer, Some(""), TrustedProxies::count(1)), peer);
        assert_eq!(
            client_ip(peer, Some("garbage"), TrustedProxies::count(1)),
            peer
        );
        assert_eq!(client_ip(peer, None, TrustedProxies::count(1)), peer);
    }
}
