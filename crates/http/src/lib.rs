//! Safe outbound HTTP client for FerrLabs APIs.
//!
//! Built for the case every API has: "I need to fetch a URL the user
//! gave me, without enabling SSRF against the cluster's metadata
//! endpoint, RDS database, or internal services."
//!
//! Defenses applied to every request:
//!
//! 1. URL scheme allowlist — only `http` / `https`.
//! 2. DNS resolution and IP allowlist — every resolved A/AAAA must be
//!    a public unicast address. Loopback, RFC1918, link-local, ULA,
//!    multicast, broadcast, unspecified, IPv6 unique-local — all
//!    rejected. The AWS / GCP metadata IP `169.254.169.254` is a
//!    link-local address and gets caught by that rule.
//! 3. DNS pinning — the resolved IP is pinned into the connection
//!    pool, so the TCP connect cannot race against a second DNS
//!    lookup that resolves to an internal IP (DNS-rebinding defense).
//! 4. Manual redirect following — reqwest's automatic redirect policy
//!    is disabled. Each `Location` header is re-validated through the
//!    same IP allowlist before we follow.
//! 5. Total deadline + bounded body — `tokio::time::timeout` wraps
//!    the entire fetch, and the response body is streamed and aborted
//!    when it exceeds `max_body_bytes` instead of being silently
//!    buffered.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use reqwest::{Client, redirect};
use thiserror::Error;
use tokio::net::lookup_host;
use url::{Url, form_urlencoded};

#[derive(Debug, Error)]
pub enum SafeFetchError {
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    #[error("scheme `{0}` not allowed (only http/https)")]
    UnsupportedScheme(String),
    #[error("url has no host")]
    MissingHost,
    #[error("dns lookup failed: {0}")]
    DnsLookup(String),
    #[error("dns returned no addresses")]
    DnsEmpty,
    #[error("address {0} is not a public unicast ip")]
    BlockedAddress(IpAddr),
    #[error("redirect limit ({0}) exceeded")]
    TooManyRedirects(u8),
    #[error("redirect missing Location header")]
    BadRedirect,
    #[error("response body exceeded {0} bytes")]
    BodyTooLarge(usize),
    #[error("request deadline exceeded")]
    Timeout,
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
}

#[derive(Debug, Clone, Default)]
pub struct SafeHttpClient {
    _priv: (),
}

impl SafeHttpClient {
    #[must_use]
    pub fn new() -> Self {
        Self { _priv: () }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SafeFetchOpts {
    pub timeout: Duration,
    pub max_body_bytes: usize,
    pub max_redirects: u8,
}

impl Default for SafeFetchOpts {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(15),
            max_body_bytes: 5 * 1024 * 1024,
            max_redirects: 5,
        }
    }
}

#[derive(Debug)]
pub struct SafeResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub final_url: String,
}

#[must_use]
pub fn is_public_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_unicast_v4(v4),
        IpAddr::V6(v6) => is_public_unicast_v6(v6),
    }
}

fn is_public_unicast_v4(ip: Ipv4Addr) -> bool {
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
    {
        return false;
    }
    let o = ip.octets();
    if o[0] == 0 {
        return false;
    }
    if o[0] == 100 && (64..=127).contains(&o[1]) {
        return false;
    }
    if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        return false;
    }
    if o[0] == 192 && o[1] == 0 && o[2] == 2 {
        return false;
    }
    if o[0] == 192 && o[1] == 88 && o[2] == 99 {
        return false;
    }
    if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
        return false;
    }
    if o[0] >= 240 {
        return false;
    }
    true
}

fn is_public_unicast_v6(ip: Ipv6Addr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    let seg = ip.segments();
    if (seg[0] & 0xfe00) == 0xfc00 {
        return false;
    }
    if (seg[0] & 0xffc0) == 0xfe80 {
        return false;
    }
    if seg[0] == 0x2001 && seg[1] == 0xdb8 {
        return false;
    }
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_unicast_v4(v4);
    }
    true
}

pub async fn safe_get(
    client: &SafeHttpClient,
    url: &str,
    opts: &SafeFetchOpts,
) -> Result<SafeResponse, SafeFetchError> {
    let fut = safe_get_inner(client, url, opts);
    match tokio::time::timeout(opts.timeout, fut).await {
        Ok(r) => r,
        Err(_) => Err(SafeFetchError::Timeout),
    }
}

pub async fn safe_post_form(
    client: &SafeHttpClient,
    url: &str,
    form: &[(&str, &str)],
    opts: &SafeFetchOpts,
) -> Result<SafeResponse, SafeFetchError> {
    let fut = safe_post_form_inner(client, url, form, opts);
    match tokio::time::timeout(opts.timeout, fut).await {
        Ok(r) => r,
        Err(_) => Err(SafeFetchError::Timeout),
    }
}

async fn safe_post_form_inner(
    _client: &SafeHttpClient,
    url: &str,
    form: &[(&str, &str)],
    opts: &SafeFetchOpts,
) -> Result<SafeResponse, SafeFetchError> {
    let parsed = Url::parse(url).map_err(|e| SafeFetchError::InvalidUrl(e.to_string()))?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => return Err(SafeFetchError::UnsupportedScheme(other.to_string())),
    }
    let host = parsed.host_str().ok_or(SafeFetchError::MissingHost)?;
    let port = parsed
        .port_or_known_default()
        .ok_or(SafeFetchError::MissingHost)?;
    let pinned = resolve_and_validate(host, port).await?;

    let pinned_client = Client::builder()
        .redirect(redirect::Policy::none())
        .resolve(host, pinned)
        .build()?;

    let body = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form.iter().copied())
        .finish();
    let resp = pinned_client
        .post(parsed)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body)
        .send()
        .await?;
    read_capped(resp, opts.max_body_bytes).await
}

async fn read_capped(
    resp: reqwest::Response,
    max_body_bytes: usize,
) -> Result<SafeResponse, SafeFetchError> {
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let mut body = Vec::new();
    let mut stream = resp;
    while let Some(chunk) = stream.chunk().await? {
        if body.len() + chunk.len() > max_body_bytes {
            return Err(SafeFetchError::BodyTooLarge(max_body_bytes));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(SafeResponse {
        status,
        body,
        final_url,
    })
}

async fn safe_get_inner(
    _client: &SafeHttpClient,
    url: &str,
    opts: &SafeFetchOpts,
) -> Result<SafeResponse, SafeFetchError> {
    let mut current = url.to_string();
    let mut hops: u8 = 0;
    loop {
        let parsed = Url::parse(&current).map_err(|e| SafeFetchError::InvalidUrl(e.to_string()))?;
        match parsed.scheme() {
            "http" | "https" => {}
            other => return Err(SafeFetchError::UnsupportedScheme(other.to_string())),
        }
        let host = parsed.host_str().ok_or(SafeFetchError::MissingHost)?;
        let port = parsed
            .port_or_known_default()
            .ok_or(SafeFetchError::MissingHost)?;
        let pinned = resolve_and_validate(host, port).await?;

        let pinned_client = Client::builder()
            .redirect(redirect::Policy::none())
            .resolve(host, pinned)
            .build()?;

        let resp = pinned_client.get(parsed.clone()).send().await?;
        let status = resp.status();
        if status.is_redirection() {
            if hops >= opts.max_redirects {
                return Err(SafeFetchError::TooManyRedirects(opts.max_redirects));
            }
            let loc = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or(SafeFetchError::BadRedirect)?;
            let next = parsed
                .join(loc)
                .map_err(|e| SafeFetchError::InvalidUrl(e.to_string()))?;
            current = next.to_string();
            hops += 1;
            continue;
        }

        return read_capped(resp, opts.max_body_bytes).await;
    }
}

async fn resolve_and_validate(host: &str, port: u16) -> Result<SocketAddr, SafeFetchError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !is_public_unicast(ip) {
            return Err(SafeFetchError::BlockedAddress(ip));
        }
        return Ok(SocketAddr::new(ip, port));
    }
    let target = format!("{host}:{port}");
    let addrs: Vec<SocketAddr> = lookup_host(&target)
        .await
        .map_err(|e| SafeFetchError::DnsLookup(e.to_string()))?
        .collect();
    if addrs.is_empty() {
        return Err(SafeFetchError::DnsEmpty);
    }
    for a in &addrs {
        if !is_public_unicast(a.ip()) {
            return Err(SafeFetchError::BlockedAddress(a.ip()));
        }
    }
    Ok(addrs[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse().unwrap())
    }

    #[test]
    fn allows_public_v4() {
        assert!(is_public_unicast(v4("8.8.8.8")));
        assert!(is_public_unicast(v4("1.1.1.1")));
        assert!(is_public_unicast(v4("140.82.121.4")));
    }

    #[test]
    fn blocks_unspecified_v4() {
        assert!(!is_public_unicast(v4("0.0.0.0")));
    }

    #[test]
    fn blocks_loopback_v4() {
        assert!(!is_public_unicast(v4("127.0.0.1")));
        assert!(!is_public_unicast(v4("127.255.255.255")));
    }

    #[test]
    fn blocks_rfc1918_v4() {
        assert!(!is_public_unicast(v4("10.0.0.1")));
        assert!(!is_public_unicast(v4("172.16.0.1")));
        assert!(!is_public_unicast(v4("172.31.255.255")));
        assert!(!is_public_unicast(v4("192.168.1.1")));
    }

    #[test]
    fn blocks_link_local_and_metadata_v4() {
        assert!(!is_public_unicast(v4("169.254.0.1")));
        assert!(!is_public_unicast(v4("169.254.169.254")));
    }

    #[test]
    fn blocks_multicast_and_broadcast_v4() {
        assert!(!is_public_unicast(v4("224.0.0.1")));
        assert!(!is_public_unicast(v4("239.255.255.255")));
        assert!(!is_public_unicast(v4("255.255.255.255")));
    }

    #[test]
    fn blocks_reserved_v4() {
        assert!(!is_public_unicast(v4("240.0.0.1")));
        assert!(!is_public_unicast(v4("100.64.0.1")));
        assert!(!is_public_unicast(v4("198.18.0.1")));
        assert!(!is_public_unicast(v4("192.0.2.1")));
        assert!(!is_public_unicast(v4("198.51.100.1")));
    }

    #[test]
    fn allows_public_v6() {
        assert!(is_public_unicast(v6("2001:4860:4860::8888")));
        assert!(is_public_unicast(v6("2606:4700:4700::1111")));
    }

    #[test]
    fn blocks_loopback_v6() {
        assert!(!is_public_unicast(v6("::1")));
    }

    #[test]
    fn blocks_unspecified_v6() {
        assert!(!is_public_unicast(v6("::")));
    }

    #[test]
    fn blocks_ula_v6() {
        assert!(!is_public_unicast(v6("fc00::1")));
        assert!(!is_public_unicast(v6("fd00::1")));
        assert!(!is_public_unicast(v6("fdff:ffff::1")));
    }

    #[test]
    fn blocks_link_local_v6() {
        assert!(!is_public_unicast(v6("fe80::1")));
        assert!(!is_public_unicast(v6("febf::1")));
    }

    #[test]
    fn blocks_multicast_v6() {
        assert!(!is_public_unicast(v6("ff00::1")));
        assert!(!is_public_unicast(v6("ff02::1")));
    }

    #[test]
    fn blocks_documentation_v6() {
        assert!(!is_public_unicast(v6("2001:db8::1")));
    }

    #[test]
    fn blocks_ipv4_mapped_private_v6() {
        assert!(!is_public_unicast(v6("::ffff:10.0.0.1")));
        assert!(!is_public_unicast(v6("::ffff:169.254.169.254")));
        assert!(is_public_unicast(v6("::ffff:8.8.8.8")));
    }

    #[tokio::test]
    async fn rejects_unsupported_scheme() {
        let c = SafeHttpClient::new();
        let err = safe_get(&c, "file:///etc/passwd", &SafeFetchOpts::default())
            .await
            .unwrap_err();
        assert!(matches!(err, SafeFetchError::UnsupportedScheme(_)));
    }

    #[tokio::test]
    async fn post_rejects_unsupported_scheme() {
        let c = SafeHttpClient::new();
        let err = safe_post_form(&c, "file:///etc/passwd", &[], &SafeFetchOpts::default())
            .await
            .unwrap_err();
        assert!(matches!(err, SafeFetchError::UnsupportedScheme(_)));
    }

    #[tokio::test]
    async fn post_rejects_loopback_literal() {
        let c = SafeHttpClient::new();
        let err = safe_post_form(
            &c,
            "http://127.0.0.1/token",
            &[("grant_type", "authorization_code")],
            &SafeFetchOpts::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SafeFetchError::BlockedAddress(_)));
    }

    #[tokio::test]
    async fn post_rejects_the_metadata_endpoint() {
        let c = SafeHttpClient::new();
        let err = safe_post_form(
            &c,
            "http://169.254.169.254/latest/api/token",
            &[],
            &SafeFetchOpts::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SafeFetchError::BlockedAddress(_)));
    }

    #[tokio::test]
    async fn rejects_loopback_literal() {
        let c = SafeHttpClient::new();
        let err = safe_get(&c, "http://127.0.0.1/", &SafeFetchOpts::default())
            .await
            .unwrap_err();
        assert!(matches!(err, SafeFetchError::BlockedAddress(_)));
    }

    #[tokio::test]
    async fn rejects_metadata_literal() {
        let c = SafeHttpClient::new();
        let err = safe_get(
            &c,
            "http://169.254.169.254/latest/meta-data/",
            &SafeFetchOpts::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SafeFetchError::BlockedAddress(_)));
    }
}
