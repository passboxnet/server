//! Website icons (favicons) fetched by the server, so clients never contact
//! the websites in a vault themselves (`GET /api/v1/icons/{domain}`).
//!
//! The server learns which domains its users look at; admins can turn the
//! feature off with `PASSBOX_ICONS=off`. Fetching is locked down against
//! server-side request forgery:
//!
//! - only `https` on the default port, no IP literals, IDNA-validated names;
//! - every resolved address must be public (no loopback, private, link-local,
//!   multicast, unique-local, documentation or other special ranges), checked
//!   in the resolver the HTTP client connects through, so redirects and DNS
//!   rebinding cannot reach internal addresses;
//! - at most 3 redirects, 3 s per request, 200 KB per response, no proxy, no
//!   cookies, and only raster image types whose bytes match their type (SVG
//!   is refused because it can carry scripts).
//!
//! Results, including misses, are cached in memory.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ureq::ResponseExt;

use super::auth::Session;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Largest icon (and homepage head) the server reads.
pub const MAX_ICON_BYTES: u64 = 200 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
/// Upper bound for one lookup with all its candidates.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_REDIRECTS: u32 = 3;
const HIT_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const MISS_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Memory the cache may use for icon bytes.
const CACHE_BYTES: usize = 32 * 1024 * 1024;
/// Icon requests per session and minute.
const RATE_LIMIT: u32 = 600;

/// A fetched icon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icon {
    pub content_type: &'static str,
    pub bytes: Vec<u8>,
}

/// Fetches the icon of a validated domain (blocking; runs on a blocking
/// thread). Tests inject their own implementation.
pub trait IconFetcher: Send + Sync {
    fn fetch(&self, domain: &str) -> Option<Icon>;
}

/// Icon settings, fetcher and cache of a server.
pub struct IconService {
    pub enabled: bool,
    fetcher: Arc<dyn IconFetcher>,
    cache: Mutex<Cache>,
}

#[derive(Default)]
struct Cache {
    entries: HashMap<String, (Instant, Option<Arc<Icon>>)>,
    bytes: usize,
}

impl IconService {
    pub fn new(enabled: bool, fetcher: Arc<dyn IconFetcher>) -> Self {
        Self {
            enabled,
            fetcher,
            cache: Mutex::new(Cache::default()),
        }
    }

    /// The default service: icons on, fetched over HTTPS.
    pub fn http() -> Self {
        Self::new(true, Arc::new(HttpIconFetcher::new()))
    }

    fn cached(&self, domain: &str) -> Option<Option<Arc<Icon>>> {
        let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.entries.get(domain).and_then(|(at, icon)| {
            let ttl = if icon.is_some() { HIT_TTL } else { MISS_TTL };
            (at.elapsed() < ttl).then(|| icon.clone())
        })
    }

    fn store(&self, domain: &str, icon: Option<Arc<Icon>>) {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let size = icon.as_ref().map_or(0, |i| i.bytes.len());
        if cache.bytes + size > CACHE_BYTES || cache.entries.len() > 50_000 {
            // Simple and bounded: start over when full.
            cache.entries.clear();
            cache.bytes = 0;
        }
        if let Some((_, Some(old))) = cache.entries.get(domain) {
            cache.bytes = cache.bytes.saturating_sub(old.bytes.len());
        }
        cache.bytes += size;
        cache
            .entries
            .insert(domain.to_owned(), (Instant::now(), icon));
    }

    /// The icon of `domain` from the cache or the fetcher.
    pub async fn lookup(&self, domain: &str) -> Option<Arc<Icon>> {
        if let Some(cached) = self.cached(domain) {
            return cached;
        }
        let fetcher = self.fetcher.clone();
        let name = domain.to_owned();
        let task = tokio::task::spawn_blocking(move || fetcher.fetch(&name));
        let icon = match tokio::time::timeout(LOOKUP_TIMEOUT, task).await {
            Ok(Ok(icon)) => icon.map(Arc::new),
            _ => None,
        };
        self.store(domain, icon.clone());
        icon
    }
}

/// `GET /api/v1/icons/{domain}`: the website's icon, or 404.
pub async fn get(
    State(state): State<AppState>,
    session: Session,
    Path(domain): Path<String>,
) -> ApiResult<Response> {
    if !state.icons.enabled {
        return Err(ApiError::NotFound);
    }
    if let Some(wait) = state.limiter.hit(
        &format!("icons:{}", session.id),
        RATE_LIMIT,
        Duration::from_secs(60),
    ) {
        return Err(ApiError::RateLimited(wait));
    }
    let domain = normalize_domain(&domain)
        .ok_or_else(|| ApiError::bad_request("not a valid public domain name"))?;
    match state.icons.lookup(&domain).await {
        Some(icon) => {
            let mut response = (StatusCode::OK, icon.bytes.clone()).into_response();
            let headers = response.headers_mut();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(icon.content_type),
            );
            headers.insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("private, max-age=604800"),
            );
            Ok(response)
        }
        None => {
            let mut response = ApiError::NotFound.into_response();
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("private, max-age=86400"),
            );
            Ok(response)
        }
    }
}

// --- Validation -------------------------------------------------------------------

/// Lower-case ASCII (punycode) form of a public DNS name, or `None` for IP
/// literals, ports, single labels and anything that is not a host name.
pub fn normalize_domain(input: &str) -> Option<String> {
    let input = input.trim().trim_end_matches('.');
    if input.is_empty()
        || input.len() > 253
        || input
            .chars()
            .any(|c| c.is_whitespace() || ":/\\@?#%[]".contains(c))
    {
        return None;
    }
    // IDNA (UTS 46) processing turns Unicode names into punycode and
    // rejects invalid punycode labels.
    let host = match url::Host::parse(input).ok()? {
        url::Host::Domain(domain) => domain,
        url::Host::Ipv4(_) | url::Host::Ipv6(_) => return None,
    };
    let labels: Vec<&str> = host.split('.').collect();
    let valid_label = |label: &&str| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if host.len() > 253 || labels.len() < 2 || !labels.iter().all(valid_label) {
        return None;
    }
    // A numeric top-level label would make it look like an address.
    if labels
        .last()
        .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    if host.ends_with(".localhost") || host == "localhost" {
        return None;
    }
    Some(host)
}

/// Whether `ip` is a public unicast address the server may connect to.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0 // "this network"
        || a == 10
        || a == 127
        || (a == 100 && (64..128).contains(&b)) // carrier-grade NAT
        || (a == 169 && b == 254)
        || (a == 172 && (16..32).contains(&b))
        || (a == 192 && b == 0 && c == 0) // IETF protocol assignments
        || (a == 192 && b == 0 && c == 2) // documentation
        || (a == 192 && b == 88 && c == 99) // 6to4 relay
        || (a == 192 && b == 168)
        || (a == 198 && (18..20).contains(&b)) // benchmarking
        || (a == 198 && b == 51 && c == 100) // documentation
        || (a == 203 && b == 0 && c == 113) // documentation
        || a >= 224) // multicast, reserved, broadcast
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    // Addresses that embed an IPv4 address are judged by it (and NAT64 and
    // 6to4 never point inside the server's network legitimately).
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    // Only global unicast (2000::/3) ...
    if segments[0] & 0xe000 != 0x2000 {
        return false;
    }
    // ... without its special-purpose blocks.
    !(segments[0] == 0x2001 && segments[1] < 0x0200 // TEREDO, benchmarking, ORCHID, ...
        || segments[0] == 0x2001 && segments[1] == 0x0db8 // documentation
        || segments[0] == 0x2002) // 6to4
}

// --- HTTP fetcher ------------------------------------------------------------------

/// Resolves names with the system resolver and refuses anything but public
/// addresses on port 443 over HTTPS.
#[derive(Debug, Default)]
pub struct PublicOnlyResolver {
    inner: ureq::unversioned::resolver::DefaultResolver,
}

impl ureq::unversioned::resolver::Resolver for PublicOnlyResolver {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        config: &ureq::config::Config,
        timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        check_uri(uri)?;
        let addresses = self.inner.resolve(uri, config, timeout)?;
        if addresses.is_empty() || addresses.iter().any(|a| !is_public_ip(a.ip())) {
            return Err(ureq::Error::HostNotFound);
        }
        Ok(addresses)
    }
}

/// Only `https://<public domain>[:443]/...`.
fn check_uri(uri: &ureq::http::Uri) -> Result<(), ureq::Error> {
    let refused = || ureq::Error::BadUri("refused by the icon fetcher".into());
    if uri.scheme_str() != Some("https") {
        return Err(refused());
    }
    let authority = uri.authority().ok_or_else(refused)?;
    if authority.port_u16().is_some_and(|port| port != 443) || authority.as_str().contains('@') {
        return Err(refused());
    }
    let host = authority.host();
    if normalize_domain(host).as_deref() != Some(&host.to_ascii_lowercase()) {
        return Err(refused());
    }
    Ok(())
}

/// Fetches icons over HTTPS with `ureq`.
pub struct HttpIconFetcher {
    agent: ureq::Agent,
}

impl Default for HttpIconFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpIconFetcher {
    pub fn new() -> Self {
        let config = ureq::Agent::config_builder()
            .https_only(true)
            .proxy(None)
            .max_redirects(MAX_REDIRECTS)
            .timeout_global(Some(REQUEST_TIMEOUT))
            .http_status_as_error(false)
            .user_agent("Passbox-Icons/1.0")
            .tls_config(
                ureq::tls::TlsConfig::builder()
                    .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                    .build(),
            )
            .build();
        Self {
            agent: ureq::Agent::with_parts(
                config,
                ureq::unversioned::transport::DefaultConnector::default(),
                PublicOnlyResolver::default(),
            ),
        }
    }

    /// GET with an `accept` header; returns the final URL, content type and
    /// body (at most [`MAX_ICON_BYTES`]) of a 200 response.
    fn get(&self, url: &str, accept: &str) -> Option<(String, String, Vec<u8>)> {
        let mut response = self.agent.get(url).header("accept", accept).call().ok()?;
        if response.status() != 200 {
            return None;
        }
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let final_url = response.get_uri().to_string();
        let bytes = response
            .body_mut()
            .with_config()
            .limit(MAX_ICON_BYTES)
            .read_to_vec()
            .ok()?;
        Some((final_url, content_type, bytes))
    }

    fn image(&self, url: &str) -> Option<Icon> {
        let (_, content_type, bytes) = self.get(url, "image/*")?;
        if !content_type.starts_with("image/") {
            return None;
        }
        sniff_image(&bytes).map(|content_type| Icon {
            content_type,
            bytes,
        })
    }
}

impl IconFetcher for HttpIconFetcher {
    fn fetch(&self, domain: &str) -> Option<Icon> {
        let base = format!("https://{domain}");
        if let Some(icon) = self.image(&format!("{base}/apple-touch-icon.png")) {
            return Some(icon);
        }
        if let Some(icon) = self.image(&format!("{base}/favicon.ico")) {
            return Some(icon);
        }
        let (final_url, content_type, html) = self.get(&format!("{base}/"), "text/html")?;
        if !content_type.starts_with("text/html") {
            return None;
        }
        let page = url::Url::parse(&final_url).ok()?;
        icon_links(&String::from_utf8_lossy(&html))
            .into_iter()
            .filter_map(|href| page.join(&href).ok())
            .filter(|url| url.scheme() == "https")
            .take(3)
            .find_map(|url| self.image(url.as_str()))
    }
}

/// The content type of a PNG, ICO, JPEG, GIF or WebP image, by its bytes.
pub fn sniff_image(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(&[0, 0, 1, 0]) {
        Some("image/x-icon")
    } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("image/jpeg")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.len() > 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

/// `href`s of `<link rel="…icon…">` tags in the document head, best first
/// (`apple-touch-icon`, then `icon`).
pub fn icon_links(html: &str) -> Vec<String> {
    // ASCII lower-casing keeps byte offsets, so positions found in `lower`
    // index `html` too.
    let lower = html.to_ascii_lowercase();
    let head_end = lower.find("</head").unwrap_or(lower.len());
    let mut found: Vec<(u8, String)> = Vec::new();
    let mut pos = 0;
    while let Some(offset) = lower[pos..head_end].find("<link") {
        let start = pos + offset;
        let Some(len) = lower[start..].find('>') else {
            break;
        };
        let end = start + len;
        let (tag, original) = (&lower[start..end], &html[start..end]);
        if let (Some(rel), Some(href)) =
            (attribute(tag, tag, "rel"), attribute(tag, original, "href"))
        {
            let rank = if rel.contains("apple-touch-icon") {
                Some(0)
            } else if rel.split_whitespace().any(|r| r == "icon") {
                Some(1)
            } else {
                None
            };
            if let Some(rank) = rank
                && !href.is_empty()
                && !href.starts_with("data:")
            {
                found.push((rank, href.to_owned()));
            }
        }
        pos = end;
        if pos >= head_end {
            break;
        }
    }
    found.sort_by_key(|(rank, _)| *rank);
    found.into_iter().map(|(_, href)| href).collect()
}

/// The value of attribute `name` in a tag. `lower` is the lower-cased tag,
/// `original` the same text in its original case.
fn attribute<'a>(lower: &str, original: &'a str, name: &str) -> Option<&'a str> {
    let bytes = lower.as_bytes();
    let skip_space = |mut i: usize| {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        i
    };
    let mut search = 0;
    while let Some(found) = lower[search..].find(name) {
        let at = search + found;
        search = at + name.len();
        if at == 0 || !bytes[at - 1].is_ascii_whitespace() {
            continue;
        }
        let eq = skip_space(search);
        if bytes.get(eq) != Some(&b'=') {
            continue;
        }
        let i = skip_space(eq + 1);
        let (start, end) = match bytes.get(i) {
            Some(&quote @ (b'"' | b'\'')) => {
                let start = i + 1;
                let end = lower[start..]
                    .find(char::from(quote))
                    .map_or(lower.len(), |e| start + e);
                (start, end)
            }
            Some(_) => {
                let end = lower[i..]
                    .find(|c: char| c.is_ascii_whitespace())
                    .map_or(lower.len(), |e| i + e);
                (i, end)
            }
            None => return None,
        };
        return Some(&original[start..end]);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_validated_and_normalized() {
        assert_eq!(
            normalize_domain("GitHub.com").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            normalize_domain("example.com.").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            normalize_domain("bücher.example").as_deref(),
            Some("xn--bcher-kva.example")
        );
        assert_eq!(
            normalize_domain("xn--bcher-kva.example").as_deref(),
            Some("xn--bcher-kva.example")
        );
        for bad in [
            "",
            "localhost",
            "foo.localhost",
            "intranet",
            "127.0.0.1",
            "2130706433",
            "0x7f.1",
            "[::1]",
            "::1",
            "example.com:8443",
            "user@example.com",
            "example.com/path",
            "-bad.example",
            "a..b",
            "1.2.3.4.5",
            "xn--zz.example",
            "exa mple.com",
        ] {
            assert_eq!(normalize_domain(bad), None, "{bad}");
        }
    }

    #[test]
    fn only_public_addresses_are_allowed() {
        for ok in [
            "93.184.215.14",
            "1.1.1.1",
            "2606:4700::1111",
            "2a00:1450::1",
        ] {
            assert!(is_public_ip(ok.parse().unwrap()), "{ok}");
        }
        for bad in [
            "0.0.0.0",
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fe80::1",
            "fc00::1",
            "fd12:3456::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::7f00:1",
            "2001:db8::1",
            "2002:7f00:1::",
            "2001::1",
        ] {
            assert!(!is_public_ip(bad.parse().unwrap()), "{bad}");
        }
        assert!(is_public_ip("::ffff:8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn resolver_refuses_internal_targets() {
        use ureq::unversioned::resolver::Resolver;
        use ureq::unversioned::transport::NextTimeout;
        let resolver = PublicOnlyResolver::default();
        let config = ureq::config::Config::default();
        for uri in [
            "http://example.com/",
            "https://example.com:8443/",
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://localhost/",
            "https://user@example.com/",
        ] {
            let uri: ureq::http::Uri = uri.parse().unwrap();
            assert!(
                resolver
                    .resolve(&uri, &config, NextTimeout::default())
                    .is_err(),
                "{uri}"
            );
        }
    }

    #[test]
    fn images_are_recognized_by_their_bytes() {
        assert_eq!(sniff_image(b"\x89PNG\r\n\x1a\nrest"), Some("image/png"));
        assert_eq!(sniff_image(&[0, 0, 1, 0, 1]), Some("image/x-icon"));
        assert_eq!(sniff_image(b"RIFF\0\0\0\0WEBPVP8 "), Some("image/webp"));
        assert_eq!(sniff_image(b"<svg xmlns=..."), None);
        assert_eq!(sniff_image(b"<html>"), None);
    }

    #[test]
    fn finds_icon_links_in_the_head() {
        let html = r#"<html><HEAD><meta charset=utf-8>
            <link rel="stylesheet" href="/a.css">
            <link rel="shortcut icon" href="/Fav.ico">
            <link href='https://cdn.example.com/touch.png' rel='apple-touch-icon' sizes="180x180">
            <link rel=icon href=data:image/png;base64,xyz>
            </head><body><link rel="icon" href="/late.png"></body></html>"#;
        assert_eq!(
            icon_links(html),
            ["https://cdn.example.com/touch.png", "/Fav.ico"]
        );
        assert!(icon_links("<html>no links</html>").is_empty());
    }

    struct Counting(std::sync::atomic::AtomicUsize);

    impl IconFetcher for Counting {
        fn fetch(&self, domain: &str) -> Option<Icon> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            (domain == "hit.example").then(|| Icon {
                content_type: "image/png",
                bytes: b"\x89PNG\r\n\x1a\n".to_vec(),
            })
        }
    }

    #[tokio::test]
    async fn hits_and_misses_are_cached() {
        let fetcher = Arc::new(Counting(Default::default()));
        let service = IconService::new(true, fetcher.clone());
        assert!(service.lookup("hit.example").await.is_some());
        assert!(service.lookup("hit.example").await.is_some());
        assert!(service.lookup("miss.example").await.is_none());
        assert!(service.lookup("miss.example").await.is_none());
        assert_eq!(fetcher.0.load(std::sync::atomic::Ordering::SeqCst), 2);
    }
}
