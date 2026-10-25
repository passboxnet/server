//! Fetching website icons over HTTPS, locked down against server-side
//! request forgery (see the parent module).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

use axum::http::header;

use super::{Fetched, Icon, IconFetcher, MAX_ICON_BYTES, Revalidation, Validators};

const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const MAX_REDIRECTS: u32 = 3;
/// Longest validator headers kept for conditional refreshes.
const MAX_ETAG: usize = 512;
const MAX_LAST_MODIFIED: usize = 128;
const MAX_SOURCE_URL: usize = 2048;

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
// --- HTTP fetcher ------------------------------------------------------------------

/// Resolves names with the system resolver and refuses anything but public
/// addresses on port 443 over HTTPS. With an outbound proxy (only the icon
/// bundle generator uses one) the proxy's own address is resolved without
/// these checks; the fetcher then checks every target itself.
#[derive(Debug, Default)]
pub struct PublicOnlyResolver {
    inner: ureq::unversioned::resolver::DefaultResolver,
    /// `host:port` of the outbound proxy, if any.
    proxy: Option<String>,
}

impl ureq::unversioned::resolver::Resolver for PublicOnlyResolver {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        config: &ureq::config::Config,
        timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        if let (Some(proxy), Some(authority)) = (&self.proxy, uri.authority())
            && authority.as_str() == proxy
        {
            return self.inner.resolve(uri, config, timeout);
        }
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

/// The same rules for a parsed URL: every redirect hop is checked before it
/// is requested.
fn allowed_url(url: &url::Url) -> bool {
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none_or(|port| port == 443)
        && url
            .host_str()
            .is_some_and(|host| normalize_domain(host).as_deref() == Some(host))
}

/// Whether every address of `host` is public. Used with a proxy, where the
/// proxy connects and the resolver above never sees the target.
fn resolves_to_public(host: &str) -> bool {
    match (host, 443).to_socket_addrs() {
        Ok(addresses) => {
            let addresses: Vec<_> = addresses.collect();
            !addresses.is_empty() && addresses.iter().all(|a| is_public_ip(a.ip()))
        }
        Err(_) => false,
    }
}

/// A 200 or 304 answer.
struct Answer {
    url: url::Url,
    status: u16,
    content_type: String,
    etag: Option<String>,
    last_modified: Option<String>,
    bytes: Vec<u8>,
}

/// What a request for an image gave.
enum ImageAnswer {
    Image(Fetched),
    NotModified,
}

/// Fetches icons over HTTPS with `ureq`.
pub struct HttpIconFetcher {
    agent: ureq::Agent,
    proxied: bool,
}

impl Default for HttpIconFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpIconFetcher {
    /// The server's fetcher: direct connections only.
    pub fn new() -> Self {
        Self::build(None, PublicOnlyResolver::default())
    }

    /// A fetcher that connects through an HTTP proxy, for
    /// `scripts/update-site-icons.mjs` on machines without direct access.
    /// The same URL, redirect, size and type rules apply, and every host
    /// (also of each redirect) must resolve to public addresses with the
    /// system resolver before it is requested. The server never uses one.
    pub fn with_proxy(proxy: &str) -> anyhow::Result<Self> {
        let parsed = ureq::Proxy::new(proxy)?;
        let authority = format!("{}:{}", parsed.host(), parsed.port());
        Ok(Self::build(
            Some(parsed),
            PublicOnlyResolver {
                inner: Default::default(),
                proxy: Some(authority),
            },
        ))
    }

    fn build(proxy: Option<ureq::Proxy>, resolver: PublicOnlyResolver) -> Self {
        let proxied = proxy.is_some();
        let config = ureq::Agent::config_builder()
            // The proxy itself is reached over plain HTTP (CONNECT); every
            // target is checked to be https by `allowed_url`.
            .https_only(!proxied)
            .proxy(proxy)
            // Redirects are followed by hand, so every hop is checked.
            .max_redirects(0)
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
                resolver,
            ),
            proxied,
        }
    }

    /// GET with an `accept` header (and validators for a conditional
    /// request), following at most [`MAX_REDIRECTS`] checked redirects.
    /// Returns a 200 answer with its body (at most [`MAX_ICON_BYTES`]) or a
    /// 304 answer.
    fn get(&self, url: &str, accept: &str, validators: Option<&Validators>) -> Option<Answer> {
        let mut current = url::Url::parse(url).ok()?;
        for _ in 0..=MAX_REDIRECTS {
            if !allowed_url(&current) || (self.proxied && !resolves_to_public(current.host_str()?))
            {
                return None;
            }
            let mut request = self.agent.get(current.as_str()).header("accept", accept);
            if let Some(validators) = validators {
                if let Some(etag) = &validators.etag {
                    request = request.header("if-none-match", etag);
                }
                if let Some(modified) = &validators.last_modified {
                    request = request.header("if-modified-since", modified);
                }
            }
            let mut response = request.call().ok()?;
            let status = response.status().as_u16();
            let text_header = |name: header::HeaderName, max: usize| {
                response
                    .headers()
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(str::trim)
                    .filter(|v| !v.is_empty() && v.len() <= max)
                    .map(str::to_owned)
            };
            match status {
                301 | 302 | 303 | 307 | 308 => {
                    let location = text_header(header::LOCATION, MAX_SOURCE_URL)?;
                    current = current.join(&location).ok()?;
                }
                200 | 304 => {
                    let content_type = text_header(header::CONTENT_TYPE, 256)
                        .unwrap_or_default()
                        .to_ascii_lowercase();
                    let etag = text_header(header::ETAG, MAX_ETAG);
                    let last_modified = text_header(header::LAST_MODIFIED, MAX_LAST_MODIFIED);
                    let bytes = if status == 200 {
                        response
                            .body_mut()
                            .with_config()
                            .limit(MAX_ICON_BYTES)
                            .read_to_vec()
                            .ok()?
                    } else {
                        Vec::new()
                    };
                    return Some(Answer {
                        url: current,
                        status,
                        content_type,
                        etag,
                        last_modified,
                        bytes,
                    });
                }
                _ => return None,
            }
        }
        None
    }

    fn image(&self, url: &str, validators: Option<&Validators>) -> Option<ImageAnswer> {
        let answer = self.get(url, "image/*", validators)?;
        if answer.status == 304 {
            return validators.map(|_| ImageAnswer::NotModified);
        }
        if !answer.content_type.starts_with("image/") {
            return None;
        }
        let content_type = sniff_image(&answer.bytes)?;
        let source_url = answer.url.as_str();
        Some(ImageAnswer::Image(Fetched {
            icon: Icon {
                content_type,
                bytes: answer.bytes,
            },
            source_url: (source_url.len() <= MAX_SOURCE_URL).then(|| source_url.to_owned()),
            etag: answer.etag,
            last_modified: answer.last_modified,
        }))
    }

    /// An image without validators.
    fn fresh_image(&self, url: &str) -> Option<Fetched> {
        match self.image(url, None)? {
            ImageAnswer::Image(fetched) => Some(fetched),
            ImageAnswer::NotModified => None,
        }
    }
}

impl IconFetcher for HttpIconFetcher {
    fn fetch(&self, domain: &str) -> Option<Icon> {
        self.fetch_with_source(domain).map(|fetched| fetched.icon)
    }

    fn fetch_with_source(&self, domain: &str) -> Option<Fetched> {
        let base = format!("https://{domain}");
        if let Some(icon) = self.fresh_image(&format!("{base}/apple-touch-icon.png")) {
            return Some(icon);
        }
        if let Some(icon) = self.fresh_image(&format!("{base}/favicon.ico")) {
            return Some(icon);
        }
        let page = self.get(&format!("{base}/"), "text/html", None)?;
        if page.status != 200 || !page.content_type.starts_with("text/html") {
            return None;
        }
        icon_links(&String::from_utf8_lossy(&page.bytes))
            .into_iter()
            .filter_map(|href| page.url.join(&href).ok())
            .filter(|url| url.scheme() == "https")
            .take(3)
            .find_map(|url| self.fresh_image(url.as_str()))
    }

    fn revalidate(&self, validators: &Validators) -> Revalidation {
        let conditional = validators.etag.is_some() || validators.last_modified.is_some();
        match self.image(&validators.source_url, conditional.then_some(validators)) {
            Some(ImageAnswer::NotModified) => Revalidation::NotModified,
            Some(ImageAnswer::Image(fetched)) => Revalidation::Changed(fetched),
            None => Revalidation::Unavailable,
        }
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
    fn redirect_targets_are_checked() {
        for ok in [
            "https://example.com/favicon.ico",
            "https://cdn.example.com:443/a.png",
        ] {
            assert!(allowed_url(&url::Url::parse(ok).unwrap()), "{ok}");
        }
        for bad in [
            "http://example.com/",
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://localhost/",
            "https://example.com:8443/",
            "https://user:pw@example.com/",
            "https://intranet/",
            "ftp://example.com/",
        ] {
            assert!(!allowed_url(&url::Url::parse(bad).unwrap()), "{bad}");
        }
    }

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
}
