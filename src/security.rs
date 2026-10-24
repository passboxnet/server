//! HTTP hardening: security headers, client IP detection and rate limiting.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, FromRequestParts, Request};
use axum::http::request::Parts;
use axum::http::{HeaderName, HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;

use crate::state::AppState;

/// Content Security Policy for the web vault. Scripts only from the server
/// itself (plus WebAssembly), no framing, no plugins. `connect-src` allows
/// other HTTPS servers because the web client can talk to a server on
/// another origin and checks breached passwords with Have I Been Pwned.
const CSP: &str = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; \
    style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; \
    connect-src 'self' https: http://localhost:* http://127.0.0.1:*; \
    frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'";

/// Adds security headers to every response. API responses are never cached.
pub async fn security_headers(request: Request, next: Next) -> Response {
    let is_api = request.uri().path().starts_with("/api/");
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    // Handlers that allow caching (website icons) set their own header.
    let cacheable = headers.contains_key(header::CACHE_CONTROL);
    let mut set = |name: HeaderName, value: &'static str| {
        headers.insert(name, HeaderValue::from_static(value));
    };
    set(header::CONTENT_SECURITY_POLICY, CSP);
    set(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(header::X_FRAME_OPTIONS, "DENY");
    set(header::REFERRER_POLICY, "no-referrer");
    // Ignored by browsers on plain HTTP, effective once served over HTTPS.
    set(header::STRICT_TRANSPORT_SECURITY, "max-age=31536000");
    set(
        HeaderName::from_static("permissions-policy"),
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    );
    set(
        HeaderName::from_static("cross-origin-opener-policy"),
        "same-origin",
    );
    if is_api && !cacheable {
        set(header::CACHE_CONTROL, "no-store");
    }
    response
}

/// The client's IP address: the socket peer, or the first address of
/// `X-Forwarded-For` when the server runs behind a trusted reverse proxy
/// (`PASSBOX_TRUST_PROXY`). `"unknown"` if neither is available (tests).
pub struct ClientIp(pub String);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        if state.trust_proxy
            && let Some(forwarded) = parts
                .headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
                .map(str::trim)
                .filter(|v| !v.is_empty() && v.len() <= 64)
        {
            return Ok(Self(forwarded.to_owned()));
        }
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map_or_else(|| "unknown".to_owned(), |c| c.0.ip().to_string());
        Ok(Self(peer))
    }
}

/// Fixed-window rate limiter kept in memory. Limits are per server process,
/// which is enough to slow down online guessing and abuse; the Secret Key
/// already makes guessing a password online infeasible.
pub struct RateLimiter {
    windows: Mutex<HashMap<String, (Instant, u32)>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
        }
    }
}

impl RateLimiter {
    /// Counts one event for `key` and returns how long to wait if the limit
    /// of `max` events per `window` is exceeded.
    pub fn hit(&self, key: &str, max: u32, window: Duration) -> Option<Duration> {
        let now = Instant::now();
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if windows.len() > 100_000 {
            windows.retain(|_, (start, _)| now.duration_since(*start) < Duration::from_secs(3600));
        }
        let entry = windows.entry(key.to_owned()).or_insert((now, 0));
        if now.duration_since(entry.0) >= window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        (entry.1 > max).then(|| window.saturating_sub(now.duration_since(entry.0)))
    }

    /// Returns the remaining wait for `key` without counting an event.
    pub fn blocked(&self, key: &str, max: u32, window: Duration) -> Option<Duration> {
        let now = Instant::now();
        let windows = self
            .windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        windows.get(key).and_then(|(start, count)| {
            let elapsed = now.duration_since(*start);
            (elapsed < window && *count >= max).then(|| window - elapsed)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limiter_blocks_after_max_hits() {
        let limiter = RateLimiter::default();
        let window = Duration::from_secs(60);
        for _ in 0..3 {
            assert!(limiter.hit("k", 3, window).is_none());
        }
        assert!(limiter.blocked("k", 3, window).is_some());
        assert!(limiter.hit("k", 3, window).is_some());
        assert!(limiter.hit("other", 3, window).is_none());
    }

    #[test]
    fn limiter_resets_after_window() {
        let limiter = RateLimiter::default();
        let window = Duration::from_millis(20);
        assert!(limiter.hit("k", 1, window).is_none());
        assert!(limiter.hit("k", 1, window).is_some());
        std::thread::sleep(Duration::from_millis(30));
        assert!(limiter.hit("k", 1, window).is_none());
    }
}
