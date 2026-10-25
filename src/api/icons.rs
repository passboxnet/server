//! Website icons (favicons) fetched by the server, so clients never contact
//! the websites in a vault themselves (`GET /api/v1/icons/{domain}`).
//!
//! Lookups go through three tiers, and every icon is fetched once per
//! instance, not once per user (docs/architecture/item-extras.md):
//!
//! 1. **memory** of this server process (hours),
//! 2. **the database**: `site_icons`, shared by all users and all server
//!    processes of the instance (migration 0003); refreshed in the
//!    background by [`spawn_refresher`] after 30 days, with conditional
//!    requests (`If-None-Match`, `If-Modified-Since`), misses after 7 days,
//! 3. **a fetch** from the website, stored in the database for everyone.
//!
//! Clients ship the icons of the most popular sites (`packages/site-icons`)
//! and ask the server only for the others. The store keeps no account,
//! session or address: the lookup runs in the `icons` database context, not
//! as the account, and request logs show `/api/v1/icons/{domain}` instead
//! of the domain (`routes::loggable_uri`). Admins can turn the feature off
//! with `PASSBOX_ICONS=off`.
//!
//! Fetching is locked down against server-side request forgery:
//!
//! - only `https` on the default port, no IP literals, IDNA-validated names;
//! - every resolved address must be public (no loopback, private, link-local,
//!   multicast, unique-local, documentation or other special ranges), checked
//!   in the resolver the HTTP client connects through, so DNS rebinding
//!   cannot reach internal addresses; redirects are followed by hand and
//!   every hop is checked the same way;
//! - at most 3 redirects, 3 s per request, 200 KB per response, no proxy, no
//!   cookies, and only raster image types whose bytes match their type (SVG
//!   is refused because it can carry scripts).

mod fetch;
mod store;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

pub use self::fetch::{
    HttpIconFetcher, PublicOnlyResolver, icon_links, is_public_ip, normalize_domain, sniff_image,
};
pub use self::store::{RefreshReport, refresh_due, spawn_refresher};
use super::auth::Session;
use crate::db::Db;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Largest icon (and homepage head) the server reads.
pub const MAX_ICON_BYTES: u64 = 200 * 1024;
/// Upper bound for one lookup with all its candidates.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(8);
/// How long this process answers from memory before asking the database
/// again (other servers may have refreshed the icon meanwhile).
const MEMORY_HIT_TTL: Duration = Duration::from_secs(6 * 60 * 60);
const MEMORY_MISS_TTL: Duration = Duration::from_secs(60 * 60);
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

/// An icon with where it came from, for conditional refreshes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    pub icon: Icon,
    /// The final URL of the image (after redirects).
    pub source_url: Option<String>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

impl From<Icon> for Fetched {
    fn from(icon: Icon) -> Self {
        Self {
            icon,
            source_url: None,
            etag: None,
            last_modified: None,
        }
    }
}

/// What the store knows about a stored icon's source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validators {
    pub source_url: String,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

/// The answer to a conditional request for a stored icon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Revalidation {
    /// `304 Not Modified`: keep the stored icon.
    NotModified,
    /// The source sent a new image.
    Changed(Fetched),
    /// The source gave no usable image: look for the icon from scratch.
    Unavailable,
}

/// Fetches the icon of a validated domain (blocking; runs on a blocking
/// thread). Tests inject their own implementation.
pub trait IconFetcher: Send + Sync {
    fn fetch(&self, domain: &str) -> Option<Icon>;

    /// [`fetch`](Self::fetch) with the source and its validators.
    fn fetch_with_source(&self, domain: &str) -> Option<Fetched> {
        self.fetch(domain).map(Fetched::from)
    }

    /// Asks the source of a stored icon whether it changed.
    fn revalidate(&self, _validators: &Validators) -> Revalidation {
        Revalidation::Unavailable
    }
}

/// Which tier answered a lookup (a label of the `/metrics` counters).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Memory,
    Database,
    Fetch,
}

impl Tier {
    const ALL: [Tier; 3] = [Tier::Memory, Tier::Database, Tier::Fetch];

    fn label(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Database => "db",
            Self::Fetch => "fetch",
        }
    }
}

/// Results of a background refresh of one icon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// The website sent the same icon (or `304 Not Modified`).
    Unchanged,
    /// A new icon replaced the stored one (or a miss found one).
    Updated,
    /// Still no icon, or the icon is gone after repeated failures.
    Missing,
    /// The website could not be reached; the stored icon stays for now.
    Failed,
}

impl RefreshOutcome {
    const ALL: [RefreshOutcome; 4] = [
        RefreshOutcome::Unchanged,
        RefreshOutcome::Updated,
        RefreshOutcome::Missing,
        RefreshOutcome::Failed,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::Updated => "updated",
            Self::Missing => "missing",
            Self::Failed => "failed",
        }
    }
}

/// Icon counters for `/metrics`. Labels are fixed; no domain ever appears.
#[derive(Default)]
pub struct IconMetrics {
    /// By tier, then hit (0) or miss (1).
    lookups: [[AtomicU64; 2]; 3],
    refreshes: [AtomicU64; 4],
}

impl IconMetrics {
    pub fn record(&self, tier: Tier, hit: bool) {
        let index = Tier::ALL.iter().position(|t| *t == tier).unwrap_or(0);
        self.lookups[index][usize::from(!hit)].fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_refresh(&self, outcome: RefreshOutcome) {
        let index = RefreshOutcome::ALL
            .iter()
            .position(|o| *o == outcome)
            .unwrap_or(0);
        self.refreshes[index].fetch_add(1, Ordering::Relaxed);
    }

    /// Lookups answered by `tier` (hits and misses).
    pub fn lookups(&self, tier: Tier, hit: bool) -> u64 {
        let index = Tier::ALL.iter().position(|t| *t == tier).unwrap_or(0);
        self.lookups[index][usize::from(!hit)].load(Ordering::Relaxed)
    }

    /// The Prometheus text of the counters.
    pub fn render(&self, out: &mut String) {
        use std::fmt::Write as _;
        out.push_str(
            "# HELP passbox_icon_lookups_total Website icon lookups by the tier that answered \
             (memory, db, fetch) and result.\n\
             # TYPE passbox_icon_lookups_total counter\n",
        );
        for tier in Tier::ALL {
            for hit in [true, false] {
                let _ = writeln!(
                    out,
                    "passbox_icon_lookups_total{{tier=\"{}\",result=\"{}\"}} {}",
                    tier.label(),
                    if hit { "hit" } else { "miss" },
                    self.lookups(tier, hit)
                );
            }
        }
        out.push_str(
            "# HELP passbox_icon_refreshes_total Background refreshes of stored website icons by outcome.\n\
             # TYPE passbox_icon_refreshes_total counter\n",
        );
        for (outcome, count) in RefreshOutcome::ALL.iter().zip(&self.refreshes) {
            let _ = writeln!(
                out,
                "passbox_icon_refreshes_total{{outcome=\"{}\"}} {}",
                outcome.label(),
                count.load(Ordering::Relaxed)
            );
        }
    }
}

/// Icon settings, fetcher and memory cache of a server process.
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
            let ttl = if icon.is_some() {
                MEMORY_HIT_TTL
            } else {
                MEMORY_MISS_TTL
            };
            (at.elapsed() < ttl).then(|| icon.clone())
        })
    }

    fn remember(&self, domain: &str, icon: Option<Arc<Icon>>) {
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

    /// Drops `domain` from this process's memory (after a refresh).
    fn forget(&self, domain: &str) {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((_, Some(old))) = cache.entries.remove(domain) {
            cache.bytes = cache.bytes.saturating_sub(old.bytes.len());
        }
    }

    /// Runs the fetcher on a blocking thread. `None` when it took too long.
    async fn run_fetcher<T: Send + 'static>(
        &self,
        work: impl FnOnce(&dyn IconFetcher) -> T + Send + 'static,
    ) -> Option<T> {
        let fetcher = self.fetcher.clone();
        let task = tokio::task::spawn_blocking(move || work(&*fetcher));
        match tokio::time::timeout(LOOKUP_TIMEOUT, task).await {
            Ok(Ok(result)) => Some(result),
            _ => None,
        }
    }

    /// The icon of a validated `domain`: from memory, the shared store, or
    /// the website (then stored for everyone). Database errors are logged
    /// (without the domain) and the lookup goes on without the store.
    pub async fn lookup(&self, db: &Db, domain: &str) -> (Option<Arc<Icon>>, Tier) {
        if let Some(cached) = self.cached(domain) {
            return (cached, Tier::Memory);
        }
        let now = crate::db::now_ms();
        match store::load(db, domain, now).await {
            Ok(Some(stored)) => {
                let icon = stored.map(Arc::new);
                self.remember(domain, icon.clone());
                return (icon, Tier::Database);
            }
            Ok(None) => {}
            Err(err) => tracing::warn!(error = %err, "could not read the website icon store"),
        }
        let name = domain.to_owned();
        let Some(fetched) = self
            .run_fetcher(move |fetcher| fetcher.fetch_with_source(&name))
            .await
        else {
            // Too slow this time: not stored, so the next request tries again
            // after the memory entry expires.
            self.remember(domain, None);
            return (None, Tier::Fetch);
        };
        if let Err(err) = store::save(db, domain, fetched.as_ref(), now, now).await {
            tracing::warn!(error = %err, "could not store a website icon");
        }
        let icon = fetched.map(|fetched| Arc::new(fetched.icon));
        self.remember(domain, icon.clone());
        (icon, Tier::Fetch)
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
    // The session only authorizes and rate limits the request. The lookup
    // below neither knows nor records who asked.
    drop(session);
    let domain = normalize_domain(&domain)
        .ok_or_else(|| ApiError::bad_request("not a valid public domain name"))?;
    let (icon, tier) = state.icons.lookup(&state.db, &domain).await;
    state.metrics.icons.record(tier, icon.is_some());
    match icon {
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

/// The static content type of a stored icon.
fn known_content_type(value: &str) -> Option<&'static str> {
    [
        "image/png",
        "image/x-icon",
        "image/jpeg",
        "image/gif",
        "image/webp",
    ]
    .into_iter()
    .find(|known| *known == value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_have_fixed_labels() {
        let metrics = IconMetrics::default();
        metrics.record(Tier::Database, true);
        metrics.record(Tier::Fetch, false);
        metrics.record_refresh(RefreshOutcome::Unchanged);
        let mut out = String::new();
        metrics.render(&mut out);
        assert!(out.contains(r#"passbox_icon_lookups_total{tier="db",result="hit"} 1"#));
        assert!(out.contains(r#"passbox_icon_lookups_total{tier="fetch",result="miss"} 1"#));
        assert!(out.contains(r#"passbox_icon_lookups_total{tier="memory",result="hit"} 0"#));
        assert!(out.contains(r#"passbox_icon_refreshes_total{outcome="unchanged"} 1"#));
        assert_eq!(out.matches("passbox_icon_lookups_total{").count(), 6);
    }

    #[test]
    fn content_types_round_trip() {
        for bytes in [
            b"\x89PNG\r\n\x1a\n".as_slice(),
            &[0, 0, 1, 0, 1],
            b"RIFF\0\0\0\0WEBPVP8 ",
        ] {
            let sniffed = sniff_image(bytes).unwrap();
            assert_eq!(known_content_type(sniffed), Some(sniffed));
        }
        assert_eq!(known_content_type("image/svg+xml"), None);
    }
}
