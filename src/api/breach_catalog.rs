//! The breach catalogue ("compromised websites"): Have I Been Pwned's public
//! list of breached sites, refreshed by a background job and served to
//! clients as one cacheable document.
//!
//! - **Worker** (`worker:breach_catalog`): every `PASSBOX_BREACH_CATALOG_HOURS`
//!   (default 6) one server instance fetches
//!   `https://haveibeenpwned.com/api/v3/breaches` (no API key; sends
//!   `If-None-Match` when the last response had an `ETag`) and stores every
//!   entry with its flags in `site_breaches` (migration 0004).
//! - **`GET /api/v1/breaches/catalog`**: the entries clients match against
//!   (a domain, not fabricated, not a spam list, not retired) with only the
//!   fields they need, as JSON (gzip when accepted) with a strong `ETag`
//!   and `Cache-Control: public, no-cache`. Before the first successful
//!   fetch it serves the snapshot bundled with the server.
//! - **`GET /api/v1/breaches/catalog/version`**: version and date only, for
//!   clients that check often.
//!
//! The same document goes to everyone, without authentication: the server
//! never learns which sites a user has logins for. Matching happens on the
//! device (`passbox_core::analysis::breaches`). `PASSBOX_BREACH_CATALOG=off`
//! turns the job and both endpoints off; clients then use their bundled
//! snapshot. The data is CC BY 4.0, Have I Been Pwned is named as the source
//! in the document and in every UI that shows it.

use std::collections::BTreeSet;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use data_encoding::HEXLOWER;
use passbox_core::analysis::breaches::{self, BreachCatalog, SiteBreach};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::db::{Job, Public, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Have I Been Pwned's list of all breaches.
pub const DEFAULT_CATALOG_URL: &str = "https://haveibeenpwned.com/api/v3/breaches";
const USER_AGENT: &str = concat!(
    "Passbox-Server/",
    env!("CARGO_PKG_VERSION"),
    " (breach catalogue)"
);
/// How long a served document is reused before the stored version is
/// compared again (other server instances may have refreshed it).
const RECHECK: Duration = Duration::from_secs(30);
/// Retry delay after a failed fetch.
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(30 * 60);
const MAX_BODY: u64 = 32 * 1024 * 1024;

/// One entry of Have I Been Pwned's breach model.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct UpstreamBreach {
    pub name: String,
    pub title: String,
    pub domain: String,
    pub breach_date: String,
    pub added_date: String,
    pub modified_date: String,
    pub pwn_count: i64,
    pub data_classes: Vec<String>,
    pub is_verified: bool,
    pub is_fabricated: bool,
    pub is_sensitive: bool,
    pub is_retired: bool,
    pub is_spam_list: bool,
}

/// What a fetch returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetched {
    /// `304 Not Modified` for the validator that was sent.
    NotModified,
    /// The full list, with the response's `ETag` if it had one.
    Body { body: String, etag: Option<String> },
}

/// Reaches Have I Been Pwned (blocking; runs on a blocking thread). Tests
/// inject their own.
pub trait CatalogUpstream: Send + Sync {
    fn fetch(&self, etag: Option<&str>) -> Result<Fetched, String>;
}

/// [`CatalogUpstream`] over HTTPS.
pub struct HttpCatalogUpstream {
    agent: ureq::Agent,
    url: String,
}

impl HttpCatalogUpstream {
    pub fn new(url: &str) -> Self {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(60)))
            .max_redirects(0)
            .user_agent(USER_AGENT)
            .build();
        Self {
            agent: config.into(),
            url: url.to_owned(),
        }
    }
}

impl CatalogUpstream for HttpCatalogUpstream {
    fn fetch(&self, etag: Option<&str>) -> Result<Fetched, String> {
        let mut request = self
            .agent
            .get(&self.url)
            .header("accept", "application/json");
        if let Some(etag) = etag.filter(|e| !e.is_empty()) {
            request = request.header("if-none-match", etag);
        }
        let mut response = request.call().map_err(|e| e.to_string())?;
        match response.status().as_u16() {
            200 => {
                let etag = response
                    .headers()
                    .get("etag")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
                let body = response
                    .body_mut()
                    .with_config()
                    .limit(MAX_BODY)
                    .read_to_string()
                    .map_err(|e| e.to_string())?;
                Ok(Fetched::Body { body, etag })
            }
            304 => Ok(Fetched::NotModified),
            429 => Err("Have I Been Pwned asks to slow down (429)".into()),
            status => Err(format!("Have I Been Pwned answered with status {status}")),
        }
    }
}

/// A document ready to send.
struct Served {
    version: String,
    updated_at: i64,
    entries: usize,
    bundled: bool,
    /// Strong validator: `"<version>"`.
    etag: String,
    json: Vec<u8>,
    gzip: Vec<u8>,
}

/// Settings, upstream and the served document.
pub struct CatalogService {
    /// `PASSBOX_BREACH_CATALOG`.
    pub enabled: bool,
    /// `PASSBOX_BREACH_CATALOG_HOURS`.
    pub interval: Duration,
    upstream: Arc<dyn CatalogUpstream>,
    /// The document and when its version was last compared.
    served: Mutex<Option<(Arc<Served>, Instant)>>,
}

impl CatalogService {
    pub fn new(enabled: bool, upstream: Arc<dyn CatalogUpstream>) -> Self {
        Self {
            enabled,
            interval: Duration::from_secs(6 * 60 * 60),
            upstream,
            served: Mutex::new(None),
        }
    }

    /// The default: on, real Have I Been Pwned.
    pub fn http() -> Self {
        Self::new(
            true,
            Arc::new(HttpCatalogUpstream::new(DEFAULT_CATALOG_URL)),
        )
    }

    fn cached(&self) -> Option<(Arc<Served>, Instant)> {
        self.served
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn store(&self, served: Arc<Served>) {
        *self.served.lock().unwrap_or_else(|e| e.into_inner()) = Some((served, Instant::now()));
    }

    /// Forgets the served document (tests, after a refresh).
    pub fn invalidate(&self) {
        *self.served.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

/// The entries clients get, in their compact form.
fn client_entry(row: &UpstreamBreach) -> Option<SiteBreach> {
    let domain = row.domain.trim().to_lowercase();
    if !breaches::include_in_catalog(&domain, row.is_fabricated, row.is_spam_list, row.is_retired) {
        return None;
    }
    Some(SiteBreach {
        name: row.name.clone(),
        title: if row.title.trim().is_empty() {
            row.name.clone()
        } else {
            row.title.clone()
        },
        domain,
        breach_date: row.breach_date.clone(),
        added_date: row.added_date.clone(),
        modified_date: row.modified_date.clone(),
        pwn_count: u64::try_from(row.pwn_count).unwrap_or(0),
        data_classes: row.data_classes.clone(),
        verified: row.is_verified,
        sensitive: row.is_sensitive,
    })
}

/// Version of a list of entries: a hash of their canonical JSON.
fn version_of(entries: &[SiteBreach]) -> String {
    let json = serde_json::to_vec(entries).unwrap_or_default();
    let hash = Sha256::digest(&json);
    HEXLOWER.encode(&hash[..12])
}

fn document(entries: Vec<SiteBreach>, version: String, updated_at: i64) -> BreachCatalog {
    BreachCatalog {
        version,
        updated_at,
        source: breaches::SOURCE_NAME.into(),
        source_url: breaches::SOURCE_URL.into(),
        license: breaches::SOURCE_LICENSE.into(),
        breaches: entries,
    }
}

fn served(catalog: &BreachCatalog, bundled: bool) -> anyhow::Result<Served> {
    let json = serde_json::to_vec(catalog)?;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(&json)?;
    let gzip = encoder.finish()?;
    Ok(Served {
        version: catalog.version.clone(),
        updated_at: catalog.updated_at,
        entries: catalog.breaches.len(),
        bundled,
        etag: format!("\"{}\"", catalog.version),
        json,
        gzip,
    })
}

/// The current document: from memory, rebuilt from the database when its
/// stored version changed, or the bundled snapshot before the first fetch.
async fn current(state: &AppState) -> anyhow::Result<Arc<Served>> {
    let service = &state.breach_catalog;
    let cached = service.cached();
    if let Some((served, checked)) = &cached {
        if checked.elapsed() < RECHECK {
            return Ok(served.clone());
        }
    }
    let cached = cached.map(|(served, _)| served);
    let mut tx = state.db.public(Public::BreachCatalog).await?;
    let stored = sqlx::query!("SELECT version, updated_at FROM site_breach_catalog WHERE id = 1")
        .fetch_optional(&mut *tx)
        .await?;
    let Some(stored) = stored.filter(|s| !s.version.is_empty()) else {
        drop(tx);
        if let Some(served) = cached.filter(|s| s.bundled) {
            service.store(served.clone());
            return Ok(served);
        }
        let served = Arc::new(served(breaches::bundled(), true)?);
        service.store(served.clone());
        return Ok(served);
    };
    if let Some(served) = cached.filter(|s| s.version == stored.version) {
        service.store(served.clone());
        return Ok(served);
    }
    let rows = sqlx::query!(
        "SELECT name, title, domain, breach_date, added_date, modified_date, pwn_count, data_classes, \
         is_verified, is_sensitive FROM site_breaches \
         WHERE domain <> '' AND NOT is_fabricated AND NOT is_spam_list AND NOT is_retired \
         ORDER BY name"
    )
    .fetch_all(&mut *tx)
    .await?;
    drop(tx);
    let entries: Vec<SiteBreach> = rows
        .into_iter()
        .map(|row| SiteBreach {
            name: row.name,
            title: row.title,
            domain: row.domain,
            breach_date: row.breach_date,
            added_date: breaches::datetime_string(row.added_date),
            modified_date: breaches::datetime_string(row.modified_date),
            pwn_count: u64::try_from(row.pwn_count).unwrap_or(0),
            data_classes: serde_json::from_value(row.data_classes).unwrap_or_default(),
            verified: row.is_verified,
            sensitive: row.is_sensitive,
        })
        .collect();
    let catalog = document(entries, stored.version, stored.updated_at);
    let served = Arc::new(served(&catalog, false)?);
    service.store(served.clone());
    Ok(served)
}

fn not_found_if_off(state: &AppState) -> ApiResult<()> {
    if state.breach_catalog.enabled {
        Ok(())
    } else {
        Err(ApiError::NotFound)
    }
}

fn header_value(value: &str) -> HeaderValue {
    HeaderValue::from_str(value).unwrap_or_else(|_| HeaderValue::from_static("\"\""))
}

fn matches_etag(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|v| v.trim().trim_start_matches("W/"))
        .any(|v| v == etag || v == "*")
}

/// `GET /api/v1/breaches/catalog`: the catalogue document.
pub async fn catalog(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    not_found_if_off(&state)?;
    let served = current(&state).await?;
    let etag = header_value(&served.etag);
    let cache = HeaderValue::from_static("public, no-cache");
    if matches_etag(&headers, &served.etag) {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        response.headers_mut().insert(header::ETAG, etag);
        response.headers_mut().insert(header::CACHE_CONTROL, cache);
        return Ok(response);
    }
    let gzip = headers
        .get_all(header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| {
            v.split(',').any(|part| {
                let mut part = part.split(';');
                part.next().is_some_and(|c| c.trim() == "gzip")
                    && !part.any(|q| q.trim().replace(' ', "") == "q=0")
            })
        });
    let body = if gzip {
        served.gzip.clone()
    } else {
        served.json.clone()
    };
    let mut response = (StatusCode::OK, body).into_response();
    let h = response.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    h.insert(header::ETAG, etag);
    h.insert(header::CACHE_CONTROL, cache);
    h.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    if gzip {
        h.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    }
    Ok(response)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogVersion {
    version: String,
    /// Newest added or modified date of the entries (Unix ms).
    updated_at: i64,
    entries: usize,
    /// No fetch succeeded yet: the server serves its bundled snapshot.
    bundled: bool,
    source: &'static str,
    source_url: &'static str,
    license: &'static str,
}

/// `GET /api/v1/breaches/catalog/version`: what the catalogue currently is.
pub async fn version(State(state): State<AppState>) -> ApiResult<Response> {
    not_found_if_off(&state)?;
    let served = current(&state).await?;
    let mut response = Json(CatalogVersion {
        version: served.version.clone(),
        updated_at: served.updated_at,
        entries: served.entries,
        bundled: served.bundled,
        source: breaches::SOURCE_NAME,
        source_url: breaches::SOURCE_URL,
        license: breaches::SOURCE_LICENSE,
    })
    .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    Ok(response)
}

/// What [`refresh`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refresh {
    /// Not due yet (another instance fetched recently).
    NotDue,
    /// Upstream had nothing new.
    Unchanged,
    /// A new version was stored.
    Updated { version: String, entries: usize },
}

/// Fetches the catalogue if it is due (or `force`), stores changed entries
/// and the new version. Safe to run on several server instances: the state
/// row is claimed before fetching, so only one of them fetches per interval.
pub async fn refresh(state: &AppState, force: bool) -> anyhow::Result<Refresh> {
    let service = state.breach_catalog.clone();
    let now = now_ms();
    let interval_ms = i64::try_from(service.interval.as_millis()).unwrap_or(i64::MAX);
    // Claim the attempt.
    let mut tx = state.db.system(Job::BreachCatalog).await?;
    sqlx::query!(
        "INSERT INTO site_breach_catalog (id, version, updated_at, entries, etag, fetched_at, checked_at, error) \
         VALUES (1, '', 0, 0, '', 0, 0, '') ON CONFLICT (id) DO NOTHING"
    )
    .execute(&mut *tx)
    .await?;
    let row = sqlx::query!(
        "SELECT version, etag, checked_at, fetched_at, error FROM site_breach_catalog WHERE id = 1 FOR UPDATE"
    )
    .fetch_one(&mut *tx)
    .await?;
    let wait = if row.error.is_empty() {
        interval_ms
    } else {
        interval_ms.min(RETRY_AFTER_FAILURE.as_millis() as i64)
    };
    if !force && row.checked_at > 0 && now - row.checked_at < wait {
        return Ok(Refresh::NotDue);
    }
    sqlx::query!(
        "UPDATE site_breach_catalog SET checked_at = $1 WHERE id = 1",
        now
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let upstream = service.upstream.clone();
    // Without stored entries a validator would only produce a 304.
    let etag = Some(row.etag).filter(|e| !e.is_empty() && !row.version.is_empty());
    let fetched = tokio::task::spawn_blocking(move || upstream.fetch(etag.as_deref()))
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let failed = |message: String| async move {
        let mut tx = state.db.system(Job::BreachCatalog).await?;
        let message: String = message.chars().take(500).collect();
        sqlx::query!(
            "UPDATE site_breach_catalog SET error = $1 WHERE id = 1",
            &message
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        anyhow::Ok(())
    };
    let (body, etag) = match fetched {
        Ok(Fetched::NotModified) => {
            let mut tx = state.db.system(Job::BreachCatalog).await?;
            sqlx::query!(
                "UPDATE site_breach_catalog SET fetched_at = $1, error = '' WHERE id = 1",
                now
            )
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(Refresh::Unchanged);
        }
        Ok(Fetched::Body { body, etag }) => (body, etag.unwrap_or_default()),
        Err(message) => {
            failed(message.clone()).await?;
            anyhow::bail!("breach catalogue fetch failed: {message}");
        }
    };
    let upstream_rows: Vec<UpstreamBreach> = match serde_json::from_str(&body) {
        Ok(rows) => rows,
        Err(err) => {
            failed(format!(
                "Have I Been Pwned sent an unexpected answer: {err}"
            ))
            .await?;
            anyhow::bail!("breach catalogue could not be parsed: {err}");
        }
    };
    // Rows the database would refuse are skipped, not fatal.
    let mut seen = BTreeSet::new();
    let upstream_rows: Vec<UpstreamBreach> = upstream_rows
        .into_iter()
        .filter(|b| {
            let date_ok = b.breach_date.is_empty()
                || (b.breach_date.len() == 10 && breaches::parse_date_ms(&b.breach_date).is_some());
            !b.name.trim().is_empty()
                && b.name.len() <= 200
                && b.title.len() <= 300
                && b.domain.trim().len() <= 253
                && b.data_classes.len() <= 200
                && date_ok
                && seen.insert(b.name.clone())
        })
        .collect();
    if upstream_rows.is_empty() {
        failed("Have I Been Pwned sent an empty list".into()).await?;
        anyhow::bail!("breach catalogue was empty");
    }
    let entries: Vec<SiteBreach> = {
        let mut entries: Vec<SiteBreach> = upstream_rows.iter().filter_map(client_entry).collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        entries
    };
    let version = version_of(&entries);
    let updated_at = BreachCatalog::newest_change(&entries);

    let mut tx = state.db.system(Job::BreachCatalog).await?;
    if version != row.version {
        let names: Vec<String> = upstream_rows.iter().map(|b| b.name.clone()).collect();
        sqlx::query!(
            "DELETE FROM site_breaches WHERE NOT (name = ANY($1))",
            &names
        )
        .execute(&mut *tx)
        .await?;
        for b in &upstream_rows {
            sqlx::query!(
                "INSERT INTO site_breaches (name, title, domain, breach_date, added_date, modified_date, \
                 pwn_count, data_classes, is_verified, is_sensitive, is_spam_list, is_fabricated, is_retired, \
                 updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
                 ON CONFLICT (name) DO UPDATE SET title = excluded.title, domain = excluded.domain, \
                 breach_date = excluded.breach_date, added_date = excluded.added_date, \
                 modified_date = excluded.modified_date, pwn_count = excluded.pwn_count, \
                 data_classes = excluded.data_classes, is_verified = excluded.is_verified, \
                 is_sensitive = excluded.is_sensitive, is_spam_list = excluded.is_spam_list, \
                 is_fabricated = excluded.is_fabricated, is_retired = excluded.is_retired, \
                 updated_at = excluded.updated_at \
                 WHERE (site_breaches.title, site_breaches.domain, site_breaches.breach_date, \
                 site_breaches.added_date, site_breaches.modified_date, site_breaches.pwn_count, \
                 site_breaches.data_classes, site_breaches.is_verified, site_breaches.is_sensitive, \
                 site_breaches.is_spam_list, site_breaches.is_fabricated, site_breaches.is_retired) \
                 IS DISTINCT FROM (excluded.title, excluded.domain, excluded.breach_date, \
                 excluded.added_date, excluded.modified_date, excluded.pwn_count, excluded.data_classes, \
                 excluded.is_verified, excluded.is_sensitive, excluded.is_spam_list, excluded.is_fabricated, \
                 excluded.is_retired)",
                &b.name,
                if b.title.trim().is_empty() { &b.name } else { &b.title },
                b.domain.trim().to_lowercase(),
                &b.breach_date,
                breaches::parse_date_ms(&b.added_date).unwrap_or(0).max(0),
                breaches::parse_date_ms(&b.modified_date).unwrap_or(0).max(0),
                b.pwn_count.max(0),
                serde_json::to_value(&b.data_classes)?,
                b.is_verified,
                b.is_sensitive,
                b.is_spam_list,
                b.is_fabricated,
                b.is_retired,
                now,
            )
            .execute(&mut *tx)
            .await?;
        }
    }
    sqlx::query!(
        "UPDATE site_breach_catalog SET version = $1, updated_at = $2, entries = $3, etag = $4, \
         fetched_at = $5, error = '' WHERE id = 1",
        &version,
        updated_at,
        entries.len() as i64,
        etag.chars().take(500).collect::<String>(),
        now,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    if version == row.version {
        return Ok(Refresh::Unchanged);
    }
    service.invalidate();
    tracing::info!(version, entries = entries.len(), "breach catalogue updated");
    Ok(Refresh::Updated {
        version,
        entries: entries.len(),
    })
}

/// Runs [`refresh`] in the background. A few minutes after start, then
/// every few minutes it checks whether a fetch is due.
pub fn spawn_worker(state: AppState) {
    if !state.breach_catalog.enabled {
        return;
    }
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(20)).await;
        loop {
            if let Err(err) = refresh(&state, false).await {
                tracing::warn!(error = ?err, "breach catalogue refresh failed");
            }
            tokio::time::sleep(Duration::from_secs(10 * 60)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_and_compacts_entries() {
        let row = UpstreamBreach {
            name: "Adobe".into(),
            title: String::new(),
            domain: "Adobe.com ".into(),
            is_verified: true,
            pwn_count: -1,
            ..UpstreamBreach::default()
        };
        let entry = client_entry(&row).unwrap();
        assert_eq!(entry.domain, "adobe.com");
        assert_eq!(entry.title, "Adobe");
        assert_eq!(entry.pwn_count, 0);
        assert!(entry.verified);
        for excluded in [
            UpstreamBreach {
                is_spam_list: true,
                ..row.clone()
            },
            UpstreamBreach {
                is_fabricated: true,
                ..row.clone()
            },
            UpstreamBreach {
                is_retired: true,
                ..row.clone()
            },
            UpstreamBreach {
                domain: String::new(),
                ..row.clone()
            },
        ] {
            assert!(client_entry(&excluded).is_none());
        }
    }

    #[test]
    fn versions_change_with_the_content() {
        let a = vec![SiteBreach {
            name: "A".into(),
            ..SiteBreach::default()
        }];
        let mut b = a.clone();
        assert_eq!(version_of(&a), version_of(&b));
        b[0].pwn_count = 1;
        assert_ne!(version_of(&a), version_of(&b));
    }

    #[test]
    fn reads_if_none_match() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::IF_NONE_MATCH,
            HeaderValue::from_static("W/\"x\", \"abc\""),
        );
        assert!(matches_etag(&headers, "\"abc\""));
        assert!(!matches_etag(&headers, "\"abd\""));
    }
}
