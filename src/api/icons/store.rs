//! The shared icon store (`site_icons`) and its background refresh.
//!
//! Request handlers read and write it in the `icons` context; the refresh
//! job runs on the worker pool in `worker:icons`. Several server processes
//! may share the table: writes are upserts, and the refresh job claims rows
//! (`claimed_until`) with `FOR UPDATE SKIP LOCKED`, so each due icon is
//! refreshed by one process.

use std::time::Duration;

use sha2::{Digest, Sha256};

use super::{
    Fetched, Icon, IconService, RefreshOutcome, Revalidation, Validators, known_content_type,
};
use crate::db::{Db, Job, now_ms};
use crate::state::AppState;

const DAY_MS: i64 = 24 * 60 * 60 * 1000;
/// Icons are checked again after this long.
pub const REFRESH_AFTER_MS: i64 = 30 * DAY_MS;
/// Sites without an icon are tried again after this long.
pub const MISS_RETRY_MS: i64 = 7 * DAY_MS;
/// Entries nobody asked for in this long are removed.
pub const UNUSED_AFTER_MS: i64 = 180 * DAY_MS;
/// `last_requested_at` is written at most this often per icon.
const REQUESTED_RESOLUTION_MS: i64 = DAY_MS;
/// How long a refresh job holds a claimed row.
const CLAIM_MS: i64 = 15 * 60 * 1000;
/// After a failed refresh of an icon, wait this long before the next try.
const FAILURE_BACKOFF_MS: i64 = DAY_MS;
/// Failed refreshes in a row before a stored icon is given up.
const MAX_FAILURES: i32 = 3;
/// How often the refresh job runs, and how many icons it takes each time.
const REFRESH_INTERVAL: Duration = Duration::from_secs(10 * 60);
const REFRESH_BATCH: i64 = 25;
const REFRESH_BATCHES_PER_RUN: usize = 8;

/// The stored answer for `domain`: `Some(Some(icon))` for an icon,
/// `Some(None)` for a known miss, `None` when the store has never looked.
/// Notes that someone asked (at most daily per icon, without who).
pub(super) async fn load(
    db: &Db,
    domain: &str,
    now: i64,
) -> Result<Option<Option<Icon>>, sqlx::Error> {
    let mut tx = db.system(Job::Icons).await?;
    let row = sqlx::query!(
        "SELECT image, content_type FROM site_icons WHERE domain = $1",
        domain
    )
    .fetch_optional(&mut *tx)
    .await?;
    if row.is_some() {
        sqlx::query!(
            "UPDATE site_icons SET last_requested_at = $2 WHERE domain = $1 AND last_requested_at < $3",
            domain,
            now,
            now - REQUESTED_RESOLUTION_MS,
        )
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(row.map(|row| {
        match (
            row.image,
            row.content_type.as_deref().and_then(known_content_type),
        ) {
            (Some(bytes), Some(content_type)) => Some(Icon {
                content_type,
                bytes,
            }),
            _ => None,
        }
    }))
}

/// Stores a fetch result (an icon or a miss) in the request context. A miss
/// never replaces an icon another server stored meanwhile.
pub(super) async fn save(
    db: &Db,
    domain: &str,
    fetched: Option<&Fetched>,
    now: i64,
    requested_at: i64,
) -> Result<(), sqlx::Error> {
    let mut tx = db.system(Job::Icons).await?;
    upsert(&mut tx, domain, fetched, now, requested_at).await?;
    tx.commit().await
}

async fn upsert(
    conn: &mut crate::db::Conn,
    domain: &str,
    fetched: Option<&Fetched>,
    now: i64,
    requested_at: i64,
) -> Result<(), sqlx::Error> {
    let image = fetched.map(|f| f.icon.bytes.as_slice());
    let content_type = fetched.map(|f| f.icon.content_type);
    let sha256 = fetched.map(|f| Sha256::digest(&f.icon.bytes).to_vec());
    let source_url = fetched.and_then(|f| f.source_url.as_deref());
    let etag = fetched.and_then(|f| f.etag.as_deref());
    let last_modified = fetched.and_then(|f| f.last_modified.as_deref());
    let retry_after = fetched.is_none().then_some(now + MISS_RETRY_MS);
    sqlx::query!(
        "INSERT INTO site_icons (domain, image, content_type, sha256, source_url, etag, last_modified, \
             fetched_at, last_requested_at, retry_after, failures, claimed_until) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 0, 0) \
         ON CONFLICT (domain) DO UPDATE SET image = EXCLUDED.image, content_type = EXCLUDED.content_type, \
             sha256 = EXCLUDED.sha256, source_url = EXCLUDED.source_url, etag = EXCLUDED.etag, \
             last_modified = EXCLUDED.last_modified, fetched_at = EXCLUDED.fetched_at, \
             last_requested_at = GREATEST(site_icons.last_requested_at, EXCLUDED.last_requested_at), \
             retry_after = EXCLUDED.retry_after, failures = 0, claimed_until = 0 \
         WHERE EXCLUDED.image IS NOT NULL OR site_icons.image IS NULL",
        domain,
        image,
        content_type,
        sha256,
        source_url,
        etag,
        last_modified,
        now,
        requested_at,
        retry_after,
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// What one refresh run did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RefreshReport {
    pub unchanged: usize,
    pub updated: usize,
    pub missing: usize,
    pub failed: usize,
    /// Entries removed because nobody asked for them in 180 days.
    pub removed: u64,
}

impl RefreshReport {
    fn count(&mut self, outcome: RefreshOutcome) {
        match outcome {
            RefreshOutcome::Unchanged => self.unchanged += 1,
            RefreshOutcome::Updated => self.updated += 1,
            RefreshOutcome::Missing => self.missing += 1,
            RefreshOutcome::Failed => self.failed += 1,
        }
    }

    /// Icons looked at.
    pub fn refreshed(&self) -> usize {
        self.unchanged + self.updated + self.missing + self.failed
    }
}

struct Claimed {
    domain: String,
    hit: bool,
    sha256: Option<Vec<u8>>,
    validators: Option<Validators>,
    failures: i32,
}

/// Refreshes up to `limit` due icons: icons older than 30 days (with a
/// conditional request when the source sent validators) and misses whose
/// 7 days are over, of sites someone asked for in the last 180 days. Also
/// removes entries nobody asked for in 180 days.
pub async fn refresh_due(
    db: &Db,
    icons: &IconService,
    metrics: &super::IconMetrics,
    now: i64,
    limit: i64,
) -> Result<RefreshReport, sqlx::Error> {
    let mut report = RefreshReport::default();
    let mut tx = db.system(Job::IconRefresh).await?;
    report.removed = sqlx::query!(
        "DELETE FROM site_icons WHERE last_requested_at < $1",
        now - UNUSED_AFTER_MS
    )
    .execute(&mut *tx)
    .await?
    .rows_affected();
    let claimed: Vec<Claimed> = sqlx::query!(
        r#"UPDATE site_icons SET claimed_until = $2
           WHERE domain IN (
               SELECT domain FROM site_icons
               WHERE claimed_until < $1
                 AND ((image IS NOT NULL AND fetched_at < $3) OR (image IS NULL AND retry_after <= $1))
               ORDER BY last_requested_at DESC
               LIMIT $4
               FOR UPDATE SKIP LOCKED)
           RETURNING domain, image IS NOT NULL AS "hit!", sha256, source_url, etag, last_modified, failures"#,
        now,
        now + CLAIM_MS,
        now - REFRESH_AFTER_MS,
        limit,
    )
    .fetch_all(&mut *tx)
    .await?
    .into_iter()
    .map(|row| Claimed {
        domain: row.domain,
        hit: row.hit,
        sha256: row.sha256,
        validators: row.source_url.map(|source_url| Validators {
            source_url,
            etag: row.etag,
            last_modified: row.last_modified,
        }),
        failures: row.failures,
    })
    .collect();
    tx.commit().await?;

    for entry in claimed {
        let outcome = refresh_one(db, icons, &entry, now).await?;
        if outcome == RefreshOutcome::Updated || outcome == RefreshOutcome::Missing {
            icons.forget(&entry.domain);
        }
        metrics.record_refresh(outcome);
        report.count(outcome);
    }
    Ok(report)
}

async fn refresh_one(
    db: &Db,
    icons: &IconService,
    entry: &Claimed,
    now: i64,
) -> Result<RefreshOutcome, sqlx::Error> {
    // A stored icon with a source: ask whether it changed.
    let mut fetched: Option<Option<Fetched>> = None;
    if entry.hit
        && let Some(validators) = entry.validators.clone()
    {
        match icons
            .run_fetcher(move |fetcher| fetcher.revalidate(&validators))
            .await
        {
            Some(Revalidation::NotModified) => {
                let mut tx = db.system(Job::IconRefresh).await?;
                sqlx::query!(
                    "UPDATE site_icons SET fetched_at = $2, failures = 0, claimed_until = 0 WHERE domain = $1",
                    entry.domain,
                    now,
                )
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
                return Ok(RefreshOutcome::Unchanged);
            }
            Some(Revalidation::Changed(new)) => fetched = Some(Some(new)),
            Some(Revalidation::Unavailable) | None => {}
        }
    }
    let fetched = match fetched {
        Some(found) => found,
        None => {
            let domain = entry.domain.clone();
            match icons
                .run_fetcher(move |fetcher| fetcher.fetch_with_source(&domain))
                .await
            {
                Some(found) => found,
                // Too slow: counts as a failure, not as "no icon".
                None => return failed(db, entry, now).await,
            }
        }
    };
    let mut tx = db.system(Job::IconRefresh).await?;
    let outcome = match &fetched {
        Some(new) => {
            let same = entry.sha256.as_deref() == Some(Sha256::digest(&new.icon.bytes).as_slice());
            upsert(&mut tx, &entry.domain, Some(new), now, 0).await?;
            if same {
                RefreshOutcome::Unchanged
            } else {
                RefreshOutcome::Updated
            }
        }
        None if entry.hit && entry.failures + 1 < MAX_FAILURES => {
            drop(tx);
            return failed(db, entry, now).await;
        }
        None => {
            // A miss again, or an icon that failed too often: a miss now.
            sqlx::query!(
                "UPDATE site_icons SET image = NULL, content_type = NULL, sha256 = NULL, source_url = NULL, \
                     etag = NULL, last_modified = NULL, fetched_at = $2, retry_after = $3, failures = 0, \
                     claimed_until = 0 \
                 WHERE domain = $1",
                entry.domain,
                now,
                now + MISS_RETRY_MS,
            )
            .execute(&mut *tx)
            .await?;
            RefreshOutcome::Missing
        }
    };
    tx.commit().await?;
    Ok(outcome)
}

/// A refresh that did not get an answer: keep what is stored, try again
/// later.
async fn failed(db: &Db, entry: &Claimed, now: i64) -> Result<RefreshOutcome, sqlx::Error> {
    let mut tx = db.system(Job::IconRefresh).await?;
    sqlx::query!(
        "UPDATE site_icons SET failures = failures + 1, claimed_until = $2 WHERE domain = $1",
        entry.domain,
        now + FAILURE_BACKOFF_MS,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(RefreshOutcome::Failed)
}

/// Starts the background refresh of stored icons (every 10 minutes, a few
/// hundred icons at most). Does nothing while icons are turned off.
pub fn spawn_refresher(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(REFRESH_INTERVAL);
        // The first tick fires at once; let the server start first.
        interval.tick().await;
        loop {
            interval.tick().await;
            if !state.icons.enabled {
                continue;
            }
            let mut total = RefreshReport::default();
            for _ in 0..REFRESH_BATCHES_PER_RUN {
                match refresh_due(
                    &state.db,
                    &state.icons,
                    &state.metrics.icons,
                    now_ms(),
                    REFRESH_BATCH,
                )
                .await
                {
                    Ok(report) => {
                        total.unchanged += report.unchanged;
                        total.updated += report.updated;
                        total.missing += report.missing;
                        total.failed += report.failed;
                        total.removed += report.removed;
                        if report.refreshed() < usize::try_from(REFRESH_BATCH).unwrap_or(0) {
                            break;
                        }
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "website icon refresh failed");
                        break;
                    }
                }
            }
            if total.refreshed() > 0 || total.removed > 0 {
                // Counts only: no domains in the log.
                tracing::info!(
                    unchanged = total.unchanged,
                    updated = total.updated,
                    missing = total.missing,
                    failed = total.failed,
                    removed = total.removed,
                    "refreshed website icons"
                );
            }
        }
    });
}
