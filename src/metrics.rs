//! Prometheus metrics (`GET /metrics` on `PASSBOX_METRICS_BIND`).
//!
//! Labels never carry tenant data: requests are counted by route class (the
//! first path segment of the API, from a fixed list) and status class,
//! never by path, account, organization or IP.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::db::{Db, now_ms};

/// Upper bounds of the latency buckets, in seconds.
const BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Route classes: the first segment after `/api/v1/`. Anything else counts
/// as `other`, so clients cannot create new label values.
const API_CLASSES: &[&str] = &[
    "access-requests",
    "account",
    "admin",
    "agent-events",
    "agent-grants",
    "agent-limit",
    "attachments",
    "auth",
    "breach",
    "device-links",
    "emergency",
    "icons",
    "invitations",
    "items",
    "keys",
    "meta",
    "org-events",
    "orgs",
    "public",
    "recovery",
    "scim",
    "service-account",
    "service-accounts",
    "sessions",
    "share-links",
    "sso",
    "sync",
    "vaults",
];

#[derive(Default)]
struct Series {
    count: u64,
    sum: f64,
    buckets: [u64; BUCKETS.len()],
}

/// Request counters, shared by all requests.
#[derive(Default)]
pub struct Metrics {
    requests: Mutex<BTreeMap<(&'static str, &'static str), Series>>,
    /// Website icon lookups by tier and background refreshes.
    pub icons: crate::api::icons::IconMetrics,
}

/// The route class of a request path.
pub fn route_class(path: &str) -> &'static str {
    if let Some(rest) = path.strip_prefix("/api/v1/") {
        let first = rest.split('/').next().unwrap_or_default();
        return API_CLASSES
            .iter()
            .copied()
            .find(|class| *class == first)
            .unwrap_or("other");
    }
    match path {
        "/health" | "/ready" => "health",
        _ => "web",
    }
}

fn status_class(status: StatusCode) -> &'static str {
    match status.as_u16() {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        _ => "5xx",
    }
}

impl Metrics {
    fn record(&self, class: &'static str, status: StatusCode, seconds: f64) {
        let mut requests = self
            .requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let series = requests.entry((class, status_class(status))).or_default();
        series.count += 1;
        series.sum += seconds;
        for (bucket, bound) in series.buckets.iter_mut().zip(BUCKETS) {
            if seconds <= bound {
                *bucket += 1;
            }
        }
    }

    /// The Prometheus text exposition of all metrics.
    pub async fn render(&self, db: &Db) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "# HELP passbox_build_info Version of the running server.\n\
             # TYPE passbox_build_info gauge\n\
             passbox_build_info{{version=\"{}\"}} 1",
            env!("CARGO_PKG_VERSION")
        );
        self.render_requests(&mut out);
        self.icons.render(&mut out);
        out.push_str(
            "# HELP passbox_db_pool_connections Open database connections per pool and state.\n\
             # TYPE passbox_db_pool_connections gauge\n",
        );
        for (pool, size, idle) in db.pool_stats() {
            let idle = u32::try_from(idle).unwrap_or(u32::MAX).min(size);
            let _ = writeln!(
                out,
                "passbox_db_pool_connections{{pool=\"{pool}\",state=\"idle\"}} {idle}\n\
                 passbox_db_pool_connections{{pool=\"{pool}\",state=\"in_use\"}} {}",
                size - idle
            );
        }
        let ready = db.readiness().await.is_ok();
        let _ = writeln!(
            out,
            "# HELP passbox_db_ready Whether the database answers and is migrated.\n\
             # TYPE passbox_db_ready gauge\n\
             passbox_db_ready {}",
            u8::from(ready)
        );
        match queue_depths(db).await {
            Ok((mail_pending, mail_failed, webhooks_due)) => {
                let _ = writeln!(
                    out,
                    "# HELP passbox_job_queue_depth Jobs waiting per queue.\n\
                     # TYPE passbox_job_queue_depth gauge\n\
                     passbox_job_queue_depth{{queue=\"mail\",state=\"pending\"}} {mail_pending}\n\
                     passbox_job_queue_depth{{queue=\"mail\",state=\"failed\"}} {mail_failed}\n\
                     passbox_job_queue_depth{{queue=\"webhooks\",state=\"due\"}} {webhooks_due}"
                );
            }
            Err(err) => tracing::warn!(error = %err, "could not read queue depths for metrics"),
        }
        out
    }

    fn render_requests(&self, out: &mut String) {
        let requests = self
            .requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        out.push_str(
            "# HELP passbox_http_requests_total HTTP requests by route class and status class.\n\
             # TYPE passbox_http_requests_total counter\n",
        );
        for ((class, status), series) in requests.iter() {
            let _ = writeln!(
                out,
                "passbox_http_requests_total{{class=\"{class}\",status=\"{status}\"}} {}",
                series.count
            );
        }
        out.push_str(
            "# HELP passbox_http_request_duration_seconds HTTP request latency by route class.\n\
             # TYPE passbox_http_request_duration_seconds histogram\n",
        );
        let mut by_class: BTreeMap<&str, Series> = BTreeMap::new();
        for ((class, _), series) in requests.iter() {
            let total = by_class.entry(class).or_default();
            total.count += series.count;
            total.sum += series.sum;
            for (sum, bucket) in total.buckets.iter_mut().zip(series.buckets) {
                *sum += bucket;
            }
        }
        for (class, series) in &by_class {
            for (bound, bucket) in BUCKETS.iter().zip(series.buckets) {
                let _ = writeln!(
                    out,
                    "passbox_http_request_duration_seconds_bucket{{class=\"{class}\",le=\"{bound}\"}} {bucket}"
                );
            }
            let _ = writeln!(
                out,
                "passbox_http_request_duration_seconds_bucket{{class=\"{class}\",le=\"+Inf\"}} {count}\n\
                 passbox_http_request_duration_seconds_sum{{class=\"{class}\"}} {sum}\n\
                 passbox_http_request_duration_seconds_count{{class=\"{class}\"}} {count}",
                count = series.count,
                sum = series.sum,
            );
        }
    }
}

async fn queue_depths(db: &Db) -> anyhow::Result<(i64, i64, i64)> {
    let mut tx = db.system(crate::db::Job::Metrics).await?;
    let row = sqlx::query!(
        r#"SELECT mail_pending AS "mail_pending!", mail_failed AS "mail_failed!",
                  webhooks_due AS "webhooks_due!"
           FROM passbox.queue_depths($1)"#,
        now_ms()
    )
    .fetch_one(&mut *tx)
    .await?;
    Ok((row.mail_pending, row.mail_failed, row.webhooks_due))
}

/// Middleware that counts every request.
pub async fn track(State(metrics): State<Arc<Metrics>>, request: Request, next: Next) -> Response {
    let class = route_class(request.uri().path());
    let started = Instant::now();
    let response = next.run(request).await;
    metrics.record(class, response.status(), started.elapsed().as_secs_f64());
    response
}

/// The `/metrics` endpoint on its own listener.
pub fn router(metrics: Arc<Metrics>, db: Db) -> axum::Router {
    axum::Router::new().route(
        "/metrics",
        axum::routing::get(move || {
            let metrics = metrics.clone();
            let db = db.clone();
            async move {
                (
                    [(
                        header::CONTENT_TYPE,
                        "text/plain; version=0.0.4; charset=utf-8",
                    )],
                    metrics.render(&db).await,
                )
                    .into_response()
            }
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_classes_are_bounded() {
        assert_eq!(route_class("/api/v1/items/0123"), "items");
        assert_eq!(route_class("/api/v1/auth/login/start"), "auth");
        assert_eq!(route_class("/api/v1/someone@example.com"), "other");
        assert_eq!(route_class("/health"), "health");
        assert_eq!(route_class("/vault/settings"), "web");
    }

    #[test]
    fn requests_are_counted_by_class_and_status() {
        let metrics = Metrics::default();
        metrics.record("items", StatusCode::OK, 0.02);
        metrics.record("items", StatusCode::CONFLICT, 0.2);
        let mut out = String::new();
        metrics.render_requests(&mut out);
        assert!(out.contains(r#"passbox_http_requests_total{class="items",status="2xx"} 1"#));
        assert!(out.contains(r#"passbox_http_requests_total{class="items",status="4xx"} 1"#));
        assert!(out.contains(
            r#"passbox_http_request_duration_seconds_bucket{class="items",le="0.025"} 1"#
        ));
        assert!(out.contains(r#"passbox_http_request_duration_seconds_count{class="items"} 2"#));
    }
}
