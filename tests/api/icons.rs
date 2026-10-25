//! The shared website icon store: tiers, upserts from several servers,
//! negative caching, the background refresh, its row level security and
//! what request logs show.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use passbox_server::api::icons::{
    Fetched, Icon, IconFetcher, IconMetrics, IconService, Revalidation, Tier, Validators,
    refresh_due,
};
use passbox_server::db::now_ms;
use passbox_server::testing::TestDatabase;
use sqlx::{Connection, PgConnection};
use tower::ServiceExt;

use super::{Member, TestServer};

const DAY: i64 = 24 * 60 * 60 * 1000;

fn png(tag: &str) -> Icon {
    let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
    bytes.extend_from_slice(tag.as_bytes());
    Icon {
        content_type: "image/png",
        bytes,
    }
}

/// A website stand-in: icons by domain, a conditional-request answer, and
/// counters for what the server asked.
#[derive(Default)]
struct Sites {
    icons: Mutex<HashMap<String, Icon>>,
    revalidation: Mutex<Option<Revalidation>>,
    fetches: AtomicUsize,
    revalidations: AtomicUsize,
}

impl Sites {
    fn set(&self, domain: &str, icon: Option<Icon>) {
        let mut icons = self.icons.lock().unwrap();
        match icon {
            Some(icon) => icons.insert(domain.to_owned(), icon),
            None => icons.remove(domain),
        };
    }

    fn fetches(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }
}

/// `Arc<Sites>` as a fetcher (the service needs an owned `Arc<dyn …>`).
struct Fake(Arc<Sites>);

impl IconFetcher for Fake {
    fn fetch(&self, domain: &str) -> Option<Icon> {
        self.fetch_with_source(domain).map(|f| f.icon)
    }

    fn fetch_with_source(&self, domain: &str) -> Option<Fetched> {
        self.0.fetches.fetch_add(1, Ordering::SeqCst);
        let icon = self.0.icons.lock().unwrap().get(domain).cloned()?;
        Some(Fetched {
            icon,
            source_url: Some(format!("https://{domain}/apple-touch-icon.png")),
            etag: Some("\"v1\"".into()),
            last_modified: None,
        })
    }

    fn revalidate(&self, validators: &Validators) -> Revalidation {
        self.0.revalidations.fetch_add(1, Ordering::SeqCst);
        assert!(validators.source_url.starts_with("https://"));
        assert_eq!(validators.etag.as_deref(), Some("\"v1\""));
        self.0
            .revalidation
            .lock()
            .unwrap()
            .clone()
            .unwrap_or(Revalidation::Unavailable)
    }
}

fn service(sites: &Arc<Sites>) -> IconService {
    IconService::new(true, Arc::new(Fake(sites.clone())))
}

async fn row(
    server: &TestServer,
    domain: &str,
) -> Option<(Option<Vec<u8>>, i64, Option<i64>, i32)> {
    sqlx::query_as(
        "SELECT image, fetched_at, retry_after, failures FROM site_icons WHERE domain = $1",
    )
    .bind(domain)
    .fetch_optional(server.db())
    .await
    .unwrap()
}

async fn set(server: &TestServer, sql: &str, domain: &str, value: i64) {
    sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(domain)
        .bind(value)
        .execute(server.db())
        .await
        .unwrap();
}

pub async fn shared_store(server: &TestServer, database: &TestDatabase) {
    let db = server.pools();
    // Earlier tests stored icons too; start from an empty store.
    sqlx::query("DELETE FROM site_icons")
        .execute(server.db())
        .await
        .unwrap();
    let sites = Arc::new(Sites::default());
    sites.set("hit.example", Some(png("one")));

    // First server: fetched once, then from memory.
    let first = service(&sites);
    let (icon, tier) = first.lookup(db, "hit.example").await;
    assert_eq!(
        (icon.unwrap().bytes.clone(), tier),
        (png("one").bytes, Tier::Fetch)
    );
    let (icon, tier) = first.lookup(db, "hit.example").await;
    assert!(icon.is_some());
    assert_eq!(tier, Tier::Memory);
    assert_eq!(sites.fetches(), 1);

    // Another server (or a restart): from the database, not the website.
    let second = service(&sites);
    let (icon, tier) = second.lookup(db, "hit.example").await;
    assert_eq!(
        (icon.unwrap().bytes.clone(), tier),
        (png("one").bytes, Tier::Database)
    );
    assert_eq!(sites.fetches(), 1);

    // Misses are stored for 7 days and shared too.
    let now = now_ms();
    let (icon, tier) = first.lookup(db, "miss.example").await;
    assert_eq!((icon, tier), (None, Tier::Fetch));
    let (icon, tier) = second.lookup(db, "miss.example").await;
    assert_eq!((icon, tier), (None, Tier::Database));
    assert_eq!(sites.fetches(), 2);
    let (image, _, retry_after, _) = row(server, "miss.example").await.unwrap();
    assert!(image.is_none());
    let retry_after = retry_after.unwrap();
    assert!(retry_after >= now + 7 * DAY && retry_after < now + 7 * DAY + 60_000);

    // Two servers fetching the same new site at once: both upsert, one row.
    sites.set("race.example", Some(png("race")));
    let (one, two) = (service(&sites), service(&sites));
    let (a, b) = tokio::join!(
        one.lookup(db, "race.example"),
        two.lookup(db, "race.example")
    );
    assert!(a.0.is_some() && b.0.is_some());
    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM site_icons WHERE domain = 'race.example'")
            .fetch_one(server.db())
            .await
            .unwrap();
    assert_eq!(rows, 1);

    // The table has nothing that could tie a lookup to an account.
    let columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name::text FROM information_schema.columns WHERE table_name = 'site_icons'",
    )
    .fetch_all(server.db())
    .await
    .unwrap();
    for column in &columns {
        for forbidden in ["account", "session", "org", "user", "ip", "device"] {
            assert!(!column.contains(forbidden), "site_icons.{column}");
        }
    }

    refresh(server, &sites).await;
    policies(server, database).await;
}

async fn refresh(server: &TestServer, sites: &Arc<Sites>) {
    let db = server.pools();
    let metrics = IconMetrics::default();
    let worker = service(sites);
    let now = now_ms();

    // Nothing is due yet.
    let report = refresh_due(db, &worker, &metrics, now, 50).await.unwrap();
    assert_eq!(report.refreshed(), 0);

    // After 30 days: a conditional request; 304 keeps the icon.
    let later = now + 31 * DAY;
    *sites.revalidation.lock().unwrap() = Some(Revalidation::NotModified);
    let report = refresh_due(db, &worker, &metrics, later, 50).await.unwrap();
    // hit.example and race.example are checked with their validators; the
    // miss is tried again (its 7 days are over), still without an icon.
    assert_eq!((report.unchanged, report.missing), (2, 1), "{report:?}");
    assert_eq!(sites.revalidations.load(Ordering::SeqCst), 2);
    let (_, _, retry_after, _) = row(server, "miss.example").await.unwrap();
    assert_eq!(retry_after, Some(later + 7 * DAY));
    let fetches = sites.fetches();
    let (image, fetched_at, _, _) = row(server, "hit.example").await.unwrap();
    assert_eq!(image.unwrap(), png("one").bytes);
    assert_eq!(fetched_at, later);
    // Refreshed rows are not due again.
    let report = refresh_due(db, &worker, &metrics, later, 50).await.unwrap();
    assert_eq!(report.refreshed(), 0);

    // A changed icon replaces the stored one, for every server.
    let much_later = later + 31 * DAY;
    set(
        server,
        "UPDATE site_icons SET last_requested_at = $2 WHERE domain = $1",
        "race.example",
        much_later,
    )
    .await;
    set(
        server,
        "UPDATE site_icons SET last_requested_at = $2 WHERE domain = $1",
        "hit.example",
        much_later,
    )
    .await;
    set(
        server,
        "UPDATE site_icons SET last_requested_at = $2 WHERE domain = $1",
        "miss.example",
        much_later,
    )
    .await;
    *sites.revalidation.lock().unwrap() = Some(Revalidation::Changed(Fetched {
        icon: png("two"),
        source_url: Some("https://hit.example/apple-touch-icon.png".into()),
        etag: Some("\"v1\"".into()),
        last_modified: None,
    }));
    // The miss is due as well now: the site has an icon meanwhile.
    sites.set("miss.example", Some(png("found")));
    let report = refresh_due(db, &worker, &metrics, much_later, 50)
        .await
        .unwrap();
    assert_eq!(report.updated, 3, "{report:?}");
    assert_eq!(
        sites.fetches(),
        fetches + 1,
        "only the miss is fetched again"
    );
    let (icon, tier) = service(sites).lookup(db, "hit.example").await;
    assert_eq!(
        (icon.unwrap().bytes.clone(), tier),
        (png("two").bytes, Tier::Database)
    );
    let (icon, _) = service(sites).lookup(db, "miss.example").await;
    assert_eq!(icon.unwrap().bytes.clone(), png("found").bytes);
    let mut text = String::new();
    metrics.render(&mut text);
    assert!(
        text.contains(r#"passbox_icon_refreshes_total{outcome="unchanged"} 2"#),
        "{text}"
    );
    assert!(
        text.contains(r#"passbox_icon_refreshes_total{outcome="updated"} 3"#),
        "{text}"
    );

    // A site that stops answering keeps its icon for two failed refreshes
    // (a day apart), then becomes a miss.
    *sites.revalidation.lock().unwrap() = Some(Revalidation::Unavailable);
    sites.set("hit.example", None);
    let mut at = much_later + 31 * DAY;
    set(
        server,
        "UPDATE site_icons SET last_requested_at = $2 WHERE domain = $1",
        "hit.example",
        at,
    )
    .await;
    for expected_failures in 1..=2 {
        let report = refresh_due(db, &worker, &metrics, at, 50).await.unwrap();
        assert_eq!(report.failed, 1, "{report:?}");
        let (image, _, _, failures) = row(server, "hit.example").await.unwrap();
        assert!(image.is_some());
        assert_eq!(failures, expected_failures);
        // Not again before the back-off is over.
        let report = refresh_due(db, &worker, &metrics, at + 60_000, 50)
            .await
            .unwrap();
        assert_eq!(report.failed, 0);
        at += DAY + 1;
    }
    let report = refresh_due(db, &worker, &metrics, at, 50).await.unwrap();
    assert_eq!(report.missing, 1, "{report:?}");
    let (image, _, retry_after, failures) = row(server, "hit.example").await.unwrap();
    assert!(image.is_none());
    assert_eq!(retry_after, Some(at + 7 * DAY));
    assert_eq!(failures, 0);

    // Entries nobody asked for in 180 days are removed.
    let report = refresh_due(db, &worker, &metrics, at + 181 * DAY, 50)
        .await
        .unwrap();
    assert_eq!(report.removed, 3, "{report:?}");
    assert!(row(server, "hit.example").await.is_none());
}

async fn begin(conn: &mut PgConnection, account_id: &str, system: &str) {
    sqlx::query("BEGIN").execute(&mut *conn).await.unwrap();
    sqlx::query(
        "SELECT set_config('passbox.account_id', $1, true), set_config('passbox.context', '', true), \
         set_config('passbox.org_id', '', true), set_config('passbox.system', $2, true)",
    )
    .bind(account_id)
    .bind(system)
    .execute(&mut *conn)
    .await
    .unwrap();
}

async fn rollback(conn: &mut PgConnection) {
    sqlx::query("ROLLBACK").execute(&mut *conn).await.unwrap();
}

const INSERT: &str = "INSERT INTO site_icons (domain, fetched_at, last_requested_at, retry_after) \
                      VALUES ('rls.example', 0, 0, 1)";

fn refused(result: Result<sqlx::postgres::PgQueryResult, sqlx::Error>, what: &str) {
    match result {
        Err(sqlx::Error::Database(error)) => assert!(
            error.message().contains("row-level security")
                || error.code().as_deref() == Some("42501"),
            "{what}: {error}"
        ),
        other => panic!("{what} was not refused: {other:?}"),
    }
}

/// Every context may read the store; only the icon contexts write it.
async fn policies(server: &TestServer, database: &TestDatabase) {
    let account = Member::new(server, "10.9.5.71").await.client.account_id;
    sqlx::query(
        "INSERT INTO site_icons (domain, fetched_at, last_requested_at, retry_after) \
         VALUES ('policy.example', 0, 0, 1)",
    )
    .execute(server.db())
    .await
    .unwrap();
    let mut app = database.connect_as("passbox_app").await;
    let count = "SELECT count(*) FROM site_icons";

    begin(&mut app, "", "").await;
    let seen: i64 = sqlx::query_scalar(count).fetch_one(&mut app).await.unwrap();
    rollback(&mut app).await;
    assert_eq!(seen, 0, "no context, no rows");

    begin(&mut app, &account, "").await;
    let seen: i64 = sqlx::query_scalar(count).fetch_one(&mut app).await.unwrap();
    assert!(seen > 0, "an account reads the shared store");
    refused(
        sqlx::query(INSERT).execute(&mut app).await,
        "insert as an account",
    );
    rollback(&mut app).await;
    begin(&mut app, &account, "").await;
    let changed = sqlx::query("UPDATE site_icons SET failures = 9")
        .execute(&mut app)
        .await
        .unwrap()
        .rows_affected();
    rollback(&mut app).await;
    assert_eq!(changed, 0, "an account changes nothing");

    begin(&mut app, "", "icons").await;
    sqlx::query(INSERT).execute(&mut app).await.unwrap();
    refused(
        sqlx::query("DELETE FROM site_icons")
            .execute(&mut app)
            .await,
        "delete from requests",
    );
    rollback(&mut app).await;

    let mut worker = database.connect_as("passbox_worker").await;
    begin(&mut worker, "", "worker:mail").await;
    let changed = sqlx::query("UPDATE site_icons SET failures = 9")
        .execute(&mut worker)
        .await
        .unwrap()
        .rows_affected();
    rollback(&mut worker).await;
    assert_eq!(changed, 0, "another job changes nothing");
    begin(&mut worker, "", "worker:icons").await;
    sqlx::query(INSERT).execute(&mut worker).await.unwrap();
    let removed = sqlx::query("DELETE FROM site_icons WHERE domain = 'rls.example'")
        .execute(&mut worker)
        .await
        .unwrap()
        .rows_affected();
    rollback(&mut worker).await;
    assert_eq!(removed, 1);
    app.close().await.unwrap();
    worker.close().await.unwrap();
}

/// A buffer the log subscriber writes into.
#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Logs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Request logs (even at the most verbose level) never show the domain,
/// and nothing logged for an icon request names the account.
pub async fn icon_requests_are_not_logged(server: &TestServer) {
    let member = Member::new(server, "10.9.5.72").await;
    let sites = Arc::new(Sites::default());
    sites.set("logged.example", Some(png("log")));
    let mut state = server.state.clone();
    state.icons = Arc::new(service(&sites));
    let app = passbox_server::routes::router(&passbox_server::config::Config::default(), state);

    let logs = Logs::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let status = {
        let _guard = tracing::subscriber::set_default(subscriber);
        app.oneshot(
            Request::get("/api/v1/icons/logged.example")
                .header("authorization", format!("Bearer {}", member.token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
    };
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(text.contains("/api/v1/icons/{domain}"), "{text}");
    assert!(!text.contains("logged.example"), "{text}");
    assert!(!text.contains(&member.client.account_id), "{text}");
    assert!(!text.contains(&member.token), "{text}");
    // Counted by tier, without the domain.
    assert!(server.state.metrics.icons.lookups(Tier::Fetch, true) >= 1);
    let stored: i64 =
        sqlx::query_scalar("SELECT count(*) FROM site_icons WHERE domain = 'logged.example'")
            .fetch_one(server.db())
            .await
            .unwrap();
    assert_eq!(stored, 1);
}
