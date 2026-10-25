//! Have I Been Pwned through the server: the password range proxy and
//! email breach monitoring, with a fake upstream (no network access).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use passbox_server::api::breach::{BreachService, BreachUpstream, HibpBreach, UpstreamError};
use passbox_server::config::Config;
use serde_json::{Value, json};
use sqlx::Connection;
use tower::ServiceExt;

use super::{Member, TestServer};

#[derive(Default)]
struct FakeHibp {
    ranges: AtomicUsize,
    accounts: AtomicUsize,
    /// After this many account lookups, a new breach appears.
    new_breach_after: usize,
}

impl BreachUpstream for FakeHibp {
    fn range(&self, prefix: &str) -> Result<String, UpstreamError> {
        self.ranges.fetch_add(1, Ordering::SeqCst);
        Ok(format!(
            "{prefix}-IGNORED:0\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0"
        ))
    }

    fn breached_account(&self, email: &str) -> Result<Vec<HibpBreach>, UpstreamError> {
        let calls = self.accounts.fetch_add(1, Ordering::SeqCst) + 1;
        if !email.starts_with("pwned") {
            return Ok(Vec::new());
        }
        let breach = |name: &str, domain: &str| HibpBreach {
            name: name.into(),
            title: name.into(),
            domain: domain.into(),
            breach_date: "2013-10-04".into(),
            added_date: "2013-12-04T00:00:00Z".into(),
            pwn_count: 1000,
            data_classes: vec!["Email addresses".into(), "Passwords".into()],
        };
        let mut breaches = vec![breach("Adobe", "adobe.com")];
        if calls > self.new_breach_after {
            breaches.push(breach("Dropbox", "dropbox.com"));
        }
        Ok(breaches)
    }
}

fn with_breach(
    server: &TestServer,
    proxy: bool,
    monitoring: bool,
    fake: Arc<FakeHibp>,
) -> TestServer {
    let mut state = server.state.clone();
    let mut service = BreachService::new(proxy, monitoring, fake);
    service.requests_per_minute = 6000;
    state.breach = Arc::new(service);
    TestServer {
        app: passbox_server::routes::router(&Config::default(), state.clone()),
        state,
        env_admin_email: server.env_admin_email.clone(),
        owner: server.owner.clone(),
    }
}

async fn get_text(server: &TestServer, uri: &str, token: Option<&str>) -> (StatusCode, String) {
    let mut request = Request::get(uri);
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = server
        .app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

async fn mailed_code(server: &TestServer, to: &str) -> String {
    let (params,): (String,) = sqlx::query_as(
        "SELECT params::text FROM mail_outbox WHERE recipient = $1 AND template = 'breach_monitor_code' \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(to)
    .fetch_one(server.db())
    .await
    .unwrap();
    serde_json::from_str::<Value>(&params).unwrap()["code"]
        .as_str()
        .unwrap()
        .to_owned()
}

pub async fn breach_proxy_and_monitoring(server: &TestServer) {
    let member = Member::new(server, "10.9.6.1").await;
    let token = member.token.as_str();
    let fake = Arc::new(FakeHibp {
        new_breach_after: 1,
        ..FakeHibp::default()
    });
    let on = with_breach(server, true, true, fake.clone());

    // --- Range proxy ---------------------------------------------------------
    let (status, body) = get_text(&on, "/api/v1/breach/range/5baa6", Some(token)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365"));
    // Cached: the second request does not reach Have I Been Pwned.
    get_text(&on, "/api/v1/breach/range/5BAA6", Some(token)).await;
    assert_eq!(fake.ranges.load(Ordering::SeqCst), 1);
    for bad in ["5BAA", "5BAA61", "ZZZZZ"] {
        let (status, _) = get_text(&on, &format!("/api/v1/breach/range/{bad}"), Some(token)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let (status, _) = get_text(&on, "/api/v1/breach/range/5BAA6", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let off = with_breach(server, false, false, fake.clone());
    let (status, _) = get_text(&off, "/api/v1/breach/range/5BAA6", Some(token)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, meta) = off.request(Method::GET, "/api/v1/meta", None, None).await;
    assert_eq!(meta["breachProxy"], false);
    assert_eq!(meta["emailMonitoring"], false);
    let (_, meta) = on.request(Method::GET, "/api/v1/meta", None, None).await;
    assert_eq!(meta["emailMonitoring"], true);

    // --- Email monitoring ----------------------------------------------------
    let (status, body) = off
        .request(Method::GET, "/api/v1/breach/emails", Some(token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["available"], false);
    let (status, body) = off
        .request(
            Method::POST,
            "/api/v1/breach/emails",
            Some(token),
            Some(json!({ "email": "pwned@example.com" })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "monitoring_unavailable");

    let address = format!(
        "pwned-{}@example.com",
        member.client.email.replace('@', ".")
    );
    let (status, added) = on
        .request(
            Method::POST,
            "/api/v1/breach/emails",
            Some(token),
            Some(json!({ "email": address.to_uppercase(), "locale": "de" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{added}");
    assert_eq!(added["email"], address);
    assert_eq!(added["verified"], false);
    let id = added["id"].as_str().unwrap().to_owned();
    // Nothing is sent to Have I Been Pwned before the address is confirmed.
    assert_eq!(fake.accounts.load(Ordering::SeqCst), 0);
    // Resending right away is refused.
    let (status, _) = on
        .request(
            Method::POST,
            "/api/v1/breach/emails",
            Some(token),
            Some(json!({ "email": address })),
        )
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    let code = mailed_code(&on, &address).await;
    let verify = |code: String| {
        let on = &on;
        let id = id.clone();
        async move {
            on.request(
                Method::POST,
                &format!("/api/v1/breach/emails/{id}/verify"),
                Some(token),
                Some(json!({ "code": code })),
            )
            .await
        }
    };
    let wrong = if code == "000000" { "111111" } else { "000000" };
    let (status, _) = verify(wrong.into()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, verified) = verify(code.clone()).await;
    assert_eq!(status, StatusCode::OK, "{verified}");
    assert_eq!(verified["verified"], true);
    assert_eq!(verified["breaches"][0]["name"], "Adobe");
    assert_eq!(verified["breaches"][0]["dataClasses"][1], "Passwords");
    assert!(verified["checkedAt"].as_i64().unwrap() > 0);
    // The first results are shown, not mailed.
    let alerts: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mail_outbox WHERE recipient = $1 AND template = 'breach_monitor_alert'",
    )
    .bind(&member.client.email)
    .fetch_one(on.db())
    .await
    .unwrap();
    assert_eq!(alerts, 0);

    // Another account cannot see or touch the address.
    let other = Member::new(server, "10.9.6.2").await;
    let (_, list) = on
        .request(
            Method::GET,
            "/api/v1/breach/emails",
            Some(&other.token),
            None,
        )
        .await;
    assert_eq!(list["emails"].as_array().unwrap().len(), 0);
    let (status, _) = on
        .request(
            Method::DELETE,
            &format!("/api/v1/breach/emails/{id}"),
            Some(&other.token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A periodic check finds a new breach and mails it to the account.
    sqlx::query("UPDATE breach_monitor_emails SET checked_at = 1 WHERE id = $1")
        .bind(&id)
        .execute(on.db())
        .await
        .unwrap();
    let checked = passbox_server::api::breach::check_due(&on.state)
        .await
        .unwrap();
    assert!(checked >= 1);
    let (_, list) = on
        .request(Method::GET, "/api/v1/breach/emails", Some(token), None)
        .await;
    let names: Vec<&str> = list["emails"][0]["breaches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), 2, "{list}");
    assert!(names.contains(&"Dropbox"));
    let (params,): (String,) = sqlx::query_as(
        "SELECT params::text FROM mail_outbox WHERE recipient = $1 AND template = 'breach_monitor_alert'",
    )
    .bind(&member.client.email)
    .fetch_one(on.db())
    .await
    .unwrap();
    let params: Value = serde_json::from_str(&params).unwrap();
    assert_eq!(params["breaches"], "Dropbox");
    assert_eq!(params["monitored"], address.as_str());

    // Manual checks are limited; deleting removes the address and results.
    let (status, _) = on
        .request(
            Method::POST,
            &format!("/api/v1/breach/emails/{id}/check"),
            Some(token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let (status, _) = on
        .request(
            Method::DELETE,
            &format!("/api/v1/breach/emails/{id}"),
            Some(token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let left: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM breach_monitor_results WHERE email_id = $1")
            .bind(&id)
            .fetch_one(on.db())
            .await
            .unwrap();
    assert_eq!(left, 0);
}

// --- Breach catalogue ------------------------------------------------------------

/// A fake `/api/v3/breaches` with an `ETag`.
#[derive(Default)]
struct FakeCatalog {
    calls: AtomicUsize,
    /// Validators the server sent.
    if_none_match: std::sync::Mutex<Vec<Option<String>>>,
    /// Answer with the bigger list (a new breach was published).
    grown: std::sync::atomic::AtomicBool,
    fail: std::sync::atomic::AtomicBool,
}

const UPSTREAM_SMALL: &str = r#"[
  {"Name":"Adobe","Title":"Adobe","Domain":"adobe.com","BreachDate":"2013-10-04",
   "AddedDate":"2013-12-04T00:00:00Z","ModifiedDate":"2022-05-15T23:52:49Z","PwnCount":152445165,
   "Description":"<p>long</p>","LogoPath":"https://logos.haveibeenpwned.com/Adobe.png",
   "DataClasses":["Email addresses","Password hints","Passwords","Usernames"],
   "IsVerified":true,"IsFabricated":false,"IsSensitive":false,"IsRetired":false,"IsSpamList":false,
   "IsMalware":false,"IsSubscriptionFree":false,"IsStealerLog":false},
  {"Name":"Scraped","Title":"Scraped list","Domain":"scraped.example","BreachDate":"2020-01-01",
   "AddedDate":"2020-02-01T00:00:00Z","ModifiedDate":"2020-02-01T00:00:00Z","PwnCount":10,
   "DataClasses":["Email addresses"],"IsVerified":true,"IsSpamList":true},
  {"Name":"Fake","Title":"Fake","Domain":"fake.example","BreachDate":"2020-01-01",
   "AddedDate":"2020-02-01T00:00:00Z","ModifiedDate":"2020-02-01T00:00:00Z","PwnCount":10,
   "DataClasses":["Email addresses"],"IsFabricated":true},
  {"Name":"Combo","Title":"Combo list","Domain":"","BreachDate":"2019-01-01",
   "AddedDate":"2019-02-01T00:00:00Z","ModifiedDate":"2019-02-01T00:00:00Z","PwnCount":10,
   "DataClasses":["Email addresses","Passwords"]},
  {"Name":"Adult","Title":"Adult site","Domain":"adult.example","BreachDate":"2016-01-01",
   "AddedDate":"2016-02-01T00:00:00Z","ModifiedDate":"2016-02-01T00:00:00Z","PwnCount":10,
   "DataClasses":["Email addresses","Passwords"],"IsVerified":true,"IsSensitive":true}
]"#;

impl passbox_server::api::breach_catalog::CatalogUpstream for FakeCatalog {
    fn fetch(
        &self,
        etag: Option<&str>,
    ) -> Result<passbox_server::api::breach_catalog::Fetched, String> {
        use passbox_server::api::breach_catalog::Fetched;
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.if_none_match
            .lock()
            .unwrap()
            .push(etag.map(str::to_owned));
        if self.fail.load(Ordering::SeqCst) {
            return Err("connection refused".into());
        }
        let grown = self.grown.load(Ordering::SeqCst);
        let current = if grown { "\"v2\"" } else { "\"v1\"" };
        if etag == Some(current) {
            return Ok(Fetched::NotModified);
        }
        let body = if grown {
            UPSTREAM_SMALL.replacen(
                "[",
                r#"[{"Name":"Netflix","Title":"Netflix","Domain":"netflix.com","BreachDate":"2026-10-01",
                    "AddedDate":"2026-10-20T10:00:00Z","ModifiedDate":"2026-10-20T10:00:00Z","PwnCount":5000,
                    "DataClasses":["Email addresses","Passwords"],"IsVerified":true},"#,
                1,
            )
        } else {
            UPSTREAM_SMALL.to_owned()
        };
        Ok(Fetched::Body {
            body,
            etag: Some(current.to_owned()),
        })
    }
}

fn with_catalog(server: &TestServer, enabled: bool, fake: Arc<FakeCatalog>) -> TestServer {
    let mut state = server.state.clone();
    state.breach_catalog = Arc::new(passbox_server::api::breach_catalog::CatalogService::new(
        enabled, fake,
    ));
    TestServer {
        app: passbox_server::routes::router(&Config::default(), state.clone()),
        state,
        env_admin_email: server.env_admin_email.clone(),
        owner: server.owner.clone(),
    }
}

async fn get_raw(
    server: &TestServer,
    uri: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let mut request = Request::get(uri);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = server
        .app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, headers, body.to_vec())
}

pub async fn breach_catalog(server: &TestServer, database: &passbox_server::testing::TestDatabase) {
    use passbox_server::api::breach_catalog::{Refresh, refresh};
    let fake = Arc::new(FakeCatalog::default());
    let on = with_catalog(server, true, fake.clone());

    // Before the first fetch the bundled snapshot is served (no session needed).
    let (status, version) = on
        .request(Method::GET, "/api/v1/breaches/catalog/version", None, None)
        .await;
    assert_eq!(status, StatusCode::OK, "{version}");
    assert_eq!(version["bundled"], true);
    assert_eq!(version["source"], "Have I Been Pwned");
    assert!(version["entries"].as_u64().unwrap() > 500);

    // The worker fetches, stores every entry and serves the filtered list.
    let result = refresh(&on.state, false).await.unwrap();
    assert!(
        matches!(result, Refresh::Updated { entries: 2, .. }),
        "{result:?}"
    );
    let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM site_breaches")
        .fetch_one(on.db())
        .await
        .unwrap();
    assert_eq!(stored, 5);
    let (spam, fabricated): (bool, bool) = sqlx::query_as(
        "SELECT (SELECT is_spam_list FROM site_breaches WHERE name = 'Scraped'), \
         (SELECT is_fabricated FROM site_breaches WHERE name = 'Fake')",
    )
    .fetch_one(on.db())
    .await
    .unwrap();
    assert!(spam && fabricated);
    // Not due again within the interval; nothing is fetched.
    assert_eq!(refresh(&on.state, false).await.unwrap(), Refresh::NotDue);
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);

    let (status, headers, body) = get_raw(&on, "/api/v1/breaches/catalog", &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["cache-control"], "public, no-cache");
    assert!(headers.get("content-encoding").is_none());
    let etag = headers["etag"].to_str().unwrap().to_owned();
    let doc: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(format!("\"{}\"", doc["version"].as_str().unwrap()), etag);
    assert_eq!(doc["source"], "Have I Been Pwned");
    assert_eq!(doc["license"], "CC BY 4.0");
    let names: Vec<&str> = doc["breaches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["Adobe", "Adult"]);
    let adobe = &doc["breaches"][0];
    assert_eq!(adobe["domain"], "adobe.com");
    assert_eq!(adobe["addedDate"], "2013-12-04T00:00:00Z");
    assert_eq!(adobe["dataClasses"][2], "Passwords");
    assert!(adobe.get("description").is_none() && adobe.get("logoPath").is_none());
    assert_eq!(doc["breaches"][1]["sensitive"], true);
    assert_eq!(
        doc["updatedAt"].as_i64().unwrap(),
        passbox_core::analysis::breaches::parse_date_ms("2022-05-15T23:52:49Z").unwrap()
    );

    // Conditional and compressed requests.
    let (status, headers, body) =
        get_raw(&on, "/api/v1/breaches/catalog", &[("if-none-match", &etag)]).await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert!(body.is_empty());
    assert_eq!(headers["etag"].to_str().unwrap(), etag);
    let (status, headers, body) = get_raw(
        &on,
        "/api/v1/breaches/catalog",
        &[("accept-encoding", "br, gzip")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["content-encoding"], "gzip");
    let mut json = String::new();
    std::io::Read::read_to_string(&mut flate2::read::GzDecoder::new(&body[..]), &mut json).unwrap();
    assert_eq!(serde_json::from_str::<Value>(&json).unwrap(), doc);

    // A forced refresh sends the stored ETag and gets 304: same version.
    assert_eq!(refresh(&on.state, true).await.unwrap(), Refresh::Unchanged);
    assert_eq!(
        fake.if_none_match
            .lock()
            .unwrap()
            .last()
            .cloned()
            .flatten()
            .as_deref(),
        Some("\"v1\"")
    );
    // A new breach is published: a new version, announced to clients.
    fake.grown.store(true, Ordering::SeqCst);
    let Refresh::Updated { version: v2, .. } = refresh(&on.state, true).await.unwrap() else {
        panic!("expected an update");
    };
    let (_, version) = on
        .request(Method::GET, "/api/v1/breaches/catalog/version", None, None)
        .await;
    assert_eq!(version["version"], v2.as_str());
    assert_eq!(version["bundled"], false);
    assert_eq!(version["entries"], 3);
    assert_eq!(
        version["updatedAt"].as_i64().unwrap(),
        passbox_core::analysis::breaches::parse_date_ms("2026-10-20T10:00:00Z").unwrap()
    );
    let (status, _, _) =
        get_raw(&on, "/api/v1/breaches/catalog", &[("if-none-match", &etag)]).await;
    assert_eq!(status, StatusCode::OK, "the old ETag no longer matches");
    // Another server instance sees the new version from the database.
    let sibling = with_catalog(
        &server.sibling().await,
        true,
        Arc::new(FakeCatalog::default()),
    );
    let (_, version) = sibling
        .request(Method::GET, "/api/v1/breaches/catalog/version", None, None)
        .await;
    assert_eq!(version["version"], v2.as_str());

    // A failed fetch is recorded and keeps the stored catalogue.
    fake.fail.store(true, Ordering::SeqCst);
    assert!(refresh(&on.state, true).await.is_err());
    let error: String = sqlx::query_scalar("SELECT error FROM site_breach_catalog WHERE id = 1")
        .fetch_one(on.db())
        .await
        .unwrap();
    assert!(error.contains("connection refused"), "{error}");
    let (_, version) = on
        .request(Method::GET, "/api/v1/breaches/catalog/version", None, None)
        .await;
    assert_eq!(version["version"], v2.as_str());
    fake.fail.store(false, Ordering::SeqCst);

    // Turned off (air-gapped): no endpoints, the meta says so.
    let off = with_catalog(server, false, fake.clone());
    let (status, _) = off
        .request(Method::GET, "/api/v1/breaches/catalog", None, None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = off
        .request(Method::GET, "/api/v1/breaches/catalog/version", None, None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, meta) = off.request(Method::GET, "/api/v1/meta", None, None).await;
    assert_eq!(meta["breachCatalog"], false);
    let (_, meta) = on.request(Method::GET, "/api/v1/meta", None, None).await;
    assert_eq!(meta["breachCatalog"], true);

    // Row level security: every context reads, only the catalogue job writes.
    let mut app = database.connect_as("passbox_app").await;
    let mut worker = database.connect_as("passbox_worker").await;
    let count = |sql: &'static str| sqlx::query_scalar::<_, i64>(sql);
    for (on_worker, context, system, visible) in [
        (false, "", "", false),
        (false, "breach_catalog", "", true),
        (false, "auth", "", true),
        (true, "", "worker:breach_catalog", true),
    ] {
        let conn = if on_worker { &mut worker } else { &mut app };
        sqlx::query("BEGIN").execute(&mut *conn).await.unwrap();
        sqlx::query(
            "SELECT set_config('passbox.context', $1, true), set_config('passbox.system', $2, true)",
        )
        .bind(context)
        .bind(system)
        .execute(&mut *conn)
        .await
        .unwrap();
        let rows = count("SELECT COUNT(*) FROM site_breaches")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(rows > 0, visible, "{context}{system}");
        sqlx::query("ROLLBACK").execute(&mut *conn).await.unwrap();
    }
    // The app role cannot write, not even in a worker context.
    for (context, system) in [("breach_catalog", ""), ("", "worker:breach_catalog")] {
        sqlx::query("BEGIN").execute(&mut app).await.unwrap();
        sqlx::query(
            "SELECT set_config('passbox.context', $1, true), set_config('passbox.system', $2, true)",
        )
        .bind(context)
        .bind(system)
        .execute(&mut app)
        .await
        .unwrap();
        let result = sqlx::query("UPDATE site_breaches SET pwn_count = 0")
            .execute(&mut app)
            .await;
        assert!(
            result.is_err(),
            "app wrote site_breaches ({context}{system})"
        );
        sqlx::query("ROLLBACK").execute(&mut app).await.unwrap();
    }
    // Another job of the worker role sees and changes nothing.
    sqlx::query("BEGIN").execute(&mut worker).await.unwrap();
    sqlx::query("SELECT set_config('passbox.system', 'worker:breach', true)")
        .execute(&mut worker)
        .await
        .unwrap();
    let changed = sqlx::query("UPDATE site_breach_catalog SET error = 'x'")
        .execute(&mut worker)
        .await
        .unwrap()
        .rows_affected();
    assert_eq!(changed, 0);
    let inserted = sqlx::query(
        "INSERT INTO site_breaches (name, title, domain, breach_date, added_date, modified_date, \
         pwn_count, data_classes, is_verified, is_sensitive, is_spam_list, is_fabricated, is_retired, \
         updated_at) VALUES ('X', 'X', 'x.example', '', 0, 0, 0, '[]', true, false, false, false, false, 0)",
    )
    .execute(&mut worker)
    .await;
    assert!(inserted.is_err(), "another job inserted a breach");
    sqlx::query("ROLLBACK").execute(&mut worker).await.unwrap();
    app.close().await.unwrap();
    worker.close().await.unwrap();
}
