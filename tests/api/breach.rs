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
