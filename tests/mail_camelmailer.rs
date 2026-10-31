//! The mail outbox worker against a fake Camelmailer API.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use passbox_server::mail::{Locale, MailConfig, Mailer, Template};
use passbox_server::testing::TestDatabase;
use serde_json::{Value, json};
use tokio::net::TcpListener;

#[derive(Clone)]
struct Fake {
    status: StatusCode,
    requests: Arc<Mutex<Vec<(HeaderMap, Value)>>>,
}

async fn send(State(fake): State<Fake>, headers: HeaderMap, body: String) -> (StatusCode, String) {
    let body: Value = serde_json::from_str(&body).unwrap();
    fake.requests.lock().unwrap().push((headers, body));
    let reply = if fake.status.is_success() {
        json!({ "status": "success", "time": 0.01, "data": { "message_id": 1, "recipients": [] } })
    } else {
        json!({ "status": "error", "error": { "code": "ValidationError", "message": "refused" } })
    };
    (fake.status, reply.to_string())
}

/// A Camelmailer API on a random local port that answers sends with `status`.
async fn fake_api(status: StatusCode) -> (String, Arc<Mutex<Vec<(HeaderMap, Value)>>>) {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/api/v2/server/messages", post(send))
        .with_state(Fake {
            status,
            requests: requests.clone(),
        });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, requests)
}

async fn api_mailer(url: &str) -> (Mailer, TestDatabase) {
    let db = TestDatabase::create().await;
    let mailer = Mailer::new(
        db.db.clone(),
        &MailConfig {
            camelmailer_api_key: Some("test-key".to_owned()),
            camelmailer_url: Some(url.to_owned()),
            from: Some("Passbox <passbox@example.com>".to_owned()),
            public_url: Some("https://vault.example.com".to_owned()),
            ..Default::default()
        },
    )
    .unwrap();
    (mailer, db)
}

async fn status_of(db: &TestDatabase, id: &str) -> (String, i64) {
    sqlx::query_as("SELECT status, attempts FROM mail_outbox WHERE id = $1")
        .bind(id)
        .fetch_one(&db.owner)
        .await
        .unwrap()
}

#[tokio::test]
async fn sends_through_the_api_with_inline_logos_and_an_idempotency_key() {
    let (url, requests) = fake_api(StatusCode::CREATED).await;
    let (mailer, db) = api_mailer(&url).await;
    assert!(mailer.is_configured());
    let id = mailer
        .enqueue(
            "ada@example.com",
            Template::Test,
            Locale::En,
            json!({ "requestedBy": "admin@example.com" }),
        )
        .await
        .unwrap();

    assert_eq!(mailer.process_due().await.unwrap(), 1);
    assert_eq!(status_of(&db, &id).await.0, "sent");

    let requests = requests.lock().unwrap();
    let (headers, body) = &requests[0];
    assert_eq!(headers["x-server-api-key"], "test-key");
    assert_eq!(headers["idempotency-key"], id.as_str());
    assert_eq!(body["from"]["email"], "passbox@example.com");
    assert_eq!(body["from"]["name"], "Passbox");
    assert_eq!(body["to"][0], "ada@example.com");
    assert_eq!(body["tag"], Template::Test.as_str());
    let html = body["html_body"].as_str().unwrap();
    let attachments = body["attachments"].as_array().unwrap();
    assert!(!attachments.is_empty());
    for attachment in attachments {
        let cid = attachment["content_id"].as_str().unwrap();
        assert!(html.contains(&format!("cid:{cid}")), "the HTML shows {cid}");
        assert_eq!(attachment["content_type"], "image/png");
    }
    assert!(body["text_body"].as_str().is_some_and(|t| !t.is_empty()));
}

#[tokio::test]
async fn a_refused_request_is_not_retried_and_a_server_error_is() {
    let (url, _) = fake_api(StatusCode::UNPROCESSABLE_ENTITY).await;
    let (mailer, db) = api_mailer(&url).await;
    let id = mailer
        .enqueue("ada@example.com", Template::Test, Locale::En, json!({}))
        .await
        .unwrap();
    mailer.process_due().await.unwrap();
    assert_eq!(status_of(&db, &id).await, ("failed".to_owned(), 1));

    let (url, _) = fake_api(StatusCode::SERVICE_UNAVAILABLE).await;
    let (retrying, db) = api_mailer(&url).await;
    let id = retrying
        .enqueue("ada@example.com", Template::Test, Locale::En, json!({}))
        .await
        .unwrap();
    retrying.process_due().await.unwrap();
    assert_eq!(status_of(&db, &id).await, ("pending".to_owned(), 1));
}

#[tokio::test]
async fn smtp_and_the_api_are_exclusive_and_the_api_needs_a_sender() {
    let database = TestDatabase::create().await;
    let both = MailConfig {
        smtp_url: Some("smtp://localhost".to_owned()),
        camelmailer_api_key: Some("key".to_owned()),
        from: Some("a@example.com".to_owned()),
        ..Default::default()
    };
    assert!(Mailer::new(database.db.clone(), &both).is_err());
    let no_sender = MailConfig {
        camelmailer_api_key: Some("key".to_owned()),
        ..Default::default()
    };
    assert!(Mailer::new(database.db.clone(), &no_sender).is_err());
    let bad_url = MailConfig {
        camelmailer_api_key: Some("key".to_owned()),
        camelmailer_url: Some("ftp://example.com".to_owned()),
        from: Some("a@example.com".to_owned()),
        ..Default::default()
    };
    assert!(Mailer::new(database.db.clone(), &bad_url).is_err());
}
