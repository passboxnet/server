//! Signing in `pbx` from a signed-in browser (`/cli-logins`). The server
//! never checks the MAC or opens the payload (that is the clients' job, see
//! passboxnet/core `device_link`), so random bytes of the right length
//! stand in for them here.

use axum::http::{Method, StatusCode};
use passbox_core::{encoding, id};
use serde_json::{Value, json};

use super::{Client, TestServer, event_kinds};

fn new_request(device_name: &str) -> (String, Value) {
    let request_id = id::new_id().unwrap();
    let body = json!({
        "id": request_id,
        "ephemeralKey": encoding::encode(&vec![7u8; passbox_core::identity::ENC_PK_LEN]),
        "mac": encoding::encode(&[1u8; 32]),
        "deviceName": device_name,
    });
    (request_id, body)
}

async fn post(
    server: &TestServer,
    ip: &str,
    uri: &str,
    token: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    server
        .request_from(Some(ip), Method::POST, uri, token, Some(body))
        .await
}

async fn create(server: &TestServer, ip: &str, device_name: &str) -> (String, String) {
    let (request_id, body) = new_request(device_name);
    let (status, body) = post(server, ip, "/api/v1/cli-logins", None, body).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert!(body["expiresAt"].as_i64().unwrap() > 0);
    (request_id, body["pollToken"].as_str().unwrap().to_owned())
}

async fn poll(server: &TestServer, ip: &str, token: &str) -> Value {
    let (status, body) = post(
        server,
        ip,
        "/api/v1/cli-logins/poll",
        None,
        json!({ "pollToken": token }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

pub(super) async fn cli_logins(server: &TestServer) {
    let ip = "10.44.0.1";
    let approver = Client::new();
    approver.register_from(server, ip).await;
    let token = approver.login(server).await;

    // The device registers a request without a session.
    let (request_id, poll_token) = create(server, ip, "pbx build-box").await;
    let (_, mut duplicate) = new_request("pbx build-box");
    duplicate["id"] = json!(request_id);
    let (status, _) = post(server, ip, "/api/v1/cli-logins", None, duplicate).await;
    assert_eq!(status, StatusCode::CONFLICT, "IDs are unique");
    for (field, value) in [
        ("mac", json!(encoding::encode(&[1u8; 16]))),
        ("ephemeralKey", json!(encoding::encode(&[7u8; 32]))),
        ("deviceName", json!("pbx\u{7}box")),
        ("deviceName", json!("x".repeat(81))),
        ("id", json!("not-an-id")),
    ] {
        let (_, mut body) = new_request("pbx");
        body[field] = value;
        let (status, body) = post(server, ip, "/api/v1/cli-logins", None, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{field}: {body}");
    }
    assert_eq!(poll(server, ip, &poll_token).await["status"], "pending");

    // The approver needs a session and sees name, IP, key and MAC.
    let uri = format!("/api/v1/cli-logins/{request_id}");
    let (status, _) = server.request(Method::GET, &uri, None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, view) = server.request(Method::GET, &uri, Some(&token), None).await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["id"], request_id.as_str());
    assert_eq!(view["deviceName"], "pbx build-box");
    assert_eq!(view["ip"], ip);
    assert_eq!(view["mac"], encoding::encode(&[1u8; 32]));
    assert!(view["expiresAt"].as_i64().unwrap() > view["createdAt"].as_i64().unwrap());
    let (status, _) = server
        .request(
            Method::GET,
            &format!("/api/v1/cli-logins/{}", id::new_id().unwrap()),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "unknown requests");

    // Approve once; the device receives the payload once.
    let sealed = encoding::encode(b"sealed for the device");
    let approve = format!("{uri}/approve");
    let (status, body) = post(
        server,
        ip,
        &approve,
        Some(&token),
        json!({ "sealedPayload": sealed }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, body) = post(
        server,
        ip,
        &approve,
        Some(&token),
        json!({ "sealedPayload": sealed }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "answered once");
    assert_eq!(body["error"], "cli_login_expired");
    let (status, _) = server.request(Method::GET, &uri, Some(&token), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "no longer pending");
    let answer = poll(server, ip, &poll_token).await;
    assert_eq!(answer["status"], "approved");
    assert_eq!(answer["sealedPayload"], sealed.as_str());
    assert!(answer["approvedBy"].is_string());
    assert_eq!(poll(server, ip, &poll_token).await["status"], "expired");
    assert!(
        event_kinds(server, &token)
            .await
            .contains(&"cli_login_approved".to_owned())
    );

    // Deny: the device is told once.
    let (request_id, poll_token) = create(server, ip, "pbx").await;
    let (status, _) = post(
        server,
        ip,
        &format!("/api/v1/cli-logins/{request_id}/deny"),
        Some(&token),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let answer = poll(server, ip, &poll_token).await;
    assert_eq!(answer["status"], "denied");
    assert!(answer.get("sealedPayload").is_none());
    assert_eq!(poll(server, ip, &poll_token).await["status"], "expired");
    assert!(
        event_kinds(server, &token)
            .await
            .contains(&"cli_login_denied".to_owned())
    );

    // Cancel (Ctrl+C on the device): gone for the approver too.
    let (request_id, poll_token) = create(server, ip, "pbx").await;
    let (status, _) = post(
        server,
        ip,
        "/api/v1/cli-logins/cancel",
        None,
        json!({ "pollToken": poll_token }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(poll(server, ip, &poll_token).await["status"], "expired");
    let (status, _) = server
        .request(
            Method::GET,
            &format!("/api/v1/cli-logins/{request_id}"),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(poll(server, ip, "no such token").await["status"], "expired");

    // After ten minutes a request can no longer be approved.
    let (request_id, poll_token) = create(server, ip, "pbx").await;
    sqlx::query("UPDATE cli_logins SET expires_at = 1 WHERE id = $1")
        .bind(&request_id)
        .execute(server.db())
        .await
        .unwrap();
    let (status, _) = post(
        server,
        ip,
        &format!("/api/v1/cli-logins/{request_id}/approve"),
        Some(&token),
        json!({ "sealedPayload": sealed }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(poll(server, ip, &poll_token).await["status"], "expired");

    // At most three open requests per IP...
    let busy = "10.44.0.2";
    for _ in 0..3 {
        create(server, busy, "pbx").await;
    }
    let (status, _) = post(
        server,
        busy,
        "/api/v1/cli-logins",
        None,
        new_request("pbx").1,
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    // ...and ten new ones per IP and hour, even when they are cancelled.
    let churn = "10.44.0.3";
    for _ in 0..10 {
        let (_, poll_token) = create(server, churn, "pbx").await;
        post(
            server,
            churn,
            "/api/v1/cli-logins/cancel",
            None,
            json!({ "pollToken": poll_token }),
        )
        .await;
    }
    let (status, _) = post(
        server,
        churn,
        "/api/v1/cli-logins",
        None,
        new_request("pbx").1,
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}
