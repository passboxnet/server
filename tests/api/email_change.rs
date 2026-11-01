//! Changing the account's email address: a code mailed to the new address,
//! a notice to the old one, sign-in with the new address afterwards.

use axum::http::{Method, StatusCode};
use passbox_core::aead::SymmetricKey;
use serde_json::{Value, json};

use super::{Client, TestServer};

/// Sign-ins of this test count against their own address.
const IP: &str = "10.7.0.1";

async fn mailed(server: &TestServer, to: &str, template: &str) -> Option<Value> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT params::text FROM mail_outbox WHERE recipient = $1 AND template = $2 \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(to)
    .bind(template)
    .fetch_optional(server.db())
    .await
    .unwrap();
    row.map(|(params,)| serde_json::from_str(&params).unwrap())
}

async fn code_for(server: &TestServer, to: &str) -> String {
    mailed(server, to, "email_change_code").await.unwrap()["code"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// The same account under another sign-in address.
fn under(client: &Client, email: &str) -> Client {
    Client {
        email: email.to_owned(),
        account_id: client.account_id.clone(),
        auth_secret: client.auth_secret,
        auk: SymmetricKey::generate().unwrap(),
    }
}

pub async fn email_change(server: &TestServer) {
    let client = Client::new();
    client.register_from(server, IP).await;
    let token = client
        .try_login(server, &client.auth_secret, Some(IP), None)
        .await
        .unwrap()
        .token;
    let new_email = format!("New.{}", client.email);
    let normalized = new_email.to_lowercase();

    // Invalid and unchanged addresses are refused.
    let (status, _) = server
        .post(
            "/api/v1/account/email",
            Some(&token),
            json!({ "email": "nope" }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = server
        .post(
            "/api/v1/account/email",
            Some(&token),
            json!({ "email": client.email }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, body) = server
        .post(
            "/api/v1/account/email",
            Some(&token),
            json!({ "email": new_email, "locale": "de" }),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["newEmail"], normalized);
    let (_, pending) = server
        .request(Method::GET, "/api/v1/account/email", Some(&token), None)
        .await;
    assert_eq!(pending["newEmail"], normalized);
    // A second code only after a minute.
    let (status, _) = server
        .post(
            "/api/v1/account/email",
            Some(&token),
            json!({ "email": new_email }),
        )
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    let code = code_for(server, &normalized).await;
    let wrong = if code == "000000" { "111111" } else { "000000" };
    let (status, body) = server
        .post(
            "/api/v1/account/email/confirm",
            Some(&token),
            json!({ "code": wrong }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_two_factor_code");

    let (status, body) = server
        .post(
            "/api/v1/account/email/confirm",
            Some(&token),
            json!({ "code": code }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["email"], normalized);
    let (_, account) = server
        .request(Method::GET, "/api/v1/account", Some(&token), None)
        .await;
    assert_eq!(account["email"], normalized);
    let (_, pending) = server
        .request(Method::GET, "/api/v1/account/email", Some(&token), None)
        .await;
    assert_eq!(pending, Value::Null);
    // The code is used up.
    let (status, _) = server
        .post(
            "/api/v1/account/email/confirm",
            Some(&token),
            json!({ "code": code }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The old address is told, and the change is in the activity log.
    let notice = mailed(server, &client.email, "email_changed")
        .await
        .unwrap();
    assert_eq!(notice["newEmail"], normalized);
    assert!(
        super::event_kinds(server, &token)
            .await
            .contains(&"email_changed".to_owned())
    );

    // Sign-in works with the new address and the same password only.
    under(&client, &normalized)
        .try_login(server, &client.auth_secret, Some(IP), None)
        .await
        .unwrap();
    let (status, _) = client
        .try_login(server, &client.auth_secret, Some(IP), None)
        .await
        .err()
        .unwrap();
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // An address of another account: the code is mailed as usual, and only
    // the owner of that mailbox learns that it is taken.
    let other = Client::new();
    other.register_from(server, IP).await;
    let (status, _) = server
        .post(
            "/api/v1/account/email",
            Some(&token),
            json!({ "email": other.email }),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let code = code_for(server, &other.email).await;
    let (status, body) = server
        .post(
            "/api/v1/account/email/confirm",
            Some(&token),
            json!({ "code": code }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "email_taken");

    // A pending change can be dropped.
    let (status, _) = server
        .request(Method::DELETE, "/api/v1/account/email", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, pending) = server
        .request(Method::GET, "/api/v1/account/email", Some(&token), None)
        .await;
    assert_eq!(pending, Value::Null);
}
