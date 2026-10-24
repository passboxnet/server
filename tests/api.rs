//! End-to-end tests of the HTTP API using the real client-side cryptography.
//!
//! Runs against in-memory SQLite. Set `PASSBOX_TEST_DATABASE_URL` to a
//! PostgreSQL URL to run the same tests against PostgreSQL as well.

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use passbox_core::aead::SymmetricKey;
use passbox_core::kdf::KdfParams;
use passbox_core::keyring::Keyring;
use passbox_core::opaque::{ClientLoginFlow, ClientRegistrationFlow};
use passbox_core::{encoding, id, random};
use passbox_server::config::Config;
use passbox_server::state::AppState;
use serde_json::{Value, json};
use tower::ServiceExt;

struct TestServer {
    app: Router,
}

impl TestServer {
    async fn new(database_url: &str) -> Self {
        let db = passbox_server::db::connect(database_url).await.unwrap();
        let state = AppState::load(db).await.unwrap();
        Self {
            app: passbox_server::routes::router(&Config::default(), state),
        }
    }

    async fn request(
        &self,
        method: Method,
        uri: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let request = match body {
            Some(body) => builder
                .header("content-type", "application/json")
                .body(Body::from(body.to_string())),
            None => builder.body(Body::empty()),
        }
        .unwrap();
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn post(&self, uri: &str, token: Option<&str>, body: Value) -> (StatusCode, Value) {
        self.request(Method::POST, uri, token, Some(body)).await
    }
}

/// A client account with its secrets. Key derivation is skipped (the server
/// never sees it); the AUK and auth secret are random instead.
struct Client {
    email: String,
    account_id: String,
    auth_secret: [u8; 32],
    auk: SymmetricKey,
}

impl Client {
    fn new() -> Self {
        Self {
            email: format!("{}@example.com", id::new_id().unwrap()),
            account_id: id::new_id().unwrap(),
            auth_secret: random::bytes().unwrap(),
            auk: SymmetricKey::generate().unwrap(),
        }
    }

    /// Registers the account and returns its keyring and personal vault ID.
    async fn register(&self, server: &TestServer) -> (Keyring, String) {
        let (flow, request) = ClientRegistrationFlow::start(&self.auth_secret).unwrap();
        let (status, body) = server
            .post(
                "/api/v1/auth/register/start",
                None,
                json!({
                    "accountId": self.account_id,
                    "email": self.email,
                    "registrationRequest": encoding::encode(&request),
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let response = encoding::decode(body["registrationResponse"].as_str().unwrap()).unwrap();
        let upload = flow.finish(&response).unwrap();

        let (mut keyring, encrypted_account_key) =
            Keyring::create(&self.auk, &self.account_id).unwrap();
        let vault = keyring.create_vault(r#"{"name":"Private"}"#).unwrap();
        let (status, body) = server
            .post(
                "/api/v1/auth/register/finish",
                None,
                json!({
                    "accountId": self.account_id,
                    "email": self.email,
                    "registrationUpload": encoding::encode(&upload),
                    "kdfSalt": encoding::encode(&[7u8; 16]),
                    "kdfParams": KdfParams::DEFAULT,
                    "encryptedAccountKey": encrypted_account_key,
                    "vault": {
                        "id": vault.id,
                        "encryptedKey": vault.encrypted_key,
                        "encryptedMeta": vault.encrypted_meta,
                    },
                }),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        (keyring, vault.id)
    }

    async fn login_with(
        &self,
        server: &TestServer,
        auth_secret: &[u8],
    ) -> Result<String, StatusCode> {
        let (flow, request) = ClientLoginFlow::start(auth_secret).unwrap();
        let (status, body) = server
            .post(
                "/api/v1/auth/login/start",
                None,
                json!({ "email": self.email, "credentialRequest": encoding::encode(&request) }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let response = encoding::decode(body["credentialResponse"].as_str().unwrap()).unwrap();
        // With a wrong secret the client detects the failure itself; send a
        // garbage finalization to check the server rejects it too.
        let finalization = match flow.finish(&response) {
            Ok(finish) => finish.finalization,
            Err(_) => vec![0u8; 64],
        };
        let (status, body) = server
            .post(
                "/api/v1/auth/login/finish",
                None,
                json!({
                    "loginId": body["loginId"],
                    "credentialFinalization": encoding::encode(&finalization),
                }),
            )
            .await;
        if status == StatusCode::OK {
            Ok(body["token"].as_str().unwrap().to_owned())
        } else {
            Err(status)
        }
    }

    async fn login(&self, server: &TestServer) -> String {
        self.login_with(server, &self.auth_secret).await.unwrap()
    }
}

async fn run_all(database_url: &str) {
    let server = TestServer::new(database_url).await;
    registration_and_login(&server).await;
    prelogin_does_not_reveal_accounts(&server).await;
    items_sync_and_conflicts(&server).await;
    accounts_are_isolated(&server).await;
    requests_need_a_session(&server).await;
}

#[tokio::test]
async fn api_on_sqlite() {
    run_all("sqlite::memory:").await;
}

#[tokio::test]
async fn api_on_postgres() {
    match std::env::var("PASSBOX_TEST_DATABASE_URL") {
        Ok(url) => run_all(&url).await,
        Err(_) => eprintln!("PASSBOX_TEST_DATABASE_URL not set, skipping PostgreSQL tests"),
    }
}

async fn registration_and_login(server: &TestServer) {
    let client = Client::new();
    client.register(server).await;

    // The same email cannot register twice.
    let mut duplicate = Client::new();
    duplicate.email = client.email.to_uppercase();
    let (flow_status, _) = server
        .post(
            "/api/v1/auth/register/start",
            None,
            json!({ "accountId": duplicate.account_id, "email": duplicate.email, "registrationRequest": "AA" }),
        )
        .await;
    assert_eq!(flow_status, StatusCode::CONFLICT);

    let token = client.login(server).await;
    let (status, account) = server
        .request(Method::GET, "/api/v1/account", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(account["accountId"], client.account_id);
    assert_eq!(
        account["kdfParams"]["memoryKib"],
        KdfParams::DEFAULT.memory_kib
    );
    let unlocked = Keyring::unlock(
        &client.auk,
        &client.account_id,
        account["encryptedAccountKey"].as_str().unwrap(),
    );
    assert!(unlocked.is_ok());

    assert_eq!(
        client.login_with(server, b"wrong secret").await,
        Err(StatusCode::UNAUTHORIZED)
    );

    let (status, _) = server
        .post("/api/v1/auth/logout", Some(&token), json!({}))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = server
        .request(Method::GET, "/api/v1/account", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

async fn prelogin_does_not_reveal_accounts(server: &TestServer) {
    let client = Client::new();
    client.register(server).await;
    let (status, known) = server
        .post(
            "/api/v1/auth/prelogin",
            None,
            json!({ "email": client.email }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(known["accountId"], client.account_id);

    let unknown_email = format!("{}@example.com", id::new_id().unwrap());
    let (_, first) = server
        .post(
            "/api/v1/auth/prelogin",
            None,
            json!({ "email": unknown_email }),
        )
        .await;
    let (_, second) = server
        .post(
            "/api/v1/auth/prelogin",
            None,
            json!({ "email": unknown_email }),
        )
        .await;
    assert_eq!(first, second, "fake answers must be stable");
    assert!(id::is_valid_id(first["accountId"].as_str().unwrap()));
    assert_eq!(
        encoding::decode(first["kdfSalt"].as_str().unwrap())
            .unwrap()
            .len(),
        16
    );

    // Logging in with an unknown email fails like a wrong password.
    let stranger = Client {
        email: unknown_email,
        ..Client::new()
    };
    assert_eq!(
        stranger.login_with(server, &stranger.auth_secret).await,
        Err(StatusCode::UNAUTHORIZED)
    );
}

async fn items_sync_and_conflicts(server: &TestServer) {
    let client = Client::new();
    let (keyring, vault_id) = client.register(server).await;
    let token = client.login(server).await;

    let (status, initial) = server
        .request(Method::GET, "/api/v1/sync", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(initial["vaults"].as_array().unwrap().len(), 1);
    let cursor = initial["cursor"].as_i64().unwrap();

    let item_id = id::new_id().unwrap();
    let put = |revision: u64, data: &str| {
        json!({
            "vaultId": vault_id,
            "revision": revision,
            "encryptedData": keyring.encrypt_item(&vault_id, &item_id, revision, data).unwrap(),
        })
    };
    let uri = format!("/api/v1/items/{item_id}");

    let (status, body) = server
        .request(
            Method::PUT,
            &uri,
            Some(&token),
            Some(put(1, r#"{"title":"a"}"#)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = server
        .request(
            Method::PUT,
            &uri,
            Some(&token),
            Some(put(2, r#"{"title":"b"}"#)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // A stale write is rejected with the current revision.
    let (status, body) = server
        .request(
            Method::PUT,
            &uri,
            Some(&token),
            Some(put(2, r#"{"title":"c"}"#)),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["details"]["currentRevision"], 2);

    let (_, delta) = server
        .request(
            Method::GET,
            &format!("/api/v1/sync?since={cursor}"),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(delta["vaults"].as_array().unwrap().len(), 0);
    let items = delta["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["revision"], 2);
    let decrypted = keyring
        .decrypt_item(
            &vault_id,
            &item_id,
            2,
            items[0]["encryptedData"].as_str().unwrap(),
        )
        .unwrap();
    assert_eq!(decrypted, r#"{"title":"b"}"#);
    let cursor = delta["cursor"].as_i64().unwrap();

    let (status, _) = server
        .request(
            Method::DELETE,
            &format!("{uri}?revision=3"),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, delta) = server
        .request(
            Method::GET,
            &format!("/api/v1/sync?since={cursor}"),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(delta["items"][0]["deleted"], true);
    assert_eq!(delta["items"][0]["encryptedData"], Value::Null);

    // A second vault and a metadata update.
    let mut keyring = keyring;
    let vault = keyring.create_vault(r#"{"name":"Work"}"#).unwrap();
    let (status, _) = server
        .post(
            "/api/v1/vaults",
            Some(&token),
            json!({ "id": vault.id, "encryptedKey": vault.encrypted_key, "encryptedMeta": vault.encrypted_meta }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let meta = keyring
        .encrypt_vault_meta(&vault.id, r#"{"name":"Office"}"#)
        .unwrap();
    let (status, body) = server
        .request(
            Method::PUT,
            &format!("/api/v1/vaults/{}", vault.id),
            Some(&token),
            Some(json!({ "revision": 2, "encryptedMeta": meta })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

async fn accounts_are_isolated(server: &TestServer) {
    let alice = Client::new();
    let (keyring, vault_id) = alice.register(server).await;
    let alice_token = alice.login(server).await;
    let mallory = Client::new();
    mallory.register(server).await;
    let mallory_token = mallory.login(server).await;

    let item_id = id::new_id().unwrap();
    let body = json!({
        "vaultId": vault_id,
        "revision": 1,
        "encryptedData": keyring.encrypt_item(&vault_id, &item_id, 1, "{}").unwrap(),
    });
    let uri = format!("/api/v1/items/{item_id}");
    let (status, _) = server
        .request(Method::PUT, &uri, Some(&alice_token), Some(body.clone()))
        .await;
    assert_eq!(status, StatusCode::OK);

    // Mallory can neither write into Alice's vault nor overwrite or delete her item.
    let (status, _) = server
        .request(Method::PUT, &uri, Some(&mallory_token), Some(body))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = server
        .request(
            Method::DELETE,
            &format!("{uri}?revision=2"),
            Some(&mallory_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, sync) = server
        .request(Method::GET, "/api/v1/sync", Some(&mallory_token), None)
        .await;
    assert!(sync["items"].as_array().unwrap().is_empty());
    assert!(
        sync["vaults"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["id"] != vault_id)
    );
}

async fn requests_need_a_session(server: &TestServer) {
    for (method, uri) in [
        (Method::GET, "/api/v1/account"),
        (Method::GET, "/api/v1/sync"),
        (Method::POST, "/api/v1/auth/logout"),
    ] {
        let (status, _) = server.request(method.clone(), uri, None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri}");
        let (status, _) = server.request(method, uri, Some("not-a-token"), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}
