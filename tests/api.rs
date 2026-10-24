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

#[path = "api/admin.rs"]
mod admin;

struct TestServer {
    app: Router,
    state: AppState,
    /// Listed in `PASSBOX_ADMIN_EMAILS`.
    env_admin_email: String,
}

impl TestServer {
    async fn new(database_url: &str) -> Self {
        let db = passbox_server::db::connect(database_url).await.unwrap();
        Self::with_db(db).await
    }

    /// A second server process on the same database, with its own rate
    /// limits.
    async fn with_db(db: passbox_server::db::Db) -> Self {
        let mut state = AppState::load(db).await.unwrap();
        // Lets tests pick the client IP with `X-Forwarded-For`. Requests
        // without it count as IP "unknown".
        state.trust_proxy = true;
        let env_admin_email = format!("{}@env-admin.example", id::new_id().unwrap());
        state.admin_emails = std::sync::Arc::new(vec![env_admin_email.clone()]);
        Self {
            app: passbox_server::routes::router(&Config::default(), state.clone()),
            state,
            env_admin_email,
        }
    }

    fn db(&self) -> &passbox_server::db::Db {
        &self.state.db
    }

    async fn request(
        &self,
        method: Method,
        uri: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        self.request_from(None, method, uri, token, body).await
    }

    async fn request_from(
        &self,
        ip: Option<&str>,
        method: Method,
        uri: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        if let Some(ip) = ip {
            builder = builder.header("x-forwarded-for", ip);
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

struct Login {
    token: String,
    device_token: String,
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
        self.try_login(server, auth_secret, None, None)
            .await
            .map(|login| login.token)
            .map_err(|(status, _)| status)
    }

    /// Runs a login from `ip` (or IP "unknown"), optionally presenting a
    /// device token. Fails with the status and body of the first rejected
    /// request.
    async fn try_login(
        &self,
        server: &TestServer,
        auth_secret: &[u8],
        ip: Option<&str>,
        device_token: Option<&str>,
    ) -> Result<Login, (StatusCode, Value)> {
        let (flow, request) = ClientLoginFlow::start(auth_secret).unwrap();
        let mut start =
            json!({ "email": self.email, "credentialRequest": encoding::encode(&request) });
        if let Some(device_token) = device_token {
            start["deviceToken"] = json!(device_token);
        }
        let (status, body) = server
            .request_from(
                ip,
                Method::POST,
                "/api/v1/auth/login/start",
                None,
                Some(start),
            )
            .await;
        if status != StatusCode::OK {
            return Err((status, body));
        }
        let response = encoding::decode(body["credentialResponse"].as_str().unwrap()).unwrap();
        // With a wrong secret the client detects the failure itself; send a
        // garbage finalization to check the server rejects it too.
        let finalization = match flow.finish(&response) {
            Ok(finish) => finish.finalization,
            Err(_) => vec![0u8; 64],
        };
        let (status, body) = server
            .request_from(
                ip,
                Method::POST,
                "/api/v1/auth/login/finish",
                None,
                Some(json!({
                    "loginId": body["loginId"],
                    "credentialFinalization": encoding::encode(&finalization),
                })),
            )
            .await;
        if status == StatusCode::OK {
            Ok(Login {
                token: body["token"].as_str().unwrap().to_owned(),
                device_token: body["deviceToken"].as_str().unwrap().to_owned(),
            })
        } else {
            Err((status, body))
        }
    }

    async fn login(&self, server: &TestServer) -> String {
        self.login_with(server, &self.auth_secret).await.unwrap()
    }
}

async fn run_all(database_url: &str) {
    let server = TestServer::new(database_url).await;
    // First: the first account on a fresh server becomes instance admin.
    admin::instance_administration(&TestServer::with_db(server.db().clone()).await).await;
    registration_and_login(&server).await;
    prelogin_does_not_reveal_accounts(&server).await;
    items_sync_and_conflicts(&server).await;
    accounts_are_isolated(&server).await;
    requests_need_a_session(&server).await;
    cross_origin_requests_are_allowed_without_credentials(&server).await;
    sessions_and_activity_log(&server).await;
    master_password_change(&server).await;
    known_devices_survive_email_lockout(&server).await;
    security_headers_are_set(&server).await;
    two_factor_totp_and_recovery_codes(&server).await;
    two_factor_remember_device(&server).await;
    two_factor_security_keys(&server).await;
    two_factor_rate_limits(&server).await;
    // Last: it locks out an email and counts failures for the test IP.
    failed_logins_are_rate_limited(&server).await;
}

async fn sessions_and_activity_log(server: &TestServer) {
    let client = Client::new();
    client.register(server).await;
    let laptop = client.login(server).await;
    let phone = client.login(server).await;

    let (status, sessions) = server
        .request(Method::GET, "/api/v1/sessions", Some(&laptop), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let sessions = sessions.as_array().unwrap().clone();
    assert_eq!(sessions.len(), 2);
    assert_eq!(sessions.iter().filter(|s| s["current"] == true).count(), 1);
    let phone_session = sessions.iter().find(|s| s["current"] == false).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // Signing out the phone from the laptop invalidates the phone's token.
    let (status, _) = server
        .request(
            Method::DELETE,
            &format!("/api/v1/sessions/{phone_session}"),
            Some(&laptop),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = server
        .request(Method::GET, "/api/v1/account", Some(&phone), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Other accounts' sessions cannot be revoked.
    let stranger = Client::new();
    stranger.register(server).await;
    let stranger_token = stranger.login(server).await;
    let (status, sessions) = server
        .request(Method::GET, "/api/v1/sessions", Some(&laptop), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let laptop_session = sessions[0]["id"].as_str().unwrap().to_owned();
    let (status, _) = server
        .request(
            Method::DELETE,
            &format!("/api/v1/sessions/{laptop_session}"),
            Some(&stranger_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let tablet = client.login(server).await;
    let (status, _) = server
        .post("/api/v1/sessions/revoke-others", Some(&laptop), json!({}))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = server
        .request(Method::GET, "/api/v1/account", Some(&tablet), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = server
        .request(Method::GET, "/api/v1/account", Some(&laptop), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    assert!(client.login_with(server, b"wrong").await.is_err());
    let (status, events) = server
        .request(Method::GET, "/api/v1/account/events", Some(&laptop), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let kinds: Vec<&str> = events
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    for kind in [
        "account_created",
        "login",
        "login_failed",
        "session_revoked",
        "other_sessions_revoked",
    ] {
        assert!(kinds.contains(&kind), "missing {kind} in {kinds:?}");
    }
    // Newest first.
    assert_eq!(kinds[0], "login_failed");
}

async fn master_password_change(server: &TestServer) {
    let client = Client::new();
    let (keyring, _) = client.register(server).await;
    let current = client
        .try_login(server, &client.auth_secret, Some("10.1.0.1"), None)
        .await
        .unwrap();
    let token = current.token.clone();
    let other = client
        .try_login(server, &client.auth_secret, Some("10.1.0.2"), None)
        .await
        .unwrap();
    let other_device = other.token.clone();

    let new_auth_secret: [u8; 32] = random::bytes().unwrap();
    let new_auk = SymmetricKey::generate().unwrap();
    let (flow, request) = ClientRegistrationFlow::start(&new_auth_secret).unwrap();
    let (status, body) = server
        .post(
            "/api/v1/account/password/start",
            Some(&token),
            json!({ "registrationRequest": encoding::encode(&request) }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let upload = flow
        .finish(&encoding::decode(body["registrationResponse"].as_str().unwrap()).unwrap())
        .unwrap();
    let (status, body) = server
        .post(
            "/api/v1/account/password/finish",
            Some(&token),
            json!({
                "registrationUpload": encoding::encode(&upload),
                "kdfSalt": encoding::encode(&[9u8; 16]),
                "kdfParams": KdfParams::DEFAULT,
                "encryptedAccountKey": keyring.wrap_account_key(&new_auk).unwrap(),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // Other devices are signed out; the old password no longer works.
    let (status, _) = server
        .request(Method::GET, "/api/v1/account", Some(&other_device), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        client.login_with(server, &client.auth_secret).await,
        Err(StatusCode::UNAUTHORIZED)
    );

    // Other devices lose their device token as well: once their address is
    // locked out, they are treated like unknown devices. This device keeps
    // its token.
    for _ in 0..10 {
        let (status, _) = client
            .try_login(server, b"guess", Some("10.1.0.2"), None)
            .await
            .err()
            .unwrap();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _) = client
        .try_login(
            server,
            &new_auth_secret,
            Some("10.1.0.2"),
            Some(&other.device_token),
        )
        .await
        .err()
        .unwrap();
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    client
        .try_login(
            server,
            &new_auth_secret,
            Some("10.1.0.2"),
            Some(&current.device_token),
        )
        .await
        .unwrap();

    let new_token = client.login_with(server, &new_auth_secret).await.unwrap();
    let (_, account) = server
        .request(Method::GET, "/api/v1/account", Some(&new_token), None)
        .await;
    assert_eq!(
        encoding::decode(account["kdfSalt"].as_str().unwrap()).unwrap(),
        [9u8; 16]
    );
    assert!(
        Keyring::unlock(
            &new_auk,
            &client.account_id,
            account["encryptedAccountKey"].as_str().unwrap()
        )
        .is_ok()
    );
}

/// Failed logins by someone who knows the email must not lock the user out
/// of devices that signed in before (they present a device token), nor out
/// of other addresses until the per-email backstop is reached.
async fn known_devices_survive_email_lockout(server: &TestServer) {
    let client = Client::new();
    client.register(server).await;
    let secret = client.auth_secret;
    let laptop = client
        .try_login(server, &secret, Some("10.0.1.1"), None)
        .await
        .unwrap();

    // An attacker exhausts the limit for the email from their address.
    let attacker = Some("10.0.6.6");
    for _ in 0..10 {
        let (status, _) = client
            .try_login(server, b"guess", attacker, None)
            .await
            .err()
            .unwrap();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, body) = client
        .try_login(server, &secret, attacker, None)
        .await
        .err()
        .unwrap();
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"], "rate_limited");
    // The real remaining time of the 15 minute window.
    let retry_after = body["details"]["retryAfterSeconds"].as_u64().unwrap();
    assert!(retry_after > 14 * 60 && retry_after <= 15 * 60, "{body}");

    // The known device still signs in, even from the attacker's address,
    // and gets a new device token in exchange for the old one.
    let laptop = {
        let next = client
            .try_login(server, &secret, attacker, Some(&laptop.device_token))
            .await
            .unwrap();
        assert_ne!(next.device_token, laptop.device_token);
        next
    };
    // A new device at another address is not affected either.
    let phone = client
        .try_login(server, &secret, Some("10.0.2.2"), None)
        .await
        .unwrap();

    // Backstop: 50 failures for the email in total (10 above) from many
    // addresses lock out unknown devices everywhere.
    for i in 0..40 {
        let ip = format!("10.0.7.{i}");
        let (status, _) = client
            .try_login(server, b"guess", Some(&ip), None)
            .await
            .err()
            .unwrap();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _) = client
        .try_login(server, &secret, Some("10.0.3.3"), None)
        .await
        .err()
        .unwrap();
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    // Devices with a valid device token still sign in.
    let laptop = client
        .try_login(
            server,
            &secret,
            Some("10.0.3.3"),
            Some(&laptop.device_token),
        )
        .await
        .unwrap();
    client
        .try_login(server, &secret, Some("10.0.2.2"), Some(&phone.device_token))
        .await
        .unwrap();

    // A device token has its own failure limit, so a stolen one does not
    // allow unlimited guessing.
    for _ in 0..10 {
        let (status, _) = client
            .try_login(
                server,
                b"guess",
                Some("10.0.4.4"),
                Some(&laptop.device_token),
            )
            .await
            .err()
            .unwrap();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _) = client
        .try_login(
            server,
            &secret,
            Some("10.0.1.1"),
            Some(&laptop.device_token),
        )
        .await
        .err()
        .unwrap();
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

async fn security_headers_are_set(server: &TestServer) {
    for uri in ["/health", "/api/v1/meta"] {
        let response = server
            .app
            .clone()
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let headers = response.headers();
        assert_eq!(headers["x-frame-options"], "DENY");
        assert_eq!(headers["x-content-type-options"], "nosniff");
        assert!(
            headers["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'")
        );
        if uri.starts_with("/api/") {
            assert_eq!(headers["cache-control"], "no-store");
        }
    }
}

async fn failed_logins_are_rate_limited(server: &TestServer) {
    let client = Client::new();
    client.register(server).await;
    for _ in 0..10 {
        assert_eq!(
            client.login_with(server, b"guess").await,
            Err(StatusCode::UNAUTHORIZED)
        );
    }
    let (status, body) = server
        .post(
            "/api/v1/auth/login/start",
            None,
            json!({ "email": client.email, "credentialRequest": "AA" }),
        )
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"], "rate_limited");
    assert!(body["details"]["retryAfterSeconds"].as_u64().unwrap() > 0);
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

async fn cross_origin_requests_are_allowed_without_credentials(server: &TestServer) {
    // Preflight as sent by the desktop app before an authenticated write.
    let preflight = Request::builder()
        .method(Method::OPTIONS)
        .uri("/api/v1/items/some-id")
        .header("origin", "tauri://localhost")
        .header("access-control-request-method", "PUT")
        .header(
            "access-control-request-headers",
            "authorization,content-type",
        )
        .body(Body::empty())
        .unwrap();
    let response = server.app.clone().oneshot(preflight).await.unwrap();
    assert!(response.status().is_success(), "{}", response.status());
    let headers = response.headers();
    assert_eq!(headers["access-control-allow-origin"], "*");
    let methods = headers["access-control-allow-methods"].to_str().unwrap();
    for method in ["GET", "POST", "PUT", "DELETE"] {
        assert!(methods.contains(method), "{methods}");
    }
    let allowed = headers["access-control-allow-headers"]
        .to_str()
        .unwrap()
        .to_ascii_lowercase();
    assert!(allowed.contains("authorization"), "{allowed}");
    assert!(allowed.contains("content-type"), "{allowed}");
    assert!(headers.contains_key("access-control-max-age"));
    assert!(!headers.contains_key("access-control-allow-credentials"));

    // The actual request carries the CORS header, but never allows credentials.
    let request = Request::get("/api/v1/meta")
        .header("origin", "http://tauri.localhost")
        .body(Body::empty())
        .unwrap();
    let response = server.app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["access-control-allow-origin"], "*");
    assert!(
        !response
            .headers()
            .contains_key("access-control-allow-credentials")
    );
}

// --- Two-factor authentication -------------------------------------------------------

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The code of the authenticator app `steps` time steps from now.
fn totp_code(secret: &str, steps: i64) -> String {
    let totp = passbox_core::totp::Totp::from_base32(secret).unwrap();
    totp.generate(unix_now().saturating_add_signed(steps * 30))
}

impl Client {
    /// Runs the password step of a login from `ip` and returns the
    /// `login/finish` body: a session, or a two-factor challenge.
    async fn password_step(
        &self,
        server: &TestServer,
        ip: &str,
        device_token: Option<&str>,
        origin: Option<&str>,
    ) -> Value {
        let (flow, request) = ClientLoginFlow::start(&self.auth_secret).unwrap();
        let mut start =
            json!({ "email": self.email, "credentialRequest": encoding::encode(&request) });
        if let Some(device_token) = device_token {
            start["deviceToken"] = json!(device_token);
        }
        let (status, body) = server
            .request_from(
                Some(ip),
                Method::POST,
                "/api/v1/auth/login/start",
                None,
                Some(start),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let response = encoding::decode(body["credentialResponse"].as_str().unwrap()).unwrap();
        let finish = flow.finish(&response).unwrap();
        let mut request = json!({
            "loginId": body["loginId"],
            "credentialFinalization": encoding::encode(&finish.finalization),
            "deviceName": "Test device",
            "clientKind": "cli",
        });
        if let Some(origin) = origin {
            request["origin"] = json!(origin);
        }
        let (status, body) = server
            .request_from(
                Some(ip),
                Method::POST,
                "/api/v1/auth/login/finish",
                None,
                Some(request),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    /// A password step that must end in a two-factor challenge.
    async fn challenge(&self, server: &TestServer, ip: &str, device_token: Option<&str>) -> Value {
        let body = self.password_step(server, ip, device_token, None).await;
        assert_eq!(body["twoFactorRequired"], true, "{body}");
        assert!(
            body.get("token").is_none(),
            "no session before the second factor"
        );
        body
    }
}

async fn second_factor(server: &TestServer, ip: &str, body: Value) -> (StatusCode, Value) {
    server
        .request_from(
            Some(ip),
            Method::POST,
            "/api/v1/auth/login/two-factor",
            None,
            Some(body),
        )
        .await
}

async fn event_kinds(server: &TestServer, token: &str) -> Vec<String> {
    let (status, events) = server
        .request(Method::GET, "/api/v1/account/events", Some(token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    events
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap().to_owned())
        .collect()
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_owned())
        .collect()
}

/// Turns TOTP on with a fresh login and returns (session, secret, recovery codes).
async fn enable_totp(
    server: &TestServer,
    client: &Client,
    ip: &str,
) -> (String, String, Vec<String>) {
    let body = client.password_step(server, ip, None, None).await;
    let token = body["token"].as_str().unwrap().to_owned();
    let (status, started) = server
        .post(
            "/api/v1/account/two-factor/totp/start",
            Some(&token),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{started}");
    let secret = started["secret"].as_str().unwrap().to_owned();
    let (status, confirmed) = server
        .post(
            "/api/v1/account/two-factor/totp/confirm",
            Some(&token),
            json!({ "code": totp_code(&secret, 0) }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{confirmed}");
    (token, secret, strings(&confirmed["recoveryCodes"]))
}

fn with_code(challenge: &Value, method: &str, code: &str) -> Value {
    json!({ "challengeToken": challenge["challengeToken"], "method": method, "code": code })
}

async fn two_factor_totp_and_recovery_codes(server: &TestServer) {
    let ip = "10.20.0.1";
    let client = Client::new();
    client.register(server).await;
    let body = client.password_step(server, ip, None, None).await;
    let token = body["token"].as_str().unwrap().to_owned();

    let (status, state) = server
        .request(
            Method::GET,
            "/api/v1/account/two-factor",
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(state["enabled"], false);
    assert_eq!(state["recoveryCodesRemaining"], 0);

    // Confirming needs a pending secret; a wrong first code is refused.
    let (status, _) = server
        .post(
            "/api/v1/account/two-factor/totp/confirm",
            Some(&token),
            json!({ "code": "123456" }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, started) = server
        .post(
            "/api/v1/account/two-factor/totp/start",
            Some(&token),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let secret = started["secret"].as_str().unwrap().to_owned();
    let uri = started["uri"].as_str().unwrap();
    assert!(uri.starts_with("otpauth://totp/Passbox:"), "{uri}");
    assert!(uri.contains(&format!("secret={secret}")));
    // Differs from every code of the window (almost surely).
    let wrong = format!(
        "{:06}",
        (totp_code(&secret, 0).parse::<u32>().unwrap() + 500_000) % 1_000_000
    );
    let (status, body) = server
        .post(
            "/api/v1/account/two-factor/totp/confirm",
            Some(&token),
            json!({ "code": wrong }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_two_factor_code");
    // Until confirmed, logins need no second factor.
    let body = client.password_step(server, ip, None, None).await;
    assert!(body["token"].is_string());

    // The secret is not stored in plain text.
    let (sealed,): (String,) =
        sqlx::query_as("SELECT sealed_secret FROM two_factor_totp WHERE account_id = $1")
            .bind(&client.account_id)
            .fetch_one(server.db())
            .await
            .unwrap();
    assert!(!sealed.contains(&secret));

    let first_code = totp_code(&secret, 0);
    let (status, confirmed) = server
        .post(
            "/api/v1/account/two-factor/totp/confirm",
            Some(&token),
            json!({ "code": first_code }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{confirmed}");
    let recovery = strings(&confirmed["recoveryCodes"]);
    assert_eq!(recovery.len(), 10);
    let (_, state) = server
        .request(
            Method::GET,
            "/api/v1/account/two-factor",
            Some(&token),
            None,
        )
        .await;
    assert_eq!(state["enabled"], true);
    assert_eq!(state["totp"], true);
    assert_eq!(state["recoveryCodesRemaining"], 10);
    // A second setup is refused while one is active.
    let (status, _) = server
        .post(
            "/api/v1/account/two-factor/totp/start",
            Some(&token),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Logins now stop after the password with a challenge.
    let challenge = client.challenge(server, ip, None).await;
    assert_eq!(challenge["methods"], json!(["totp", "recovery"]));
    assert!(challenge.get("webauthn").is_none());
    // Wrong code, then the confirmation code again (replay): both refused.
    let (status, body) = second_factor(server, ip, with_code(&challenge, "totp", &wrong)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_two_factor_code");
    let (status, _) = second_factor(server, ip, with_code(&challenge, "totp", &first_code)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = second_factor(server, ip, with_code(&challenge, "sms", "1")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The next step's code works (±1 step) and creates a session.
    let next_code = totp_code(&secret, 1);
    let (status, session) =
        second_factor(server, ip, with_code(&challenge, "totp", &next_code)).await;
    assert_eq!(status, StatusCode::OK, "{session}");
    let token = session["token"].as_str().unwrap().to_owned();
    assert!(session["deviceToken"].is_string());
    let (status, _) = server
        .request(Method::GET, "/api/v1/account", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    // A challenge completes once.
    let (status, body) = second_factor(server, ip, with_code(&challenge, "totp", &next_code)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "two_factor_expired");
    // The same code cannot sign in again on a new challenge.
    let again = client.challenge(server, ip, None).await;
    let (status, _) = second_factor(server, ip, with_code(&again, "totp", &next_code)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Recovery codes work once each, in any format.
    let typed = recovery[0].to_lowercase().replace('-', " ");
    let (status, session) = second_factor(server, ip, with_code(&again, "recovery", &typed)).await;
    assert_eq!(status, StatusCode::OK, "{session}");
    assert_eq!(session["recoveryCodesRemaining"], 9);
    let token = session["token"].as_str().unwrap().to_owned();
    let challenge = client.challenge(server, ip, None).await;
    let (status, _) =
        second_factor(server, ip, with_code(&challenge, "recovery", &recovery[0])).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Changes need a recent login.
    sqlx::query("UPDATE sessions SET created_at = $1 WHERE account_id = $2")
        .bind(0i64)
        .bind(&client.account_id)
        .execute(server.db())
        .await
        .unwrap();
    let (status, body) = server
        .post(
            "/api/v1/account/two-factor/recovery-codes",
            Some(&token),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "reauthentication_required");
    let challenge = client.challenge(server, ip, None).await;
    let (_, session) =
        second_factor(server, ip, with_code(&challenge, "recovery", &recovery[1])).await;
    let token = session["token"].as_str().unwrap().to_owned();
    let (status, regenerated) = server
        .post(
            "/api/v1/account/two-factor/recovery-codes",
            Some(&token),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let fresh = strings(&regenerated["recoveryCodes"]);
    assert_eq!(fresh.len(), 10);
    // The old codes are gone.
    let challenge = client.challenge(server, ip, None).await;
    let (status, _) =
        second_factor(server, ip, with_code(&challenge, "recovery", &recovery[2])).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Turning 2FA off needs a valid second factor.
    let (status, _) = server
        .post(
            "/api/v1/account/two-factor/disable",
            Some(&token),
            json!({ "method": "recovery", "code": recovery[3] }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = server
        .post(
            "/api/v1/account/two-factor/disable",
            Some(&token),
            json!({ "method": "recovery", "code": fresh[0] }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, state) = server
        .request(
            Method::GET,
            "/api/v1/account/two-factor",
            Some(&token),
            None,
        )
        .await;
    assert_eq!(state["enabled"], false);
    assert_eq!(state["recoveryCodesRemaining"], 0);
    let body = client.password_step(server, ip, None, None).await;
    assert!(body["token"].is_string(), "{body}");

    // The owner got a mail for every change (on, new codes, off).
    let mails: Vec<(String,)> = sqlx::query_as(
        "SELECT params FROM mail_outbox WHERE recipient = $1 AND template = $2 ORDER BY created_at",
    )
    .bind(&client.email)
    .bind("two_factor_changed")
    .fetch_all(server.db())
    .await
    .unwrap();
    let changes: Vec<String> = mails
        .iter()
        .map(|(params,)| {
            serde_json::from_str::<Value>(params).unwrap()["change"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(changes, ["enabled", "changed", "disabled"], "{changes:?}");

    let kinds = event_kinds(server, &token).await;
    for kind in [
        "two_factor_enabled",
        "login_two_factor",
        "two_factor_failed",
        "recovery_code_used",
        "recovery_codes_regenerated",
        "two_factor_disabled",
    ] {
        assert!(
            kinds.iter().any(|k| k == kind),
            "missing {kind} in {kinds:?}"
        );
    }
}

async fn two_factor_remember_device(server: &TestServer) {
    let ip = "10.21.0.1";
    let client = Client::new();
    client.register(server).await;
    let (_, _, recovery) = enable_totp(server, &client, ip).await;

    // Without "remember", the device token alone does not skip the step.
    let challenge = client.challenge(server, ip, None).await;
    let (_, session) =
        second_factor(server, ip, with_code(&challenge, "recovery", &recovery[0])).await;
    let device_token = session["deviceToken"].as_str().unwrap().to_owned();
    let challenge = client.challenge(server, ip, Some(&device_token)).await;

    // With "remember", the device skips it for 30 days, also after the
    // device token is rotated by the next login.
    let mut remember = with_code(&challenge, "recovery", &recovery[1]);
    remember["rememberDevice"] = json!(true);
    let (status, session) = second_factor(server, ip, remember).await;
    assert_eq!(status, StatusCode::OK);
    let remembered = session["deviceToken"].as_str().unwrap().to_owned();
    let body = client
        .password_step(server, ip, Some(&remembered), None)
        .await;
    assert!(body["token"].is_string(), "{body}");
    let rotated = body["deviceToken"].as_str().unwrap().to_owned();
    let body = client.password_step(server, ip, Some(&rotated), None).await;
    assert!(body["token"].is_string(), "{body}");
    let token = body["token"].as_str().unwrap().to_owned();
    let current = body["deviceToken"].as_str().unwrap().to_owned();
    // The replaced token and other devices still need the second factor.
    client.challenge(server, ip, Some(&remembered)).await;
    client.challenge(server, ip, None).await;

    // Turning 2FA off and on again forgets remembered devices.
    let (status, _) = server
        .post(
            "/api/v1/account/two-factor/disable",
            Some(&token),
            json!({ "method": "recovery", "code": recovery[2] }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let body = client.password_step(server, ip, Some(&current), None).await;
    let current = body["deviceToken"].as_str().unwrap().to_owned();
    enable_totp(server, &client, ip).await;
    client.challenge(server, ip, Some(&current)).await;
}

async fn two_factor_security_keys(server: &TestServer) {
    use passbox_core::passkey::{self, Flags};
    let ip = "10.22.0.1";
    let origin = "https://passbox.example";
    let client = Client::new();
    client.register(server).await;
    let body = client.password_step(server, ip, None, None).await;
    let token = body["token"].as_str().unwrap().to_owned();

    // Security keys need https (or localhost).
    let (status, _) = server
        .post(
            "/api/v1/account/two-factor/webauthn/register/start",
            Some(&token),
            json!({ "origin": "http://127.0.0.1:8080" }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, options) = server
        .post(
            "/api/v1/account/two-factor/webauthn/register/start",
            Some(&token),
            json!({ "origin": origin }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{options}");
    let public_key = &options["publicKey"];
    assert_eq!(public_key["rp"]["id"], "passbox.example");
    assert_eq!(public_key["attestation"], "none");
    assert_eq!(public_key["pubKeyCredParams"][0]["alg"], -7);
    assert_eq!(public_key["pubKeyCredParams"][1]["alg"], -8);
    let client_data = |kind: &str, challenge: &Value| {
        json!({ "type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false })
            .to_string()
            .into_bytes()
    };

    // The authenticator: Passbox's own passkey implementation.
    let key = passkey::create("passbox.example", Flags::synced(false)).unwrap();
    let register = |registration_id: &Value, client_data_json: &[u8]| {
        json!({
            "registrationId": registration_id,
            "name": "YubiKey 5C",
            "credential": {
                "clientDataJson": encoding::encode(client_data_json),
                "attestationObject": encoding::encode(&key.attestation_object),
            },
        })
    };
    // A response for another challenge is refused (and spends the registration).
    let (status, _) = server
        .post(
            "/api/v1/account/two-factor/webauthn/register/finish",
            Some(&token),
            register(
                &options["registrationId"],
                &client_data("webauthn.create", &json!(encoding::encode(&[0; 32]))),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (_, options) = server
        .post(
            "/api/v1/account/two-factor/webauthn/register/start",
            Some(&token),
            json!({ "origin": origin }),
        )
        .await;
    let (status, added) = server
        .post(
            "/api/v1/account/two-factor/webauthn/register/finish",
            Some(&token),
            register(
                &options["registrationId"],
                &client_data("webauthn.create", &options["publicKey"]["challenge"]),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{added}");
    assert_eq!(added["recoveryCodes"].as_array().unwrap().len(), 10);
    let key_id = added["id"].as_str().unwrap().to_owned();
    let (_, state) = server
        .request(
            Method::GET,
            "/api/v1/account/two-factor",
            Some(&token),
            None,
        )
        .await;
    assert_eq!(state["enabled"], true);
    assert_eq!(state["totp"], false);
    assert_eq!(state["securityKeys"][0]["name"], "YubiKey 5C");
    // The last factor cannot be removed on its own.
    let (status, _) = server
        .request(
            Method::DELETE,
            &format!("/api/v1/account/two-factor/webauthn/{key_id}"),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Signing in: the challenge carries the WebAuthn request options.
    let challenge = client.password_step(server, ip, None, Some(origin)).await;
    assert_eq!(challenge["methods"], json!(["webauthn", "recovery"]));
    let request = &challenge["webauthn"];
    assert_eq!(request["rpId"], "passbox.example");
    assert_eq!(
        request["allowCredentials"][0]["id"],
        encoding::encode(&key.credential_id)
    );
    let sign = |challenge: &Value, other_origin: Option<&str>| {
        let mut data = client_data("webauthn.get", challenge);
        if let Some(other) = other_origin {
            data = String::from_utf8(data)
                .unwrap()
                .replace(origin, other)
                .into_bytes();
        }
        let assertion = passkey::assert(
            &key.private_key_pkcs8,
            "passbox.example",
            &data,
            0,
            Flags::synced(false),
        )
        .unwrap();
        json!({
            "credentialId": encoding::encode(&key.credential_id),
            "clientDataJson": encoding::encode(&data),
            "authenticatorData": encoding::encode(&assertion.authenticator_data),
            "signature": encoding::encode(&assertion.signature),
        })
    };
    // A phishing page's assertion (other origin) is refused.
    let (status, _) = second_factor(
        server,
        ip,
        json!({
            "challengeToken": challenge["challengeToken"],
            "method": "webauthn",
            "webauthn": sign(&request["challenge"], Some("https://passbox.example.evil.test")),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, session) = second_factor(
        server,
        ip,
        json!({
            "challengeToken": challenge["challengeToken"],
            "method": "webauthn",
            "webauthn": sign(&request["challenge"], None),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    let token = session["token"].as_str().unwrap().to_owned();

    // Turning 2FA off with the security key.
    let (status, check) = server
        .post(
            "/api/v1/account/two-factor/challenge",
            Some(&token),
            json!({ "origin": origin }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{check}");
    let (status, _) = server
        .post(
            "/api/v1/account/two-factor/disable",
            Some(&token),
            json!({
                "method": "webauthn",
                "challengeToken": check["challengeToken"],
                "webauthn": sign(&check["webauthn"]["challenge"], None),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let body = client.password_step(server, ip, None, None).await;
    assert!(body["token"].is_string());
}

async fn two_factor_rate_limits(server: &TestServer) {
    let ip = "10.23.0.1";
    let client = Client::new();
    client.register(server).await;
    let (_, _, recovery) = enable_totp(server, &client, ip).await;
    // Ten wrong codes over two challenges lock the account's second step,
    // even with a correct code and from another address.
    for round in 0..2 {
        let challenge = client.challenge(server, ip, None).await;
        let attempt = with_code(&challenge, "recovery", "0000-0000-0000-0000");
        for _ in 0..5 {
            let (_, body) = second_factor(server, ip, attempt.clone()).await;
            assert_eq!(body["error"], "invalid_two_factor_code");
        }
        if round == 0 {
            // A challenge allows five attempts.
            let (_, body) = second_factor(server, ip, attempt).await;
            assert_eq!(body["error"], "two_factor_expired");
        }
    }
    let other_ip = "10.23.0.2";
    let challenge = client.challenge(server, other_ip, None).await;
    let (status, body) = second_factor(
        server,
        other_ip,
        with_code(&challenge, "recovery", &recovery[0]),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(body["details"]["retryAfterSeconds"].as_u64().unwrap() > 0);
}
