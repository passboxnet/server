//! End-to-end tests of the HTTP API using the real client-side cryptography.
//!
//! Runs against PostgreSQL: `PASSBOX_TEST_DATABASE_URL` points at a
//! superuser connection, and the run creates (and drops) a database of its
//! own with the production roles and row level security
//! (`passbox_server::testing`).

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use passbox_core::aead::SymmetricKey;
use passbox_core::kdf::KdfParams;
use passbox_core::keyring::Keyring;
use passbox_core::opaque::{ClientLoginFlow, ClientRegistrationFlow};
use passbox_core::sharing::objects::{OrgKind, OrgRole, PrincipalType, VaultRole};
use passbox_core::{encoding, id, random};
use passbox_server::config::Config;
use passbox_server::state::AppState;
use serde_json::{Value, json};
use tower::ServiceExt;

#[path = "api/admin.rs"]
mod admin;
#[path = "api/breach.rs"]
mod breach;
#[path = "api/comfort.rs"]
mod comfort;
#[path = "api/email_change.rs"]
mod email_change;
#[path = "api/extensions.rs"]
mod extensions;
#[path = "api/guests.rs"]
mod guests;
#[path = "api/icons.rs"]
mod icons;
#[path = "api/org_admin.rs"]
mod org_admin;
#[path = "api/recovery.rs"]
mod recovery;
#[path = "api/rls.rs"]
mod rls;
#[path = "api/sso.rs"]
mod sso;

struct TestServer {
    app: Router,
    state: AppState,
    /// Listed in `PASSBOX_ADMIN_EMAILS`.
    env_admin_email: String,
    /// A superuser pool on the test database (bypasses row level security),
    /// for checking and changing rows directly.
    owner: sqlx::PgPool,
}

impl TestServer {
    /// A second server process on the same database, with its own rate
    /// limits.
    async fn with_db(db: passbox_server::db::Db, owner: sqlx::PgPool) -> Self {
        Self::with_extensions(
            db,
            owner,
            &passbox_server::ext::Extensions::default(),
            |_| {},
        )
        .await
    }

    /// A server process with the extensions of an embedding program;
    /// `configure` adjusts the state first.
    async fn with_extensions(
        db: passbox_server::db::Db,
        owner: sqlx::PgPool,
        ext: &passbox_server::ext::Extensions,
        configure: impl FnOnce(&mut AppState),
    ) -> Self {
        let mut state = AppState::load(db).await.unwrap();
        configure(&mut state);
        ext.install(&mut state);
        // Lets tests pick the client IP with `X-Forwarded-For`. Requests
        // without it count as IP "unknown".
        state.trust_proxy = true;
        let env_admin_email = format!("{}@env-admin.example", id::new_id().unwrap());
        state.admin_emails = std::sync::Arc::new(vec![env_admin_email.clone()]);
        Self {
            app: passbox_server::routes::router_with(&Config::default(), state.clone(), ext),
            state,
            env_admin_email,
            owner,
        }
    }

    /// Direct SQL on the test database, past row level security.
    fn db(&self) -> &sqlx::PgPool {
        &self.owner
    }

    /// The server's own database pools (application roles).
    fn pools(&self) -> &passbox_server::db::Db {
        &self.state.db
    }

    /// Another server process on the same database.
    async fn sibling(&self) -> Self {
        Self::with_db(self.pools().clone(), self.owner.clone()).await
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

async fn run_all(database: &passbox_server::testing::TestDatabase) {
    let server = TestServer::with_db(database.db.clone(), database.owner.clone()).await;
    // First: the first account on a fresh server becomes instance admin.
    admin::instance_administration(&server.sibling().await).await;
    registration_and_login(&server).await;
    prelogin_does_not_reveal_accounts(&server).await;
    items_sync_and_conflicts(&server).await;
    accounts_are_isolated(&server).await;
    requests_need_a_session(&server).await;
    cross_origin_requests_are_allowed_without_credentials(&server).await;
    sessions_and_activity_log(&server).await;
    master_password_change(&server).await;
    email_change::email_change(&server).await;
    known_devices_survive_email_lockout(&server).await;
    item_history(&server).await;
    website_icons(&server).await;
    icons::shared_store(&server, database).await;
    icons::icon_requests_are_not_logged(&server).await;
    breach::breach_proxy_and_monitoring(&server).await;
    breach::breach_catalog(&server, database).await;
    security_headers_are_set(&server).await;
    two_factor_totp_and_recovery_codes(&server).await;
    two_factor_remember_device(&server).await;
    two_factor_security_keys(&server).await;
    two_factor_rate_limits(&server).await;
    key_pairs_and_directory(&server).await;
    organizations_and_shared_vaults(&server).await;
    recovery::recovery_code(&server).await;
    recovery::organization_recovery(&server).await;
    recovery::emergency_access(&server).await;
    recovery::device_links(&server).await;
    sso::single_sign_on(&server).await;
    org_admin::organization_administration(&server).await;
    comfort::comfort(&server).await;
    guests::guests_and_defaults(&server).await;
    extensions::extensions(&server, database).await;
    // Its own rate limits: the last test counts failures for the test IP.
    rls::policies(&server.sibling().await, database).await;
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

// --- Sharing: key pairs, key directory, organizations, shared vaults -----------

impl Client {
    /// Registers from `ip` (sharing tests use their own IPs so the auth rate
    /// limit of the other tests is not affected) and returns the keyring.
    async fn register_from(&self, server: &TestServer, ip: &str) -> Keyring {
        let (flow, request) = ClientRegistrationFlow::start(&self.auth_secret).unwrap();
        let (status, body) = server
            .request_from(
                Some(ip),
                Method::POST,
                "/api/v1/auth/register/start",
                None,
                Some(json!({
                    "accountId": self.account_id,
                    "email": self.email,
                    "registrationRequest": encoding::encode(&request),
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let response = encoding::decode(body["registrationResponse"].as_str().unwrap()).unwrap();
        let upload = flow.finish(&response).unwrap();
        let (mut keyring, encrypted_account_key) =
            Keyring::create(&self.auk, &self.account_id).unwrap();
        let vault = keyring.create_vault(r#"{"name":"Private"}"#).unwrap();
        let (status, body) = server
            .request_from(
                Some(ip),
                Method::POST,
                "/api/v1/auth/register/finish",
                None,
                Some(json!({
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
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        keyring
    }
}

/// A registered, signed-in account with published key pairs.
struct Member {
    client: Client,
    keyring: Keyring,
    token: String,
}

impl Member {
    async fn new(server: &TestServer, ip: &str) -> Self {
        let client = Client::new();
        let mut keyring = client.register_from(server, ip).await;
        let token = client
            .try_login(server, &client.auth_secret, Some(ip), None)
            .await
            .unwrap()
            .token;
        let upload = keyring.create_account_keys(1).unwrap();
        let (status, body) = server
            .request(
                Method::PUT,
                "/api/v1/account/keys",
                Some(&token),
                Some(serde_json::to_value(&upload).unwrap()),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        Self {
            client,
            keyring,
            token,
        }
    }

    fn id(&self) -> &str {
        &self.client.account_id
    }

    async fn call(
        &self,
        server: &TestServer,
        method: Method,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        server.request(method, uri, Some(&self.token), body).await
    }

    /// Full sharing sync: applies the delta and uploads own key copies.
    async fn sync(
        &mut self,
        server: &TestServer,
    ) -> (Value, passbox_core::sharing::state::SharingReport) {
        let (status, body) = self
            .call(server, Method::GET, "/api/v1/sync?since=0&sharing=1", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let delta: passbox_core::sharing::data::SharingDelta =
            serde_json::from_value(body["sharing"].clone()).unwrap();
        let report = self.keyring.apply_sharing(delta);
        for wrapped in &report.wrapped_keys {
            let (status, _) = self
                .call(
                    server,
                    Method::PUT,
                    &format!(
                        "/api/v1/vaults/{}/keys/{}/wrapped",
                        wrapped.vault_id, wrapped.key_epoch
                    ),
                    Some(json!({ "wrappedKey": wrapped.wrapped_key })),
                )
                .await;
            assert_eq!(status, StatusCode::NO_CONTENT);
        }
        (body, report)
    }

    async fn lookup(&mut self, server: &TestServer, account_id: &str) -> String {
        let since = self.keyring.trust_store().directory.size;
        let (status, body) = self
            .call(
                server,
                Method::GET,
                &format!("/api/v1/keys/{account_id}?since={since}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let response: passbox_core::directory::LookupResponse =
            serde_json::from_value(body).unwrap();
        self.keyring
            .verify_directory_lookup(account_id, &response)
            .unwrap()
            .fingerprint
    }

    async fn put_item(
        &self,
        server: &TestServer,
        vault_id: &str,
        epoch: u32,
        item_id: &str,
        revision: u64,
    ) -> StatusCode {
        let encrypted = self
            .keyring
            .encrypt_item_at(vault_id, epoch, item_id, revision, r#"{"title":"Shared"}"#)
            .unwrap_or_else(|_| encoding::encode(&[0u8; 64]));
        self.call(
            server,
            Method::PUT,
            &format!("/api/v1/items/{item_id}"),
            Some(json!({ "vaultId": vault_id, "revision": revision, "encryptedData": encrypted, "keyEpoch": epoch })),
        )
        .await
        .0
    }
}

async fn invite_and_confirm(
    server: &TestServer,
    admin: &mut Member,
    member: &mut Member,
    org_id: &str,
    role: &str,
) {
    let (status, body) = admin
        .call(
            server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/invitations"),
            Some(json!({ "email": member.client.email, "role": role })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let token = body["token"].as_str().unwrap().to_owned();
    let (status, body) = member
        .call(
            server,
            Method::POST,
            "/api/v1/invitations/accept",
            Some(json!({ "token": token })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    admin.sync(server).await;
    let fingerprint = admin.lookup(server, member.id()).await;
    let confirm = admin
        .keyring
        .confirm_member(org_id, member.id(), 2)
        .unwrap();
    assert_eq!(confirm.fingerprint, fingerprint);
    let (status, body) = admin
        .call(
            server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/members/{}/confirm", member.id()),
            Some(serde_json::to_value(&confirm).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    admin.sync(server).await;
}

async fn key_pairs_and_directory(server: &TestServer) {
    let mut alice = Member::new(server, "10.9.0.1").await;
    let bob = Member::new(server, "10.9.0.2").await;

    // The own keys come back exactly; republishing them is idempotent, other
    // keys are refused.
    let (status, own) = alice
        .call(server, Method::GET, "/api/v1/account/keys", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let mut reloaded = Keyring::unlock(&alice.client.auk, alice.id(), &{
        let (_, account) = alice
            .call(server, Method::GET, "/api/v1/account", None)
            .await;
        account["encryptedAccountKey"].as_str().unwrap().to_owned()
    })
    .unwrap();
    reloaded
        .load_account_keys(
            own["bundle"].as_str().unwrap(),
            own["bundleSignature"].as_str().unwrap(),
            own["encryptedPrivate"].as_str().unwrap(),
        )
        .unwrap();
    assert_eq!(
        reloaded.own_bundle().unwrap(),
        alice.keyring.own_bundle().unwrap()
    );
    let (status, _) = alice
        .call(
            server,
            Method::PUT,
            "/api/v1/account/keys",
            Some(own.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let mut other = Keyring::create(&alice.client.auk, alice.id()).unwrap().0;
    let other_keys = other.create_account_keys(5).unwrap();
    let (status, _) = alice
        .call(
            server,
            Method::PUT,
            "/api/v1/account/keys",
            Some(serde_json::to_value(&other_keys).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    // Someone else's bundle cannot be published under one's own account.
    let (status, _) = bob
        .call(server, Method::PUT, "/api/v1/account/keys", Some(own))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Directory lookups verify against the signed head, before and after
    // the log grew.
    alice.lookup(server, bob.id()).await;
    let carol = Member::new(server, "10.9.0.3").await;
    alice.lookup(server, bob.id()).await;
    alice.lookup(server, carol.id()).await;
    assert!(alice.keyring.trust_store().directory.size >= 3);
    // Self-monitoring: the directory lists the account's own key.
    let own_id = alice.id().to_owned();
    alice.lookup(server, &own_id).await;
    let (status, head) = alice
        .call(server, Method::GET, "/api/v1/keys/head", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(head["signature"].is_string());
    let (status, page) = alice
        .call(server, Method::GET, "/api/v1/keys/log?from=1&limit=2", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["entries"].as_array().unwrap().len(), 2);
    let (status, _) = server
        .request(
            Method::GET,
            &format!("/api/v1/keys/{}", bob.id()),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = alice
        .call(
            server,
            Method::GET,
            &format!("/api/v1/keys/{}", id::new_id().unwrap()),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

async fn organizations_and_shared_vaults(server: &TestServer) {
    let mut alice = Member::new(server, "10.9.1.1").await;
    let mut bob = Member::new(server, "10.9.1.2").await;
    let mut carol = Member::new(server, "10.9.1.3").await;
    let mut mallory = Member::new(server, "10.9.1.4").await;

    // A family with its family vault.
    let org = alice
        .keyring
        .create_org(
            OrgKind::Family,
            r#"{"name":"Doe"}"#,
            Some(r#"{"name":"Family"}"#),
            1,
        )
        .unwrap();
    let org_id = org.id.clone();
    let vault_id = org.vault.as_ref().unwrap().id.clone();
    let mut forged = org.clone();
    forged.genesis_signature = encoding::encode(&[0u8; 64]);
    let (status, _) = alice
        .call(
            server,
            Method::POST,
            "/api/v1/orgs",
            Some(serde_json::to_value(&forged).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "forged genesis");
    let mut without_vault = org.clone();
    without_vault.vault = None;
    let (status, _) = alice
        .call(
            server,
            Method::POST,
            "/api/v1/orgs",
            Some(serde_json::to_value(&without_vault).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "family needs its vault");
    let (status, body) = alice
        .call(
            server,
            Method::POST,
            "/api/v1/orgs",
            Some(serde_json::to_value(&org).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (_, report) = alice.sync(server).await;
    assert!(
        report.view.warnings.is_empty(),
        "{:?}",
        report.view.warnings
    );
    assert_eq!(report.view.orgs[0].name.as_deref(), Some("Doe"));
    assert_eq!(report.view.vaults[0].role.as_deref(), Some("manage"));

    // Non-members see nothing.
    let (status, _) = mallory
        .call(server, Method::GET, &format!("/api/v1/orgs/{org_id}"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = mallory
        .call(
            server,
            Method::GET,
            &format!("/api/v1/vaults/{vault_id}/members"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        mallory
            .put_item(server, &vault_id, 1, &id::new_id().unwrap(), 1)
            .await,
        StatusCode::NOT_FOUND
    );
    let (status, _) = mallory
        .call(
            server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/invitations"),
            Some(json!({ "email": "x@example.com", "role": "member" })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Invitation: preview, wrong account, accept once.
    let (status, body) = alice
        .call(
            server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/invitations"),
            Some(json!({ "email": bob.client.email.to_uppercase(), "role": "member" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let token = body["token"].as_str().unwrap().to_owned();
    assert_eq!(body["path"], format!("/invite/{token}"));
    let (status, preview) = server
        .request_from(
            Some("10.9.1.9"),
            Method::GET,
            &format!("/api/v1/invitations/{token}"),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(preview["email"], bob.client.email);
    assert_eq!(preview["orgKind"], "family");
    assert_eq!(preview["inviterEmail"], alice.client.email);
    let (status, invitations) = alice
        .call(
            server,
            Method::GET,
            &format!("/api/v1/orgs/{org_id}/invitations"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(invitations.as_array().unwrap().len(), 1);
    assert!(invitations[0].get("token").is_none());
    let (status, _) = carol
        .call(
            server,
            Method::POST,
            "/api/v1/invitations/accept",
            Some(json!({ "token": token })),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "invitation is for another email"
    );
    let (status, _) = bob
        .call(
            server,
            Method::POST,
            "/api/v1/invitations/accept",
            Some(json!({ "token": token })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = bob
        .call(
            server,
            Method::POST,
            "/api/v1/invitations/accept",
            Some(json!({ "token": token })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "single use");
    // Accepted, not confirmed: no vault access, cannot confirm others.
    let (_, report) = bob.sync(server).await;
    assert!(report.view.vaults.is_empty());
    assert_eq!(report.view.orgs[0].status, "accepted");
    let (status, _) = bob
        .call(
            server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/members/{}/confirm", bob.id()),
            Some(json!({})),
        )
        .await;
    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::UNPROCESSABLE_ENTITY,
        "{status}"
    );

    // Confirmation by the admin's client, after a directory lookup.
    alice.sync(server).await;
    alice.lookup(server, bob.id()).await;
    let confirm = alice.keyring.confirm_member(&org_id, bob.id(), 2).unwrap();
    let mut wrong = confirm.clone();
    wrong.attestation_signature = encoding::encode(&[1u8; 64]);
    let (status, _) = alice
        .call(
            server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/members/{}/confirm", bob.id()),
            Some(serde_json::to_value(&wrong).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "forged attestation");
    let (status, body) = alice
        .call(
            server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/members/{}/confirm", bob.id()),
            Some(serde_json::to_value(&confirm).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    alice.sync(server).await;

    // Share the family vault with Bob, view only.
    let change = alice
        .keyring
        .share_vault(
            &vault_id,
            PrincipalType::Account,
            bob.id(),
            VaultRole::View,
            3,
        )
        .unwrap();
    let (status, body) = alice
        .call(
            server,
            Method::POST,
            &format!("/api/v1/vaults/{vault_id}/members"),
            Some(serde_json::to_value(&change).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Replaying the same change fails (the manifest version is taken).
    let (status, _) = alice
        .call(
            server,
            Method::POST,
            &format!("/api/v1/vaults/{vault_id}/members"),
            Some(serde_json::to_value(&change).unwrap()),
        )
        .await;
    assert_ne!(status, StatusCode::OK);
    alice.sync(server).await;
    let item_id = id::new_id().unwrap();
    assert_eq!(
        alice.put_item(server, &vault_id, 1, &item_id, 1).await,
        StatusCode::OK
    );
    assert_eq!(
        alice
            .put_item(server, &vault_id, 0, &id::new_id().unwrap(), 1)
            .await,
        StatusCode::CONFLICT,
        "wrong key epoch"
    );

    let (body, report) = bob.sync(server).await;
    assert!(
        report.view.warnings.is_empty(),
        "{:?}",
        report.view.warnings
    );
    assert_eq!(report.view.vaults[0].role.as_deref(), Some("view"));
    let item = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == item_id.as_str())
        .unwrap();
    assert_eq!(item["keyEpoch"], 1);
    assert_eq!(
        bob.keyring
            .decrypt_item_at(
                &vault_id,
                1,
                &item_id,
                1,
                item["encryptedData"].as_str().unwrap()
            )
            .unwrap(),
        r#"{"title":"Shared"}"#
    );
    // A second sync uses the own wrapped copy.
    let (_, report) = bob.sync(server).await;
    assert!(report.wrapped_keys.is_empty());
    // View-only members cannot write, share or rotate.
    assert_eq!(
        bob.put_item(server, &vault_id, 1, &item_id, 2).await,
        StatusCode::FORBIDDEN
    );
    let (status, _) = bob
        .call(
            server,
            Method::DELETE,
            &format!("/api/v1/items/{item_id}?revision=2"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = bob
        .call(
            server,
            Method::POST,
            &format!("/api/v1/vaults/{vault_id}/members"),
            Some(serde_json::to_value(&change).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // Legacy sync (without sharing=1) shows personal vaults only.
    let (_, legacy) = bob
        .call(server, Method::GET, "/api/v1/sync?since=0", None)
        .await;
    assert!(legacy.get("sharing").is_none());
    assert!(
        legacy["vaults"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["id"] != vault_id.as_str())
    );

    // A manifest not signed by the uploader is refused.
    let mut forged = alice
        .keyring
        .share_vault(
            &vault_id,
            PrincipalType::Account,
            bob.id(),
            VaultRole::Edit,
            4,
        )
        .unwrap();
    let honest = forged.clone();
    forged.manifest_signature = encoding::encode(&[2u8; 64]);
    let (status, _) = alice
        .call(
            server,
            Method::POST,
            &format!("/api/v1/vaults/{vault_id}/members"),
            Some(serde_json::to_value(&forged).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Role change to edit: Bob can write now.
    let (status, body) = alice
        .call(
            server,
            Method::POST,
            &format!("/api/v1/vaults/{vault_id}/members"),
            Some(serde_json::to_value(&honest).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, report) = bob.sync(server).await;
    assert_eq!(report.view.vaults[0].role.as_deref(), Some("edit"));
    assert_eq!(
        bob.put_item(server, &vault_id, 1, &item_id, 2).await,
        StatusCode::OK
    );

    // Carol joins; then Bob is removed from the vault with a key rotation.
    invite_and_confirm(server, &mut alice, &mut carol, &org_id, "member").await;
    let change = alice
        .keyring
        .share_vault(
            &vault_id,
            PrincipalType::Account,
            carol.id(),
            VaultRole::Edit,
            5,
        )
        .unwrap();
    let (status, body) = alice
        .call(
            server,
            Method::POST,
            &format!("/api/v1/vaults/{vault_id}/members"),
            Some(serde_json::to_value(&change).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    alice.sync(server).await;
    let rotation = alice
        .keyring
        .rotate_vault(
            &vault_id,
            &[(PrincipalType::Account, bob.id().to_owned())],
            r#"{"name":"Family"}"#,
            6,
        )
        .unwrap();
    let (status, _) = bob
        .call(
            server,
            Method::POST,
            &format!("/api/v1/vaults/{vault_id}/rotate"),
            Some(serde_json::to_value(&rotation).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "editors cannot rotate");
    let (status, body) = alice
        .call(
            server,
            Method::POST,
            &format!("/api/v1/vaults/{vault_id}/rotate"),
            Some(serde_json::to_value(&rotation).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["keyEpoch"], 2);
    // Bob lost access at once and never receives the new key.
    let (body, report) = bob.sync(server).await;
    assert!(report.view.vaults.is_empty());
    assert!(body["sharing"]["vaultKeys"].as_array().unwrap().is_empty());
    assert!(!bob.keyring.has_vault_key(&vault_id, 2));
    assert_eq!(
        bob.put_item(server, &vault_id, 2, &item_id, 3).await,
        StatusCode::NOT_FOUND
    );
    let (status, _) = bob
        .call(
            server,
            Method::GET,
            &format!("/api/v1/vaults/{vault_id}/members"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // Writes need the new epoch; the batch endpoint re-encrypts items.
    alice.sync(server).await;
    assert_eq!(
        alice.put_item(server, &vault_id, 1, &item_id, 3).await,
        StatusCode::CONFLICT
    );
    let reencrypted = alice
        .keyring
        .encrypt_item_at(&vault_id, 2, &item_id, 3, r#"{"title":"Shared"}"#)
        .unwrap();
    let (status, body) = alice
        .call(
            server,
            Method::POST,
            &format!("/api/v1/vaults/{vault_id}/items/batch"),
            Some(json!({ "items": [{ "id": item_id, "revision": 3, "keyEpoch": 2, "encryptedData": reencrypted }] })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body[0]["status"], "ok");
    let (body, report) = carol.sync(server).await;
    assert!(
        report.view.warnings.is_empty(),
        "{:?}",
        report.view.warnings
    );
    assert!(carol.keyring.has_vault_key(&vault_id, 2));
    let item = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == item_id.as_str())
        .unwrap();
    assert_eq!(item["keyEpoch"], 2);
    carol
        .keyring
        .decrypt_item_at(
            &vault_id,
            2,
            &item_id,
            3,
            item["encryptedData"].as_str().unwrap(),
        )
        .unwrap();
    // The history keeps the earlier versions with their own key epoch;
    // members read it, people without access do not.
    let (status, history) = carol
        .call(
            server,
            Method::GET,
            &format!("/api/v1/items/{item_id}/versions"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{history}");
    let versions = history["versions"].as_array().unwrap();
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0]["revision"], 2);
    assert_eq!(versions[0]["keyEpoch"], 1);
    assert_eq!(versions[1]["revision"], 1);
    assert!(versions[0]["updatedBy"].is_string());
    if carol.keyring.has_vault_key(&vault_id, 1) {
        carol
            .keyring
            .decrypt_item_at(
                &vault_id,
                1,
                &item_id,
                2,
                versions[0]["encryptedData"].as_str().unwrap(),
            )
            .unwrap();
    }
    for outsider in [&bob, &mallory] {
        let (status, _) = outsider
            .call(
                server,
                Method::GET,
                &format!("/api/v1/items/{item_id}/versions"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
    let (status, members) = carol
        .call(
            server,
            Method::GET,
            &format!("/api/v1/vaults/{vault_id}/members"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(members["members"].as_array().unwrap().len(), 2);

    // Removing Carol from the organization ends her access and marks the
    // vault for rotation; only admins can remove others.
    let (status, _) = bob
        .call(
            server,
            Method::DELETE,
            &format!("/api/v1/orgs/{org_id}/members/{}", carol.id()),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, removed) = alice
        .call(
            server,
            Method::DELETE,
            &format!("/api/v1/orgs/{org_id}/members/{}", carol.id()),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{removed}");
    assert_eq!(removed["vaults"][0], vault_id.as_str());
    let (status, _) = carol
        .call(server, Method::GET, &format!("/api/v1/orgs/{org_id}"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, report) = alice.sync(server).await;
    assert!(report.view.vaults[0].rotation_pending);
    let rotation = alice
        .keyring
        .rotate_vault(
            &vault_id,
            &[(PrincipalType::Account, carol.id().to_owned())],
            r#"{"name":"Family"}"#,
            7,
        )
        .unwrap();
    let (status, body) = alice
        .call(
            server,
            Method::POST,
            &format!("/api/v1/vaults/{vault_id}/rotate"),
            Some(serde_json::to_value(&rotation).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, report) = alice.sync(server).await;
    assert!(!report.view.vaults[0].rotation_pending);
    let rotation = alice.keyring.rotate_org_key(&org_id, 8).unwrap();
    let (status, body) = alice
        .call(
            server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/rotate-key"),
            Some(serde_json::to_value(&rotation).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (_, report) = bob.sync(server).await;
    assert_eq!(report.view.orgs[0].name.as_deref(), Some("Doe"));

    // Roles: members cannot change roles, the owner can.
    let attestation = alice
        .keyring
        .set_member_role(&org_id, bob.id(), OrgRole::Admin, 9)
        .unwrap();
    let (status, _) = bob
        .call(
            server,
            Method::PUT,
            &format!("/api/v1/orgs/{org_id}/members/{}", bob.id()),
            Some(serde_json::to_value(&attestation).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = alice
        .call(
            server,
            Method::PUT,
            &format!("/api/v1/orgs/{org_id}/members/{}", bob.id()),
            Some(serde_json::to_value(&attestation).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (_, report) = bob.sync(server).await;
    assert_eq!(report.view.orgs[0].role, "admin");
    let me = report.view.orgs[0]
        .members
        .iter()
        .find(|m| m.account_id == bob.id())
        .unwrap();
    assert_eq!(me.role, "admin");
    assert!(me.verified);

    // Groups: an admin creates one, the vault is shared with it, the group
    // member gets the key through the group.
    let mut dave = Member::new(server, "10.9.1.5").await;
    invite_and_confirm(server, &mut alice, &mut dave, &org_id, "member").await;
    let group = alice
        .keyring
        .create_group(&org_id, r#"{"name":"Kids"}"#, &[dave.id().to_owned()], 10)
        .unwrap();
    let (status, body) = dave
        .call(
            server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/groups"),
            Some(serde_json::to_value(&group).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = alice
        .call(
            server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/groups"),
            Some(serde_json::to_value(&group).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    alice.sync(server).await;
    let change = alice
        .keyring
        .share_vault(
            &vault_id,
            PrincipalType::Group,
            &group.id,
            VaultRole::View,
            11,
        )
        .unwrap();
    let (status, body) = alice
        .call(
            server,
            Method::POST,
            &format!("/api/v1/vaults/{vault_id}/members"),
            Some(serde_json::to_value(&change).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, report) = dave.sync(server).await;
    assert!(
        report.view.warnings.is_empty(),
        "{:?}",
        report.view.warnings
    );
    assert_eq!(report.view.vaults[0].role.as_deref(), Some("view"));
    assert!(dave.keyring.has_vault_key(&vault_id, 3));
    assert_eq!(
        dave.put_item(server, &vault_id, 3, &id::new_id().unwrap(), 1)
            .await,
        StatusCode::FORBIDDEN
    );
    let (status, _) = alice
        .call(
            server,
            Method::DELETE,
            &format!("/api/v1/orgs/{org_id}/groups/{}", group.id),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "group still has vaults");

    // Security events.
    let (_, events) = bob
        .call(server, Method::GET, "/api/v1/account/events", None)
        .await;
    let kinds: Vec<&str> = events
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    for kind in [
        "keys_published",
        "org_invitation_accepted",
        "org_membership_confirmed",
        "vault_shared",
        "vault_unshared",
        "org_role_changed",
    ] {
        assert!(kinds.contains(&kind), "{kind} in {kinds:?}");
    }
    mallory.sync(server).await;
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
async fn api() {
    let database = passbox_server::testing::TestDatabase::create().await;
    run_all(&database).await;
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

async fn item_history(server: &TestServer) {
    // Own IPs keep the auth rate limit of the other tests untouched.
    let member = Member::new(server, "10.9.5.1").await;
    let (keyring, token) = (&member.keyring, member.token.clone());
    let (_, initial) = server
        .request(Method::GET, "/api/v1/sync", Some(&token), None)
        .await;
    let vault_id = initial["vaults"][0]["id"].as_str().unwrap().to_owned();
    let item_id = id::new_id().unwrap();
    let uri = format!("/api/v1/items/{item_id}");
    let versions_uri = format!("{uri}/versions");
    for revision in 1..=23u64 {
        let data = format!(r#"{{"title":"v{revision}"}}"#);
        let (status, body) = server
            .request(
                Method::PUT,
                &uri,
                Some(&token),
                Some(json!({
                    "vaultId": vault_id,
                    "revision": revision,
                    "encryptedData": keyring.encrypt_item(&vault_id, &item_id, revision, &data).unwrap(),
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    // The creation time stays while the item changes.
    let (_, sync) = server
        .request(Method::GET, "/api/v1/sync", Some(&token), None)
        .await;
    let item = sync["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == item_id.as_str())
        .unwrap();
    let created_at = item["createdAt"].as_i64().unwrap();
    assert!(created_at > 0 && created_at <= item["updatedAt"].as_i64().unwrap());

    // The newest 20 earlier versions, newest first, each decryptable with
    // its own revision.
    let (status, history) = server
        .request(Method::GET, &versions_uri, Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{history}");
    let versions = history["versions"].as_array().unwrap();
    assert_eq!(versions.len(), 20);
    assert_eq!(versions[0]["revision"], 22);
    assert_eq!(versions[19]["revision"], 3);
    assert_eq!(versions[0]["keyEpoch"], 0);
    for version in versions {
        let revision = version["revision"].as_u64().unwrap();
        let data = keyring
            .decrypt_item(
                &vault_id,
                &item_id,
                revision,
                version["encryptedData"].as_str().unwrap(),
            )
            .unwrap();
        assert_eq!(data, format!(r#"{{"title":"v{revision}"}}"#));
    }

    // Other accounts cannot read it; without a session it is refused.
    let other_token = Member::new(server, "10.9.5.2").await.token;
    let (status, _) = server
        .request(Method::GET, &versions_uri, Some(&other_token), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = server.request(Method::GET, &versions_uri, None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A permanent deletion removes the history.
    let (status, _) = server
        .request(
            Method::DELETE,
            &format!("{uri}?revision=24"),
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = server
        .request(Method::GET, &versions_uri, Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM item_versions WHERE item_id = $1")
        .bind(&item_id)
        .fetch_one(server.db())
        .await
        .unwrap();
    assert_eq!(left, 0);
}

/// Serves a PNG for `icon.example` and nothing else, without network access.
struct FakeIcons;

impl passbox_server::api::icons::IconFetcher for FakeIcons {
    fn fetch(&self, domain: &str) -> Option<passbox_server::api::icons::Icon> {
        (domain == "icon.example").then(|| passbox_server::api::icons::Icon {
            content_type: "image/png",
            bytes: b"\x89PNG\r\n\x1a\nfake".to_vec(),
        })
    }
}

async fn website_icons(server: &TestServer) {
    use passbox_server::api::icons::IconService;
    use std::sync::Arc;

    let token = Member::new(server, "10.9.5.3").await.token;
    let with_icons = |enabled: bool| {
        let mut state = server.state.clone();
        state.icons = Arc::new(IconService::new(enabled, Arc::new(FakeIcons)));
        TestServer {
            app: passbox_server::routes::router(&Config::default(), state.clone()),
            state,
            env_admin_email: server.env_admin_email.clone(),
            owner: server.owner.clone(),
        }
    };
    let icons = with_icons(true);
    let get = |server: &TestServer, uri: String, token: Option<String>| {
        let app = server.app.clone();
        async move {
            let mut request = Request::get(uri);
            if let Some(token) = token {
                request = request.header("authorization", format!("Bearer {token}"));
            }
            let response = app
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = response.status();
            let headers = response.headers().clone();
            let body = response.into_body().collect().await.unwrap().to_bytes();
            (status, headers, body)
        }
    };

    let (status, headers, body) = get(
        &icons,
        "/api/v1/icons/Icon.Example".into(),
        Some(token.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["content-type"], "image/png");
    assert_eq!(headers["cache-control"], "private, max-age=604800");
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert!(headers.get("set-cookie").is_none());
    assert!(body.starts_with(b"\x89PNG"));

    // Unknown sites answer 404 (cached); internal targets are refused
    // before anything is fetched.
    let (status, headers, _) = get(
        &icons,
        "/api/v1/icons/missing.example".into(),
        Some(token.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(headers["cache-control"], "private, max-age=86400");
    for bad in [
        "127.0.0.1",
        "localhost",
        "10.0.0.1",
        "%5B%3A%3A1%5D",
        "example.com:8443",
        "intranet",
    ] {
        let (status, _, _) = get(&icons, format!("/api/v1/icons/{bad}"), Some(token.clone())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let (status, _, _) = get(&icons, "/api/v1/icons/icon.example".into(), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // PASSBOX_ICONS=off: the endpoint is gone and /meta says so.
    let off = with_icons(false);
    let (status, _, _) = get(&off, "/api/v1/icons/icon.example".into(), Some(token)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, meta) = off.request(Method::GET, "/api/v1/meta", None, None).await;
    assert_eq!(meta["icons"], false);
    let (_, meta) = icons.request(Method::GET, "/api/v1/meta", None, None).await;
    assert_eq!(meta["icons"], true);
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
    let (sealed,): (Vec<u8>,) =
        sqlx::query_as("SELECT sealed_secret FROM two_factor_totp WHERE account_id = $1")
            .bind(&client.account_id)
            .fetch_one(server.db())
            .await
            .unwrap();
    assert!(!String::from_utf8_lossy(&sealed).contains(&secret));

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
        "SELECT params::text FROM mail_outbox WHERE recipient = $1 AND template = $2 ORDER BY created_at",
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
