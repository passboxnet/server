//! Single sign-on (OIDC) against an in-process mock identity provider,
//! trusted devices (SSO unlock) and SCIM provisioning.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::routing::{get, post};
use http_body_util::BodyExt;
use passbox_core::oidc::test_issuer::TestIssuer;
use passbox_core::opaque::ClientLoginFlow;
use passbox_core::sharing::objects::OrgKind;
use passbox_core::trusted_device::{TrustedDeviceKey, TrustedDeviceUnlock, approval_code};
use passbox_core::{encoding, id};
use passbox_server::config::Config;
use passbox_server::mail::{MailConfig, Mailer};
use passbox_server::state::AppState;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use super::{Client, Member, TestServer, invite_and_confirm};

const PUBLIC_URL: &str = "https://vault.example.com";
const CLIENT_ID: &str = "passbox-test";
const CLIENT_SECRET: &str = "s3cret with spaces&symbols";

// --- Mock identity provider ------------------------------------------------------------

struct Grant {
    claims: Value,
    challenge: String,
    alg: &'static str,
}

#[derive(Clone)]
struct Idp {
    base: String,
    issuer: Arc<TestIssuer>,
    grants: Arc<Mutex<HashMap<String, Grant>>>,
    secret: Arc<Mutex<String>>,
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap();
                out.push(u8::from_str_radix(hex, 16).unwrap());
                i += 2;
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8(out).unwrap()
}

fn query(url: &str) -> HashMap<String, String> {
    url.split_once('?')
        .map(|(_, q)| q)
        .unwrap_or_default()
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (k.to_owned(), percent_decode(v)))
        .collect()
}

async fn discovery(State(idp): State<Idp>) -> axum::Json<Value> {
    axum::Json(json!({
        "issuer": idp.base,
        "authorization_endpoint": format!("{}/authorize", idp.base),
        "token_endpoint": format!("{}/token", idp.base),
        "jwks_uri": format!("{}/jwks", idp.base),
        "id_token_signing_alg_values_supported": ["RS256", "ES256"],
        "code_challenge_methods_supported": ["S256"],
        "response_types_supported": ["code"],
    }))
}

async fn jwks(State(idp): State<Idp>) -> axum::Json<Value> {
    axum::Json(idp.issuer.jwks())
}

async fn token(
    State(idp): State<Idp>,
    headers: HeaderMap,
    body: String,
) -> (StatusCode, axum::Json<Value>) {
    let form: HashMap<String, String> = body
        .split('&')
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| (k.to_owned(), percent_decode(v)))
        .collect();
    let expected = format!(
        "Basic {}",
        data_encoding::BASE64.encode(
            format!(
                "{}:{}",
                passbox_server::api::sso::oidc::form_encode(CLIENT_ID),
                passbox_server::api::sso::oidc::form_encode(&idp.secret.lock().unwrap())
            )
            .as_bytes()
        )
    );
    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(expected.as_str()) {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({ "error": "invalid_client" })),
        );
    }
    let Some(grant) = idp
        .grants
        .lock()
        .unwrap()
        .remove(form.get("code").map(String::as_str).unwrap_or(""))
    else {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({ "error": "invalid_grant" })),
        );
    };
    let verifier = form.get("code_verifier").cloned().unwrap_or_default();
    if encoding::encode(&Sha256::digest(verifier.as_bytes())) != grant.challenge
        || form.get("grant_type").map(String::as_str) != Some("authorization_code")
        || form.get("redirect_uri").map(String::as_str)
            != Some(&format!("{PUBLIC_URL}/api/v1/sso/callback"))
    {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({ "error": "invalid_grant" })),
        );
    }
    let kid = if grant.alg == "ES256" {
        "ec-1"
    } else {
        "rsa-1"
    };
    let id_token = idp.issuer.sign(grant.alg, kid, &grant.claims);
    (
        StatusCode::OK,
        axum::Json(json!({ "access_token": "at", "token_type": "Bearer", "id_token": id_token })),
    )
}

impl Idp {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let idp = Self {
            base,
            issuer: Arc::new(TestIssuer::new()),
            grants: Arc::new(Mutex::new(HashMap::new())),
            secret: Arc::new(Mutex::new(CLIENT_SECRET.to_owned())),
        };
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/token", post(token))
            .with_state(idp.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        idp
    }

    /// What the provider does when the user signs in at `authorization_url`:
    /// returns the `state` and an authorization code for `claims` (merged
    /// over sensible defaults).
    fn authorize(
        &self,
        authorization_url: &str,
        claims: Value,
        alg: &'static str,
    ) -> (String, String) {
        let params = query(authorization_url);
        assert_eq!(params["response_type"], "code");
        assert_eq!(params["client_id"], CLIENT_ID);
        assert_eq!(params["code_challenge_method"], "S256");
        assert_eq!(
            params["redirect_uri"],
            format!("{PUBLIC_URL}/api/v1/sso/callback")
        );
        assert!(params["scope"].split(' ').any(|s| s == "openid"));
        let now = super::unix_now() as i64;
        let mut full = json!({
            "iss": self.base, "aud": CLIENT_ID, "nonce": params["nonce"], "iat": now, "exp": now + 300,
            "email_verified": true, "name": "Test User", "groups": ["staff"],
        });
        for (key, value) in claims.as_object().unwrap() {
            if value.is_null() {
                full.as_object_mut().unwrap().remove(key);
            } else {
                full[key] = value.clone();
            }
        }
        let code = id::new_id().unwrap();
        self.grants.lock().unwrap().insert(
            code.clone(),
            Grant {
                claims: full,
                challenge: params["code_challenge"].clone(),
                alg,
            },
        );
        (params["state"].clone(), code)
    }
}

// --- Helpers ---------------------------------------------------------------------------

async fn sso_server(db: passbox_server::db::Db) -> TestServer {
    passbox_server::api::sso::allow_http_loopback(true);
    let mut state = AppState::load(db.clone()).await.unwrap();
    state.trust_proxy = true;
    // Requests without X-Forwarded-For share the IP "unknown".
    state.auth_rate_limit = 10_000;
    state.mailer = Mailer::new(
        db,
        &MailConfig {
            public_url: Some(PUBLIC_URL.to_owned()),
            ..MailConfig::default()
        },
    )
    .unwrap();
    TestServer {
        app: passbox_server::routes::router(&Config::default(), state.clone()),
        state,
        env_admin_email: String::new(),
    }
}

/// GETs the callback and returns the redirect target.
async fn callback(server: &TestServer, state: &str, code: &str) -> String {
    let response = server
        .app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/sso/callback?state={state}&code={code}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response.headers()["location"].to_str().unwrap().to_owned();
    assert!(
        location.starts_with(&format!("{PUBLIC_URL}/#/sso?")),
        "{location}"
    );
    let _ = response.into_body().collect().await;
    location
}

fn param(location: &str, name: &str) -> Option<String> {
    query(location.split_once("#/sso").unwrap().1)
        .get(name)
        .cloned()
}

/// Starts a sign-in for `org_id` and lets the provider answer with
/// `claims`; returns the redirect target and the flow secret.
async fn sign_in_at_idp(
    server: &TestServer,
    idp: &Idp,
    org_id: &str,
    claims: Value,
    alg: &'static str,
) -> (String, String) {
    let (status, start) = server
        .request_from(
            Some(&random_ip()),
            Method::POST,
            "/api/v1/sso/start",
            None,
            Some(json!({ "orgId": org_id, "email": "hint@example.com" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{start}");
    let url = start["authorizationUrl"].as_str().unwrap();
    assert_eq!(query(url)["login_hint"], "hint@example.com");
    let (state, code) = idp.authorize(url, claims, alg);
    (
        callback(server, &state, &code).await,
        start["flowSecret"].as_str().unwrap().to_owned(),
    )
}

/// A full SSO sign-in for `member`; returns the redeemed response.
async fn sso_proof(
    server: &TestServer,
    idp: &Idp,
    org_id: &str,
    member: &Member,
    device_id: Option<&str>,
) -> Value {
    let (location, secret) = sign_in_at_idp(
        server,
        idp,
        org_id,
        json!({ "sub": format!("sub-{}", member.id()), "email": member.client.email }),
        "RS256",
    )
    .await;
    let ticket = param(&location, "ticket").unwrap_or_else(|| panic!("{location}"));
    let mut body = json!({ "ticket": ticket, "flowSecret": secret });
    if let Some(device_id) = device_id {
        body["deviceId"] = json!(device_id);
    }
    let (status, redeemed) = server.post("/api/v1/sso/redeem", None, body).await;
    assert_eq!(status, StatusCode::OK, "{redeemed}");
    redeemed
}

/// A password login (OPAQUE) with an optional SSO proof and device token.
async fn password_login(
    server: &TestServer,
    client: &Client,
    proof: Option<&str>,
    device_token: Option<&str>,
) -> (StatusCode, Value) {
    let (flow, request) = ClientLoginFlow::start(&client.auth_secret).unwrap();
    let mut start =
        json!({ "email": client.email, "credentialRequest": encoding::encode(&request) });
    if let Some(device_token) = device_token {
        start["deviceToken"] = json!(device_token);
    }
    let (status, body) = server
        .request_from(
            Some("10.77.0.1"),
            Method::POST,
            "/api/v1/auth/login/start",
            None,
            Some(start),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let finish = flow
        .finish(&encoding::decode(body["credentialResponse"].as_str().unwrap()).unwrap())
        .unwrap();
    let mut req = json!({ "loginId": body["loginId"], "credentialFinalization": encoding::encode(&finish.finalization) });
    if let Some(proof) = proof {
        req["ssoProof"] = json!(proof);
    }
    server
        .request_from(
            Some("10.77.0.1"),
            Method::POST,
            "/api/v1/auth/login/finish",
            None,
            Some(req),
        )
        .await
}

async fn create_team(server: &TestServer, owner: &mut Member) -> String {
    let org = owner
        .keyring
        .create_org(OrgKind::Team, r#"{"name":"Acme"}"#, None, 1)
        .unwrap();
    let (status, body) = owner
        .call(
            server,
            Method::POST,
            "/api/v1/orgs",
            Some(serde_json::to_value(&org).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    owner.sync(server).await;
    org.id
}

fn settings(idp: &Idp, domain: &str) -> Value {
    json!({
        "enabled": true,
        "provider": "keycloak",
        "displayName": "Acme Keycloak",
        "issuer": format!("{}/", idp.base),
        "clientId": CLIENT_ID,
        "clientSecret": CLIENT_SECRET,
        "allowedDomains": [domain],
    })
}

// --- OIDC sign-in --------------------------------------------------------------------------

pub async fn single_sign_on(base: &TestServer) {
    let server = sso_server(base.db().clone()).await;
    let server = &server;
    let idp = Idp::start().await;
    let mut alice = Member::new(server, "10.77.1.1").await;
    let mut bob = Member::new(server, "10.77.1.2").await;
    let carol = Member::new(server, "10.77.1.3").await;
    let org_id = create_team(server, &mut alice).await;
    invite_and_confirm(server, &mut alice, &mut bob, &org_id, "member").await;
    let uri = format!("/api/v1/orgs/{org_id}/sso");

    // Only owners and admins configure SSO.
    let (status, _) = bob
        .call(
            server,
            Method::PUT,
            &uri,
            Some(settings(&idp, "example.com")),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = alice.call(server, Method::GET, &uri, None).await;
    assert_eq!((status, body), (StatusCode::OK, Value::Null));
    // Before saving: the connection check.
    let (status, check) = alice
        .call(
            server,
            Method::POST,
            &format!("{uri}/check"),
            Some(json!({ "issuer": idp.base })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{check}");
    assert_eq!(check["ok"], true, "{check}");
    assert_eq!(check["keys"], 2);
    assert_eq!(
        check["redirectUri"],
        format!("{PUBLIC_URL}/api/v1/sso/callback")
    );
    let (_, check) = alice
        .call(
            server,
            Method::POST,
            &format!("{uri}/check"),
            Some(json!({ "issuer": "http://127.0.0.1:9/" })),
        )
        .await;
    assert_eq!(check["ok"], false);
    assert_eq!(check["problem"]["code"], "sso_unreachable");
    let (status, body) = alice
        .call(server, Method::PUT, &uri, Some(json!({ "enabled": true, "displayName": "x", "issuer": "https://idp.invalid", "clientId": "c", "clientSecret": "s", "allowedDomains": ["example.com"] })))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "sso_unreachable");

    // Save: the issuer is normalized to the discovery document's, the
    // secret is never returned and is encrypted at rest.
    let (status, config) = alice
        .call(
            server,
            Method::PUT,
            &uri,
            Some(settings(&idp, "Example.com")),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{config}");
    assert_eq!(config["issuer"], idp.base);
    assert_eq!(config["hasClientSecret"], true);
    assert_eq!(config["allowedDomains"], json!(["example.com"]));
    assert!(config.get("clientSecret").is_none());
    assert_eq!(
        config["discovery"]["tokenEndpoint"],
        format!("{}/token", idp.base)
    );
    let stored: String =
        sqlx::query_scalar("SELECT encrypted_client_secret FROM org_sso WHERE org_id = $1")
            .bind(&org_id)
            .fetch_one(server.db())
            .await
            .unwrap();
    assert!(!stored.contains("s3cret"));
    // Saving again without a secret keeps it.
    let mut again = settings(&idp, "example.com");
    again.as_object_mut().unwrap().remove("clientSecret");
    let (status, config) = alice.call(server, Method::PUT, &uri, Some(again)).await;
    assert_eq!(
        (status, config["hasClientSecret"].clone()),
        (StatusCode::OK, json!(true))
    );

    // A domain belongs to one organization.
    let mut dave = Member::new(server, "10.77.1.4").await;
    let other_org = create_team(server, &mut dave).await;
    let (status, body) = dave
        .call(
            server,
            Method::PUT,
            &format!("/api/v1/orgs/{other_org}/sso"),
            Some(settings(&idp, "example.com")),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["details"]["code"], "sso_domain_taken");

    // Discovery by email domain.
    let (_, found) = server
        .post(
            "/api/v1/sso/discover",
            None,
            json!({ "email": "Someone@EXAMPLE.com" }),
        )
        .await;
    assert_eq!(found["sso"]["orgId"], org_id);
    assert_eq!(found["sso"]["displayName"], "Acme Keycloak");
    let (_, none) = server
        .post(
            "/api/v1/sso/discover",
            None,
            json!({ "email": "a@elsewhere.example" }),
        )
        .await;
    assert_eq!(none["sso"], Value::Null);

    // Bob signs in with SSO and uses the proof for his password login.
    let redeemed = sso_proof(server, &idp, &org_id, &bob, None).await;
    assert_eq!(redeemed["status"], "ok");
    assert_eq!(redeemed["accountId"], bob.id());
    assert_eq!(redeemed["email"], bob.client.email);
    assert_eq!(redeemed["deviceUnlock"], false);
    let proof = redeemed["proof"].as_str().unwrap();
    // Not for another account, and single use.
    let (status, body) = password_login(server, &carol.client, Some(proof), None).await;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::FORBIDDEN, json!("sso_proof_invalid"))
    );
    let (status, body) = password_login(server, &bob.client, Some(proof), None).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "consumed by the failed attempt: {body}"
    );
    let proof = sso_proof(server, &idp, &org_id, &bob, None).await["proof"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, body) = password_login(server, &bob.client, Some(&proof), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // "SSO required": members need SSO; owners and admins do not.
    let mut required = settings(&idp, "example.com");
    required["required"] = json!(true);
    required["reauthHours"] = json!(2);
    let (status, body) = alice.call(server, Method::PUT, &uri, Some(required)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = password_login(server, &bob.client, None, None).await;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::FORBIDDEN, json!("sso_required")),
        "{body}"
    );
    let (status, _) = password_login(server, &alice.client, None, None).await;
    assert_eq!(status, StatusCode::OK);
    let proof = sso_proof(server, &idp, &org_id, &bob, None).await["proof"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, session) = password_login(server, &bob.client, Some(&proof), None).await;
    assert_eq!(status, StatusCode::OK, "{session}");
    // The device is remembered for the re-authentication interval, also
    // across device token rotation.
    let device_token = session["deviceToken"].as_str().unwrap().to_owned();
    let (status, session) = password_login(server, &bob.client, None, Some(&device_token)).await;
    assert_eq!(status, StatusCode::OK, "{session}");
    let rotated = session["deviceToken"].as_str().unwrap().to_owned();
    let until: i64 =
        sqlx::query_scalar("SELECT sso_until FROM device_tokens WHERE token_hash = $1")
            .bind(hex(&rotated))
            .fetch_one(server.db())
            .await
            .unwrap();
    let hours = (until - passbox_server::db::now_ms()) as f64 / 3_600_000.0;
    assert!((1.9..=2.0).contains(&hours), "{hours}");
    let (status, _) = password_login(server, &bob.client, None, Some(&rotated)).await;
    assert_eq!(status, StatusCode::OK);

    // The provider identity is linked by subject: a changed email at the
    // provider still signs in Bob.
    let (location, secret) = sign_in_at_idp(
        server,
        &idp,
        &org_id,
        json!({ "sub": format!("sub-{}", bob.id()), "email": "renamed@example.com" }),
        "ES256",
    )
    .await;
    let (status, body) = server
        .post(
            "/api/v1/sso/redeem",
            None,
            json!({ "ticket": param(&location, "ticket").unwrap(), "flowSecret": secret }),
        )
        .await;
    assert_eq!(
        (status, body["accountId"].clone()),
        (StatusCode::OK, json!(bob.id())),
        "{body}"
    );

    // Errors end as a redirect with a code, never with a session.
    let cases: Vec<(Value, &str)> = vec![
        (
            json!({ "sub": "x1", "email": carol.client.email }),
            "sso_not_member",
        ),
        (
            json!({ "sub": "x2", "email": "ada@elsewhere.example" }),
            "sso_domain_not_allowed",
        ),
        (
            json!({ "sub": "x3", "email": bob.client.email, "email_verified": false }),
            "sso_email_unverified",
        ),
        (json!({ "sub": "x4", "email": null }), "sso_no_email"),
        (
            json!({ "sub": "x5", "email": bob.client.email, "nonce": "other" }),
            "sso_invalid_token",
        ),
        (
            json!({ "sub": "x6", "email": bob.client.email, "aud": "someone-else" }),
            "sso_invalid_token",
        ),
        (
            json!({ "sub": "x7", "email": bob.client.email, "iss": "https://evil.example" }),
            "sso_invalid_token",
        ),
        (
            json!({ "sub": "x8", "email": bob.client.email, "exp": 1 }),
            "sso_invalid_token",
        ),
    ];
    for (claims, code) in cases {
        let (location, _) = sign_in_at_idp(server, &idp, &org_id, claims.clone(), "RS256").await;
        assert_eq!(param(&location, "error").as_deref(), Some(code), "{claims}");
        assert!(param(&location, "ticket").is_none());
    }
    // A token signed with an algorithm Passbox refuses.
    let (location, _) = sign_in_at_idp(
        server,
        &idp,
        &org_id,
        json!({ "sub": "x9", "email": bob.client.email }),
        "HS256",
    )
    .await;
    assert_eq!(
        param(&location, "error").as_deref(),
        Some("sso_invalid_token")
    );

    // Unknown email in an allowed domain: no account yet.
    let (location, secret) = sign_in_at_idp(
        server,
        &idp,
        &org_id,
        json!({ "sub": "new-1", "email": "newcomer@example.com" }),
        "RS256",
    )
    .await;
    let ticket = param(&location, "ticket").unwrap();
    // The ticket only works with the flow secret of the tab that started it.
    let (status, body) = server
        .post(
            "/api/v1/sso/redeem",
            None,
            json!({ "ticket": ticket, "flowSecret": "wrong" }),
        )
        .await;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::FORBIDDEN, json!("sso_expired"))
    );
    let (location, secret2) = sign_in_at_idp(
        server,
        &idp,
        &org_id,
        json!({ "sub": "new-1", "email": "newcomer@example.com" }),
        "RS256",
    )
    .await;
    let _ = secret;
    let (status, body) = server
        .post(
            "/api/v1/sso/redeem",
            None,
            json!({ "ticket": param(&location, "ticket").unwrap(), "flowSecret": secret2 }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "no_account");
    assert_eq!(body["email"], "newcomer@example.com");
    assert!(body.get("proof").is_none());

    // The state is single use, and the code must come from the provider.
    let (status, start) = server
        .post("/api/v1/sso/start", None, json!({ "orgId": org_id }))
        .await;
    assert_eq!(status, StatusCode::OK);
    let (state, code) = idp.authorize(
        start["authorizationUrl"].as_str().unwrap(),
        json!({ "sub": "y", "email": bob.client.email }),
        "RS256",
    );
    let location = callback(server, &state, "forged-code").await;
    assert_eq!(
        param(&location, "error").as_deref(),
        Some("sso_token_rejected")
    );
    let location = callback(server, &state, &code).await;
    assert_eq!(param(&location, "error").as_deref(), Some("sso_expired"));
    // A wrong client secret is rejected by the provider.
    *idp.secret.lock().unwrap() = "rotated".into();
    let (location, _) = sign_in_at_idp(
        server,
        &idp,
        &org_id,
        json!({ "sub": "z", "email": bob.client.email }),
        "RS256",
    )
    .await;
    assert_eq!(
        param(&location, "error").as_deref(),
        Some("sso_token_rejected")
    );
    *idp.secret.lock().unwrap() = CLIENT_SECRET.into();

    // "Test connection" shows the claims to the admin who started it.
    let (status, start) = alice
        .call(
            server,
            Method::POST,
            &format!("{uri}/test/start"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{start}");
    assert_eq!(
        query(start["authorizationUrl"].as_str().unwrap())["prompt"],
        "login"
    );
    let (state, code) = idp.authorize(
        start["authorizationUrl"].as_str().unwrap(),
        json!({ "sub": "admin-sub", "email": alice.client.email }),
        "RS256",
    );
    let ticket = param(&callback(server, &state, &code).await, "ticket").unwrap();
    let test_body = json!({ "ticket": ticket, "flowSecret": start["flowSecret"] });
    let (status, _) = server
        .post("/api/v1/sso/redeem", None, test_body.clone())
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a test ticket is no sign-in"
    );
    let (status, start) = alice
        .call(
            server,
            Method::POST,
            &format!("{uri}/test/start"),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (state, code) = idp.authorize(
        start["authorizationUrl"].as_str().unwrap(),
        json!({ "sub": "admin-sub", "email": alice.client.email }),
        "RS256",
    );
    let ticket = param(&callback(server, &state, &code).await, "ticket").unwrap();
    let test_body = json!({ "ticket": ticket, "flowSecret": start["flowSecret"] });
    let (status, result) = alice
        .call(
            server,
            Method::POST,
            &format!("{uri}/test/result"),
            Some(test_body),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["outcome"], "ok");
    assert_eq!(result["subject"], "admin-sub");
    assert_eq!(result["accountFound"], true);
    assert_eq!(result["groups"], json!(["staff"]));
    assert!(result["claims"].get("nonce").is_none());
    // The test did not link the subject.
    let linked: Option<String> =
        sqlx::query_scalar("SELECT account_id FROM sso_identities WHERE subject = 'admin-sub'")
            .fetch_optional(server.db())
            .await
            .unwrap();
    assert!(linked.is_none());

    trusted_devices(server, &idp, &org_id, &mut alice, &mut bob).await;
    provisioning(server, &idp, &org_id, &mut alice, &mut bob).await;

    // Removing the configuration frees the domains.
    let (status, _) = alice.call(server, Method::DELETE, &uri, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, none) = server
        .post(
            "/api/v1/sso/discover",
            None,
            json!({ "email": "a@example.com" }),
        )
        .await;
    assert_eq!(none["sso"], Value::Null);
    let (status, _) = password_login(server, &bob.client, None, None).await;
    assert_eq!(status, StatusCode::OK, "no longer required");
}

fn random_ip() -> String {
    let [a, b] = passbox_core::random::bytes::<2>().unwrap();
    format!("10.78.{a}.{b}")
}

fn hex(token: &str) -> String {
    data_encoding::HEXLOWER.encode(&Sha256::digest(token.as_bytes()))
}

// --- Trusted devices (SSO unlock) ------------------------------------------------------------

async fn trusted_devices(
    server: &TestServer,
    idp: &Idp,
    org_id: &str,
    alice: &mut Member,
    bob: &mut Member,
) {
    let uri = format!("/api/v1/orgs/{org_id}/sso");
    let device = TrustedDeviceKey::generate().unwrap();
    let device_id = id::new_id().unwrap();
    let upload = bob
        .keyring
        .trust_device(&device_id, &device.public_key(), "", 1)
        .unwrap();
    // Not before the organization allows it.
    let (status, body) = bob
        .call(
            server,
            Method::POST,
            "/api/v1/account/trusted-devices",
            Some(serde_json::to_value(&upload).unwrap()),
        )
        .await;
    assert_eq!(
        (status, body["error"].clone()),
        (
            StatusCode::FORBIDDEN,
            json!("sso_device_unlock_not_allowed")
        )
    );
    let mut allow = settings(idp, "example.com");
    allow["required"] = json!(true);
    allow["allowDeviceUnlock"] = json!(true);
    let (status, body) = alice.call(server, Method::PUT, &uri, Some(allow)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // A grant signed by someone else, or for another key, is refused.
    let forged = alice
        .keyring
        .trust_device(&device_id, &device.public_key(), "", 1)
        .unwrap();
    let (status, _) = bob
        .call(
            server,
            Method::POST,
            "/api/v1/account/trusted-devices",
            Some(serde_json::to_value(&forged).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let mut swapped = upload.clone();
    swapped.public_key = encoding::encode(&TrustedDeviceKey::generate().unwrap().public_key());
    let (status, _) = bob
        .call(
            server,
            Method::POST,
            "/api/v1/account/trusted-devices",
            Some(serde_json::to_value(&swapped).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let mut body = serde_json::to_value(&upload).unwrap();
    body["name"] = json!("Bob's laptop");
    let (status, created) = bob
        .call(
            server,
            Method::POST,
            "/api/v1/account/trusted-devices",
            Some(body),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["name"], "Bob's laptop");

    // Unlock: SSO sign-in, then the sealed account key, no master password.
    let redeemed = sso_proof(server, idp, org_id, bob, Some(&device_id)).await;
    assert_eq!(redeemed["deviceUnlock"], true);
    assert_eq!(redeemed["deviceTrusted"], true);
    let (status, unlocked) = server
        .post(
            "/api/v1/sso/unlock",
            None,
            json!({ "proof": redeemed["proof"], "deviceId": device_id, "deviceName": "Laptop", "clientKind": "web" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{unlocked}");
    let record: TrustedDeviceUnlock = serde_json::from_value(unlocked["unlock"].clone()).unwrap();
    let keyring = device.unlock(&record).unwrap();
    assert_eq!(keyring.account_id(), bob.id());
    let token = unlocked["session"]["token"].as_str().unwrap();
    let (status, account) = server
        .request(Method::GET, "/api/v1/account", Some(token), None)
        .await;
    assert_eq!(
        (status, account["accountId"].clone()),
        (StatusCode::OK, json!(bob.id()))
    );
    // Proofs are single use; an unknown device gets a clear error.
    let (status, _) = server
        .post(
            "/api/v1/sso/unlock",
            None,
            json!({ "proof": redeemed["proof"], "deviceId": device_id }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let proof = sso_proof(server, idp, org_id, bob, None).await["proof"].clone();
    let (status, body) = server
        .post(
            "/api/v1/sso/unlock",
            None,
            json!({ "proof": proof, "deviceId": id::new_id().unwrap() }),
        )
        .await;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::FORBIDDEN, json!("sso_device_not_trusted"))
    );

    // A new device asks; the trusted device compares the code and approves.
    let phone = TrustedDeviceKey::generate().unwrap();
    let proof = sso_proof(server, idp, org_id, bob, None).await["proof"].clone();
    let (status, request) = server
        .post(
            "/api/v1/sso/device-requests",
            None,
            json!({ "proof": proof, "publicKey": encoding::encode(&phone.public_key()), "deviceName": "Phone", "clientKind": "web" }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{request}");
    assert_eq!(request["approvalCode"], phone.approval_code());
    let request_id = request["requestId"].as_str().unwrap().to_owned();
    let poll = json!({ "requestToken": request["requestToken"] });
    let (status, pending) = server
        .post("/api/v1/sso/device-requests/status", None, poll.clone())
        .await;
    assert_eq!(
        (status, pending["status"].clone()),
        (StatusCode::OK, json!("pending"))
    );
    let bob_session = unlocked["session"]["token"].as_str().unwrap().to_owned();
    let (status, list) = server
        .request(
            Method::GET,
            "/api/v1/account/trusted-devices",
            Some(&bob_session),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["allowed"], true);
    assert_eq!(list["devices"].as_array().unwrap().len(), 1);
    let shown = &list["requests"][0];
    assert_eq!(shown["deviceName"], "Phone");
    let shown_key = encoding::decode(shown["publicKey"].as_str().unwrap()).unwrap();
    assert_eq!(approval_code(&shown_key), phone.approval_code());
    // Only the account's own devices can approve.
    let foreign = alice
        .keyring
        .trust_device(&request_id, &shown_key, "", 2)
        .unwrap();
    let (status, _) = alice
        .call(
            server,
            Method::POST,
            &format!("/api/v1/account/trusted-devices/requests/{request_id}/approve"),
            Some(serde_json::to_value(&foreign).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // The device's own keyring signs the approval (it holds the account keys).
    let approval = keyring
        .trust_device(&request_id, &shown_key, &device_id, 2)
        .unwrap();
    let (status, body) = server
        .request(
            Method::POST,
            &format!("/api/v1/account/trusted-devices/requests/{request_id}/approve"),
            Some(&bob_session),
            Some(serde_json::to_value(&approval).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, approved) = server
        .post("/api/v1/sso/device-requests/status", None, poll.clone())
        .await;
    assert_eq!(
        (status, approved["status"].clone()),
        (StatusCode::OK, json!("approved")),
        "{approved}"
    );
    let record: TrustedDeviceUnlock =
        serde_json::from_value(approved["result"]["unlock"].clone()).unwrap();
    assert_eq!(phone.unlock(&record).unwrap().account_id(), bob.id());
    let (status, _) = server
        .post("/api/v1/sso/device-requests/status", None, poll)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "single use");

    // Removing a trusted device.
    let (status, _) = server
        .request(
            Method::DELETE,
            &format!("/api/v1/account/trusted-devices/{request_id}"),
            Some(&bob_session),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

// --- SCIM ----------------------------------------------------------------------------------

async fn scim(
    server: &TestServer,
    method: Method,
    uri: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("/api/v1/scim/v2{uri}"))
        .header("authorization", format!("Bearer {token}"));
    let request = match body {
        Some(body) => builder
            .header("content-type", "application/scim+json")
            .body(Body::from(body.to_string())),
        None => {
            builder = builder.header("accept", "application/scim+json");
            builder.body(Body::empty())
        }
    }
    .unwrap();
    let response = server.app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    if status != StatusCode::NO_CONTENT {
        assert_eq!(response.headers()["content-type"], "application/scim+json");
    }
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn patch(ops: Value) -> Value {
    json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": ops })
}

async fn overview_status(server: &TestServer, admin: &Member, org_id: &str, email: &str) -> String {
    let (status, overview) = admin
        .call(
            server,
            Method::GET,
            &format!("/api/v1/orgs/{org_id}/scim"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{overview}");
    overview["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["email"] == email)
        .map(|u| u["status"].as_str().unwrap().to_owned())
        .unwrap_or_default()
}

async fn provisioning(
    server: &TestServer,
    idp: &Idp,
    org_id: &str,
    alice: &mut Member,
    bob: &mut Member,
) {
    // Tokens: admins only, shown once.
    let tokens = format!("/api/v1/orgs/{org_id}/scim/tokens");
    let (status, _) = bob
        .call(
            server,
            Method::POST,
            &tokens,
            Some(json!({ "name": "Okta" })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, created) = alice
        .call(
            server,
            Method::POST,
            &tokens,
            Some(json!({ "name": "Okta", "expiresInDays": 30 })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let token = created["token"].as_str().unwrap().to_owned();
    assert!(token.starts_with("pbx_scim_"));
    assert_eq!(created["baseUrl"], format!("{PUBLIC_URL}/api/v1/scim/v2"));

    let (status, error) = scim(server, Method::GET, "/Users", "wrong", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        error["schemas"][0],
        "urn:ietf:params:scim:api:messages:2.0:Error"
    );
    assert_eq!(error["status"], "401");
    let (status, config) = scim(server, Method::GET, "/ServiceProviderConfig", &token, None).await;
    assert_eq!(
        (status, config["patch"]["supported"].clone()),
        (StatusCode::OK, json!(true))
    );
    let (status, types) = scim(server, Method::GET, "/ResourceTypes", &token, None).await;
    assert_eq!(
        (status, types["totalResults"].clone()),
        (StatusCode::OK, json!(2))
    );
    let (status, _) = scim(server, Method::GET, "/Schemas", &token, None).await;
    assert_eq!(status, StatusCode::OK);

    // Okta's first call: is the user there?
    let (status, list) = scim(
        server,
        Method::GET,
        "/Users?filter=userName%20eq%20%22nobody%40example.com%22&startIndex=1&count=100",
        &token,
        None,
    )
    .await;
    assert_eq!(
        (status, list["totalResults"].clone()),
        (StatusCode::OK, json!(0))
    );

    // A person without an account: invited (with a mail).
    let dave = Client::new();
    let (status, user) = scim(
        server,
        Method::POST,
        "/Users",
        &token,
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": dave.email.to_uppercase(), "externalId": "00u-dave",
            "name": { "givenName": "Dave", "familyName": "Doe" },
            "emails": [{ "value": dave.email, "type": "work", "primary": true }],
            "active": true,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{user}");
    let dave_id = user["id"].as_str().unwrap().to_owned();
    assert_eq!(user["meta"]["resourceType"], "User");
    assert_eq!(user["meta"]["version"], "W/\"1\"");
    assert_eq!(
        overview_status(server, alice, org_id, &dave.email).await,
        "invited"
    );
    let mails: Vec<String> =
        sqlx::query_scalar("SELECT template FROM mail_outbox WHERE recipient = $1")
            .bind(&dave.email)
            .fetch_all(server.db())
            .await
            .unwrap();
    assert_eq!(mails, vec!["invitation"]);
    // userName is unique (case-insensitive).
    let (status, error) = scim(
        server,
        Method::POST,
        "/Users",
        &token,
        Some(json!({ "userName": dave.email, "emails": [{ "value": dave.email }] })),
    )
    .await;
    assert_eq!(
        (status, error["scimType"].clone()),
        (StatusCode::CONFLICT, json!("uniqueness"))
    );
    let (status, error) = scim(
        server,
        Method::POST,
        "/Users",
        &token,
        Some(json!({ "userName": "not-an-email" })),
    )
    .await;
    assert_eq!(
        (status, error["scimType"].clone()),
        (StatusCode::BAD_REQUEST, json!("invalidValue"))
    );

    // An existing member is linked.
    let (status, bob_user) = scim(
        server,
        Method::POST,
        "/Users",
        &token,
        Some(json!({ "userName": bob.client.email, "active": true, "displayName": "Bob" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{bob_user}");
    let bob_scim = bob_user["id"].as_str().unwrap().to_owned();
    assert_eq!(
        overview_status(server, alice, org_id, &bob.client.email).await,
        "confirmed"
    );

    // Filters.
    let filter = |f: &str| {
        format!(
            "/Users?filter={}",
            passbox_server::api::sso::oidc::query_encode(f)
        )
    };
    let (_, list) = scim(
        server,
        Method::GET,
        &filter(&format!("userName eq \"{}\"", dave.email)),
        &token,
        None,
    )
    .await;
    assert_eq!(list["totalResults"], 1);
    assert_eq!(list["Resources"][0]["id"], dave_id);
    let (_, list) = scim(
        server,
        Method::GET,
        &filter("externalId eq \"00u-dave\" or displayName eq \"Bob\""),
        &token,
        None,
    )
    .await;
    assert_eq!(list["totalResults"], 2);
    let (_, list) = scim(
        server,
        Method::GET,
        "/Users?startIndex=2&count=1",
        &token,
        None,
    )
    .await;
    assert_eq!(
        (
            list["totalResults"].clone(),
            list["itemsPerPage"].clone(),
            list["startIndex"].clone()
        ),
        (json!(2), json!(1), json!(2))
    );
    let (status, error) = scim(server, Method::GET, &filter("userName eq"), &token, None).await;
    assert_eq!(
        (status, error["scimType"].clone()),
        (StatusCode::BAD_REQUEST, json!("invalidFilter"))
    );

    // Dave registers and signs in through the organization's SSO, which
    // accepts the invitation: pending confirmation by an admin client.
    let mut dave = Member::new_with(server, "10.77.2.1", dave).await;
    assert_eq!(
        overview_status(server, alice, org_id, &dave.client.email).await,
        "invited"
    );
    let redeemed = sso_proof(server, idp, org_id, &dave, None).await;
    assert_eq!(redeemed["status"], "ok", "{redeemed}");
    assert_eq!(
        overview_status(server, alice, org_id, &dave.client.email).await,
        "pending_confirmation"
    );
    dave.sync(server).await;

    // Deprovisioning (Entra style) ends Bob's sessions right away.
    let proof = sso_proof(server, idp, org_id, bob, None).await["proof"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, session) = password_login(server, &bob.client, Some(&proof), None).await;
    assert_eq!(status, StatusCode::OK, "{session}");
    let bob_token = session["token"].as_str().unwrap().to_owned();
    let (status, user) = scim(
        server,
        Method::PATCH,
        &format!("/Users/{bob_scim}"),
        &token,
        Some(patch(
            json!([{ "op": "Replace", "path": "active", "value": "False" }]),
        )),
    )
    .await;
    assert_eq!(
        (status, user["active"].clone()),
        (StatusCode::OK, json!(false)),
        "{user}"
    );
    assert_eq!(user["meta"]["version"], "W/\"2\"");
    let (status, _) = server
        .request(Method::GET, "/api/v1/account", Some(&bob_token), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = bob.call(server, Method::GET, "/api/v1/account", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let devices: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM trusted_devices WHERE account_id = $1")
            .bind(bob.id())
            .fetch_one(server.db())
            .await
            .unwrap();
    assert_eq!(devices, 0);
    assert_eq!(
        overview_status(server, alice, org_id, &bob.client.email).await,
        "deactivated"
    );
    // A suspended member cannot sign in with SSO either.
    let (location, _) = sign_in_at_idp(
        server,
        idp,
        org_id,
        json!({ "sub": format!("sub-{}", bob.id()), "email": bob.client.email }),
        "RS256",
    )
    .await;
    assert_eq!(param(&location, "error").as_deref(), Some("sso_suspended"));
    // Reactivation (Okta style, no path) restores the previous status.
    let (status, user) = scim(
        server,
        Method::PATCH,
        &format!("/Users/{bob_scim}"),
        &token,
        Some(patch(
            json!([{ "op": "replace", "value": { "active": true, "name.givenName": "Robert" } }]),
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{user}");
    assert_eq!(user["name"]["givenName"], "Robert");
    assert_eq!(
        overview_status(server, alice, org_id, &bob.client.email).await,
        "confirmed"
    );
    let role: String =
        sqlx::query_scalar("SELECT status FROM org_members WHERE org_id = $1 AND account_id = $2")
            .bind(org_id)
            .bind(bob.id())
            .fetch_one(server.db())
            .await
            .unwrap();
    assert_eq!(role, "confirmed");

    // The owner cannot be deprovisioned.
    let (status, owner) = scim(
        server,
        Method::POST,
        "/Users",
        &token,
        Some(json!({ "userName": alice.client.email })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, error) = scim(
        server,
        Method::PUT,
        &format!("/Users/{}", owner["id"].as_str().unwrap()),
        &token,
        Some(json!({ "userName": alice.client.email, "active": false })),
    )
    .await;
    assert_eq!(
        (status, error["scimType"].clone()),
        (StatusCode::BAD_REQUEST, json!("mutability"))
    );

    // Groups with membership changes in the styles IdPs use.
    let (status, group) = scim(
        server,
        Method::POST,
        "/Groups",
        &token,
        Some(json!({ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "Engineering", "members": [{ "value": bob_scim }] })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{group}");
    let group_id = group["id"].as_str().unwrap().to_owned();
    let (status, group) = scim(
        server,
        Method::PATCH,
        &format!("/Groups/{group_id}"),
        &token,
        Some(patch(json!([
            { "op": "Add", "path": "members", "value": [{ "value": dave_id }] },
            { "op": "Remove", "path": format!("members[value eq \"{bob_scim}\"]") },
            { "op": "Replace", "path": "displayName", "value": "Eng" },
        ]))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{group}");
    assert_eq!(group["displayName"], "Eng");
    assert_eq!(group["members"].as_array().unwrap().len(), 1);
    assert_eq!(group["members"][0]["value"], dave_id);
    let (_, list) = scim(
        server,
        Method::GET,
        "/Groups?filter=displayName%20eq%20%22eng%22",
        &token,
        None,
    )
    .await;
    assert_eq!(list["totalResults"], 1);
    let (_, user) = scim(
        server,
        Method::GET,
        &format!("/Users/{dave_id}"),
        &token,
        None,
    )
    .await;
    assert_eq!(user["groups"][0]["display"], "Eng");
    let (status, _) = scim(
        server,
        Method::PATCH,
        &format!("/Groups/{group_id}"),
        &token,
        Some(patch(
            json!([{ "op": "add", "path": "members", "value": [{ "value": "unknown" }] }]),
        )),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = scim(
        server,
        Method::PATCH,
        &format!("/Groups/{group_id}"),
        &token,
        Some(json!({ "Operations": [] })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "PatchOp schema required");
    let (status, overview) = alice
        .call(
            server,
            Method::GET,
            &format!("/api/v1/orgs/{org_id}/scim"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(overview["groups"][0]["members"], 1);
    assert_eq!(overview["tokens"][0]["name"], "Okta");
    let (status, _) = scim(
        server,
        Method::DELETE,
        &format!("/Groups/{group_id}"),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // DELETE deprovisions and forgets the user.
    let (status, _) = scim(
        server,
        Method::DELETE,
        &format!("/Users/{dave_id}"),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = scim(
        server,
        Method::GET,
        &format!("/Users/{dave_id}"),
        &token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let dave_status: String =
        sqlx::query_scalar("SELECT status FROM org_members WHERE org_id = $1 AND account_id = $2")
            .bind(org_id)
            .bind(dave.id())
            .fetch_one(server.db())
            .await
            .unwrap();
    assert_eq!(dave_status, "suspended");

    // Revoked tokens stop working.
    let token_id = created["id"].as_str().unwrap();
    let (status, _) = alice
        .call(
            server,
            Method::DELETE,
            &format!("{tokens}/{token_id}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = scim(server, Method::GET, "/Users", &token, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

impl Member {
    /// A member for an existing (not yet registered) client.
    async fn new_with(server: &TestServer, ip: &str, client: Client) -> Self {
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
}
