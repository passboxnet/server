//! Recovery code, organization recovery, emergency access and device links.

use axum::http::{Method, StatusCode};
use passbox_core::device_link::{DeviceLinkOffer, DeviceLinkRequest};
use passbox_core::keyring::{AccountKeysUpload, Keyring};
use passbox_core::opaque::{ClientLoginFlow, ClientRegistrationFlow};
use passbox_core::recovery::code::RecoveryCode;
use passbox_core::recovery::org::{
    ApprovedRecovery, OrgRecoveryRecord, RecoveryRequestKey, RecoveryRequestRecord,
};
use passbox_core::sharing::objects::OrgKind;
use passbox_core::{aead::SymmetricKey, encoding, random};
use serde_json::{Value, json};

use super::{Client, Member, TestServer, enable_totp, event_kinds, invite_and_confirm, totp_code};

async fn mails(server: &TestServer, recipient: &str) -> Vec<String> {
    sqlx::query_scalar("SELECT template FROM mail_outbox WHERE recipient = $1 ORDER BY created_at")
        .bind(recipient)
        .fetch_all(server.db())
        .await
        .unwrap()
}

async fn post_from(
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

/// Registers a recovery code for a signed-in member.
async fn create_recovery_code(server: &TestServer, member: &Member) -> RecoveryCode {
    let code = RecoveryCode::generate().unwrap();
    let keys = code.keys().unwrap();
    let (flow, request) = ClientRegistrationFlow::start(&*keys.auth_secret).unwrap();
    let (status, body) = member
        .call(
            server,
            Method::POST,
            "/api/v1/account/recovery-code/start",
            Some(json!({ "registrationRequest": encoding::encode(&request) })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let upload = flow
        .finish(&encoding::decode(body["registrationResponse"].as_str().unwrap()).unwrap())
        .unwrap();
    let wrapped = member
        .keyring
        .wrap_account_key_for_recovery(&keys.wrap_key)
        .unwrap();
    let (status, body) = member
        .call(
            server,
            Method::POST,
            "/api/v1/account/recovery-code",
            Some(json!({ "registrationUpload": encoding::encode(&upload), "wrappedAccountKey": wrapped })),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    code
}

/// Runs the recovery-code login. `Err` carries the status of the rejected step.
async fn recover_with_code(
    server: &TestServer,
    ip: &str,
    email: &str,
    code: &RecoveryCode,
) -> Result<Value, StatusCode> {
    let keys = code.keys().unwrap();
    let (flow, request) = ClientLoginFlow::start(&*keys.auth_secret).unwrap();
    let (status, body) = post_from(
        server,
        ip,
        "/api/v1/recovery/code/start",
        None,
        json!({ "email": email, "credentialRequest": encoding::encode(&request) }),
    )
    .await;
    if status != StatusCode::OK {
        return Err(status);
    }
    let response = encoding::decode(body["credentialResponse"].as_str().unwrap()).unwrap();
    let finalization = match flow.finish(&response) {
        Ok(finish) => finish.finalization,
        // A wrong code fails on the client; check the server rejects it too.
        Err(_) => vec![0u8; 64],
    };
    let (status, body) = post_from(
        server,
        ip,
        "/api/v1/recovery/code/finish",
        None,
        json!({
            "loginId": body["loginId"],
            "credentialFinalization": encoding::encode(&finalization),
            "deviceName": "Recovery device",
            "clientKind": "web",
        }),
    )
    .await;
    if status == StatusCode::OK {
        Ok(body)
    } else {
        Err(status)
    }
}

/// Sets new credentials with a recovery token. Returns the new auth secret
/// and the new recovery code.
async fn complete(
    server: &TestServer,
    ip: &str,
    token: &str,
    keyring: &Keyring,
) -> Result<([u8; 32], RecoveryCode), (StatusCode, Value)> {
    let auth_secret: [u8; 32] = random::bytes().unwrap();
    let auk = SymmetricKey::generate().unwrap();
    let code = RecoveryCode::generate().unwrap();
    let code_keys = code.keys().unwrap();
    let (flow, request) = ClientRegistrationFlow::start(&auth_secret).unwrap();
    let (code_flow, code_request) = ClientRegistrationFlow::start(&*code_keys.auth_secret).unwrap();
    let (status, body) = post_from(
        server,
        ip,
        "/api/v1/recovery/complete/start",
        None,
        json!({
            "recoveryToken": token,
            "registrationRequest": encoding::encode(&request),
            "recoveryRegistrationRequest": encoding::encode(&code_request),
        }),
    )
    .await;
    if status != StatusCode::OK {
        return Err((status, body));
    }
    let upload = flow
        .finish(&encoding::decode(body["registrationResponse"].as_str().unwrap()).unwrap())
        .unwrap();
    let code_upload = code_flow
        .finish(&encoding::decode(body["recoveryRegistrationResponse"].as_str().unwrap()).unwrap())
        .unwrap();
    let (status, body) = post_from(
        server,
        ip,
        "/api/v1/recovery/complete/finish",
        None,
        json!({
            "recoveryToken": token,
            "registrationUpload": encoding::encode(&upload),
            "kdfSalt": encoding::encode(&[9u8; 16]),
            "kdfParams": passbox_core::kdf::KdfParams::DEFAULT,
            "encryptedAccountKey": keyring.wrap_account_key(&auk).unwrap(),
            "recoveryCode": {
                "registrationUpload": encoding::encode(&code_upload),
                "wrappedAccountKey": keyring.wrap_account_key_for_recovery(&code_keys.wrap_key).unwrap(),
            },
        }),
    )
    .await;
    if status != StatusCode::NO_CONTENT {
        return Err((status, body));
    }
    Ok((auth_secret, code))
}

fn account_keys(body: &Value) -> AccountKeysUpload {
    serde_json::from_value(body["accountKeys"].clone()).unwrap()
}

pub(super) async fn recovery_code(server: &TestServer) {
    let ip = "10.40.0.1";
    let mut ada = Member::new(server, ip).await;
    let (status, body) = ada
        .call(server, Method::GET, "/api/v1/account/recovery", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["recoveryCode"], Value::Null);
    let code = create_recovery_code(server, &ada).await;
    let (_, body) = ada
        .call(server, Method::GET, "/api/v1/account/recovery", None)
        .await;
    assert!(body["recoveryCode"]["createdAt"].as_i64().unwrap() > 0);
    assert!(
        mails(server, &ada.client.email)
            .await
            .contains(&"recovery_code_created".to_owned())
    );

    // Unknown emails and accounts without a code look the same as real ones,
    // and a wrong code fails.
    let stranger = format!("{}@example.com", passbox_core::id::new_id().unwrap());
    assert_eq!(
        recover_with_code(server, ip, &stranger, &code).await.err(),
        Some(StatusCode::UNAUTHORIZED)
    );
    let wrong = RecoveryCode::generate().unwrap();
    assert_eq!(
        recover_with_code(server, ip, &ada.client.email, &wrong)
            .await
            .err(),
        Some(StatusCode::UNAUTHORIZED)
    );
    assert!(
        event_kinds(server, &ada.token)
            .await
            .contains(&"account_recovery_failed".to_owned())
    );

    // The right code returns the wrapped account key and the key pairs.
    let body = recover_with_code(server, ip, &ada.client.email, &code)
        .await
        .unwrap();
    assert_eq!(body["method"], "code");
    assert!(body.get("twoFactorMethods").is_none());
    let mut recovered = Keyring::unlock_with_recovery(
        &code.keys().unwrap().wrap_key,
        &ada.client.account_id,
        body["wrappedAccountKey"].as_str().unwrap(),
    )
    .unwrap();
    let keys = account_keys(&body);
    recovered
        .load_account_keys(
            &keys.bundle,
            &keys.bundle_signature,
            &keys.encrypted_private,
        )
        .unwrap();
    let token = body["recoveryToken"].as_str().unwrap().to_owned();

    // New credentials: every session ends, the old ones stop working.
    let (new_secret, new_code) = complete(server, ip, &token, &recovered).await.unwrap();
    let (status, _) = ada
        .call(server, Method::GET, "/api/v1/account/recovery", None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "old session revoked");
    assert_eq!(
        ada.client
            .try_login(server, &ada.client.auth_secret, Some(ip), None)
            .await
            .map(|_| ())
            .map_err(|(status, _)| status),
        Err(StatusCode::UNAUTHORIZED)
    );
    let fresh = ada
        .client
        .try_login(server, &new_secret, Some(ip), None)
        .await
        .unwrap()
        .token;
    ada.token = fresh.clone();
    let kinds = event_kinds(server, &fresh).await;
    assert!(
        kinds.contains(&"account_recovered_code".to_owned()),
        "{kinds:?}"
    );
    assert!(
        mails(server, &ada.client.email)
            .await
            .contains(&"recovery_used".to_owned())
    );
    // The token was single use, and the old code was replaced.
    let (status, body) = complete(server, ip, &token, &recovered).await.unwrap_err();
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "recovery_expired");
    assert_eq!(
        recover_with_code(server, ip, &ada.client.email, &code)
            .await
            .err(),
        Some(StatusCode::UNAUTHORIZED)
    );
    assert!(
        recover_with_code(server, ip, &ada.client.email, &new_code)
            .await
            .is_ok()
    );

    // With two-factor sign-in, the code alone is not enough.
    let mut client = ada.client.clone_with_secret(new_secret);
    client.email = ada.client.email.clone();
    let (two_factor_token, secret, _) = enable_totp(server, &client, ip).await;
    let _ = two_factor_token;
    let body = recover_with_code(server, ip, &ada.client.email, &new_code)
        .await
        .unwrap();
    assert!(body.get("wrappedAccountKey").is_none());
    let methods: Vec<String> = serde_json::from_value(body["twoFactorMethods"].clone()).unwrap();
    assert_eq!(methods, vec!["totp", "recovery"]);
    let token = body["recoveryToken"].as_str().unwrap().to_owned();
    let (status, body) = complete(server, ip, &token, &recovered).await.unwrap_err();
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "two_factor_required");
    let (status, _) = post_from(
        server,
        ip,
        "/api/v1/recovery/two-factor",
        None,
        json!({ "recoveryToken": token, "method": "totp", "code": "000000" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = post_from(
        server,
        ip,
        "/api/v1/recovery/two-factor",
        None,
        json!({ "recoveryToken": token, "method": "totp", "code": totp_code(&secret, 1) }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["wrappedAccountKey"].as_str().is_some());
    complete(server, ip, &token, &recovered).await.unwrap();

    // Recovery attempts are rate limited per email and IP.
    let other_ip = "10.40.0.99";
    for _ in 0..10 {
        assert_eq!(
            recover_with_code(server, other_ip, &ada.client.email, &wrong)
                .await
                .err(),
            Some(StatusCode::UNAUTHORIZED)
        );
    }
    assert_eq!(
        recover_with_code(server, other_ip, &ada.client.email, &wrong)
            .await
            .err(),
        Some(StatusCode::TOO_MANY_REQUESTS)
    );
    let _ = &mut ada;
}

async fn org_recovery_record(
    server: &TestServer,
    member: &Member,
    org_id: &str,
) -> OrgRecoveryRecord {
    let (status, body) = member
        .call(
            server,
            Method::GET,
            &format!("/api/v1/orgs/{org_id}/recovery"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    serde_json::from_value(body["key"].clone()).unwrap()
}

pub(super) async fn organization_recovery(server: &TestServer) {
    let ip = "10.41.0.1";
    let mut alice = Member::new(server, "10.41.0.2").await;
    let mut bob = Member::new(server, "10.41.0.3").await;
    let org = alice
        .keyring
        .create_org(OrgKind::Team, r#"{"name":"Acme"}"#, None, 1)
        .unwrap();
    let org_id = org.id.clone();
    let (status, body) = alice
        .call(
            server,
            Method::POST,
            "/api/v1/orgs",
            Some(serde_json::to_value(&org).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    alice.sync(server).await;
    invite_and_confirm(server, &mut alice, &mut bob, &org_id, "member").await;
    bob.sync(server).await;

    // The owner sets up recovery; members cannot.
    let upload = alice
        .keyring
        .create_org_recovery_key(&org_id, 1, 5)
        .unwrap();
    let (status, _) = bob
        .call(
            server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/recovery/keys"),
            Some(serde_json::to_value(&upload).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = alice
        .call(
            server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/recovery/keys"),
            Some(serde_json::to_value(&upload).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // Bob opts in.
    let record = org_recovery_record(server, &bob, &org_id).await;
    assert!(record.grants[0].sealed_key.is_none(), "only for the holder");
    let info = bob.keyring.verify_org_recovery(&org_id, &record).unwrap();
    assert_eq!(info.admins, vec![alice.id().to_owned()]);
    let escrow = bob
        .keyring
        .enroll_org_recovery(&org_id, &record, 6)
        .unwrap();
    let (status, body) = bob
        .call(
            server,
            Method::PUT,
            &format!("/api/v1/orgs/{org_id}/recovery/escrow"),
            Some(serde_json::to_value(&escrow).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (_, body) = bob
        .call(server, Method::GET, "/api/v1/account/recovery", None)
        .await;
    assert_eq!(body["orgEscrows"][0]["orgId"], org_id.as_str());

    // Bob forgot his password: a new device asks for recovery. Unknown
    // emails get the same answer.
    let device = RecoveryRequestKey::generate().unwrap();
    let request = |email: &str, key: &RecoveryRequestKey| json!({ "email": email, "orgId": org_id, "ephemeralKey": encoding::encode(&key.public_key()), "deviceName": "Firefox on Linux" });
    let (status, fake) = post_from(
        server,
        ip,
        "/api/v1/recovery/org/request",
        None,
        request("nobody@example.com", &device),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, body) = post_from(
        server,
        ip,
        "/api/v1/recovery/org/request",
        None,
        request(&bob.client.email, &device),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(
        fake.as_object().unwrap().keys().collect::<Vec<_>>(),
        body.as_object().unwrap().keys().collect::<Vec<_>>()
    );
    let request_id = body["requestId"].as_str().unwrap().to_owned();
    let request_token = body["requestToken"].as_str().unwrap().to_owned();
    let status_body = json!({ "requestId": request_id, "requestToken": request_token });
    let (_, body) = post_from(
        server,
        ip,
        "/api/v1/recovery/org/status",
        None,
        status_body.clone(),
    )
    .await;
    assert_eq!(body["status"], "pending");
    assert!(
        mails(server, &alice.client.email)
            .await
            .contains(&"recovery_requested".to_owned())
    );
    assert!(
        mails(server, &bob.client.email)
            .await
            .contains(&"recovery".to_owned())
    );

    // Only admins who hold the key see requests.
    let (status, _) = bob
        .call(
            server,
            Method::GET,
            &format!("/api/v1/orgs/{org_id}/recovery/requests"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = alice
        .call(
            server,
            Method::GET,
            &format!("/api/v1/orgs/{org_id}/recovery/requests"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let requests: Vec<RecoveryRequestRecord> = serde_json::from_value(body.clone()).unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(body[0]["email"], bob.client.email.as_str());

    // Alice compares the code with Bob and approves.
    let record = org_recovery_record(server, &alice, &org_id).await;
    let approval = alice
        .keyring
        .approve_org_recovery(&record, &requests[0], 7)
        .unwrap();
    assert_eq!(approval.request_code, device.request_code());
    let mut forged = approval.clone();
    forged.sealed_key = encoding::encode(&[1u8; 1200]);
    let (status, _) = alice
        .call(
            server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/recovery/requests/{request_id}/approve"),
            Some(serde_json::to_value(&forged).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "sealed key not covered");
    let (status, body) = alice
        .call(
            server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/recovery/requests/{request_id}/approve"),
            Some(serde_json::to_value(&approval).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert!(
        mails(server, &bob.client.email)
            .await
            .contains(&"recovery_approved".to_owned())
    );

    // A wrong request token sees nothing.
    let (_, body) = post_from(
        server,
        ip,
        "/api/v1/recovery/org/status",
        None,
        json!({ "requestId": request_id, "requestToken": "wrong" }),
    )
    .await;
    assert_eq!(body["status"], "pending");
    assert!(body.get("approved").is_none());

    // The device opens the account key and sets new credentials.
    let (status, body) = post_from(
        server,
        ip,
        "/api/v1/recovery/org/status",
        None,
        status_body.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "approved");
    let approved: ApprovedRecovery = serde_json::from_value(body["approved"].clone()).unwrap();
    let mut recovered = device.open(&approved).unwrap();
    let keys: AccountKeysUpload =
        serde_json::from_value(body["recovery"]["accountKeys"].clone()).unwrap();
    recovered
        .load_account_keys(
            &keys.bundle,
            &keys.bundle_signature,
            &keys.encrypted_private,
        )
        .unwrap();
    let token = body["recovery"]["recoveryToken"]
        .as_str()
        .unwrap()
        .to_owned();
    let (new_secret, _) = complete(server, ip, &token, &recovered).await.unwrap();
    let (status, _) = bob
        .call(server, Method::GET, "/api/v1/account/recovery", None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let fresh = bob
        .client
        .try_login(server, &new_secret, Some(ip), None)
        .await
        .unwrap()
        .token;
    bob.token = fresh.clone();
    assert!(
        event_kinds(server, &fresh)
            .await
            .contains(&"account_recovered_org".to_owned())
    );
    assert!(
        event_kinds(server, &alice.token)
            .await
            .contains(&"org_member_recovered".to_owned())
    );
    assert!(
        mails(server, &alice.client.email)
            .await
            .contains(&"recovery_used".to_owned())
    );
    let (_, body) = post_from(server, ip, "/api/v1/recovery/org/status", None, status_body).await;
    assert_eq!(body["status"], "completed");

    // A second request can be declined; then the device gets nothing.
    let other = RecoveryRequestKey::generate().unwrap();
    let (_, body) = post_from(
        server,
        ip,
        "/api/v1/recovery/org/request",
        None,
        request(&bob.client.email, &other),
    )
    .await;
    let request_id = body["requestId"].as_str().unwrap().to_owned();
    let status_body = json!({ "requestId": request_id, "requestToken": body["requestToken"] });
    let (status, _) = alice
        .call(
            server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/recovery/requests/{request_id}/deny"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, body) = post_from(server, ip, "/api/v1/recovery/org/status", None, status_body).await;
    assert_eq!(body["status"], "denied");
    assert!(body.get("recovery").is_none());

    // Opting out deletes the escrow.
    let (status, _) = bob
        .call(
            server,
            Method::DELETE,
            &format!("/api/v1/orgs/{org_id}/recovery/escrow"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, body) = bob
        .call(server, Method::GET, "/api/v1/account/recovery", None)
        .await;
    assert_eq!(body["orgEscrows"], json!([]));
}

pub(super) async fn emergency_access(server: &TestServer) {
    let ip = "10.42.0.1";
    let mut grantor = Member::new(server, "10.42.0.2").await;
    let mut grantee = Member::new(server, "10.42.0.3").await;
    let vault = grantor
        .keyring
        .create_vault(r#"{"name":"Notfall"}"#)
        .unwrap();
    let (status, body) = grantor
        .call(
            server,
            Method::POST,
            "/api/v1/vaults",
            Some(json!({ "id": vault.id, "encryptedKey": vault.encrypted_key, "encryptedMeta": vault.encrypted_meta })),
        )
        .await;
    assert!(status.is_success(), "{body}");
    let item_id = passbox_core::id::new_id().unwrap();
    let item = grantor
        .keyring
        .encrypt_item(&vault.id, &item_id, 1, r#"{"title":"Bank"}"#)
        .unwrap();
    let (status, body) = grantor
        .call(
            server,
            Method::PUT,
            &format!("/api/v1/items/{item_id}"),
            Some(json!({ "vaultId": vault.id, "revision": 1, "encryptedData": item })),
        )
        .await;
    assert!(status.is_success(), "{body}");

    // Invite, accept, confirm.
    let (status, _) = grantor
        .call(
            server,
            Method::POST,
            "/api/v1/emergency/grants",
            Some(json!({ "granteeEmail": grantor.client.email, "waitDays": 7 })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "not yourself");
    let (status, _) = grantor
        .call(
            server,
            Method::POST,
            "/api/v1/emergency/grants",
            Some(json!({ "granteeEmail": grantee.client.email, "waitDays": 31 })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "wait too long");
    let (status, body) = grantor
        .call(
            server,
            Method::POST,
            "/api/v1/emergency/grants",
            Some(json!({ "granteeEmail": grantee.client.email, "waitDays": 7 })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let grant_id = body["id"].as_str().unwrap().to_owned();
    assert!(
        mails(server, &grantee.client.email)
            .await
            .contains(&"emergency_access_invited".to_owned())
    );
    let (_, list) = grantee
        .call(server, Method::GET, "/api/v1/emergency", None)
        .await;
    assert_eq!(list["received"][0]["status"], "invited");
    let (status, _) = grantor
        .call(
            server,
            Method::POST,
            &format!("/api/v1/emergency/grants/{grant_id}/accept"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "only the invited person");
    let (status, _) = grantee
        .call(
            server,
            Method::POST,
            &format!("/api/v1/emergency/grants/{grant_id}/accept"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    grantor.lookup(server, grantee.id()).await;
    let upload = grantor
        .keyring
        .seal_emergency_access(
            &grant_id,
            grantee.id(),
            7,
            std::slice::from_ref(&vault.id),
            1,
            10,
        )
        .unwrap();
    let mut wrong_wait = grantor
        .keyring
        .seal_emergency_access(
            &grant_id,
            grantee.id(),
            3,
            std::slice::from_ref(&vault.id),
            1,
            10,
        )
        .unwrap();
    wrong_wait.version = 1;
    let (status, _) = grantor
        .call(
            server,
            Method::POST,
            &format!("/api/v1/emergency/grants/{grant_id}/confirm"),
            Some(serde_json::to_value(&wrong_wait).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "signed wait must match");
    let (status, body) = grantor
        .call(
            server,
            Method::POST,
            &format!("/api/v1/emergency/grants/{grant_id}/confirm"),
            Some(serde_json::to_value(&upload).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, _) = grantor
        .call(
            server,
            Method::POST,
            &format!("/api/v1/emergency/grants/{grant_id}/confirm"),
            Some(serde_json::to_value(&upload).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "versions only grow");

    // Nothing before a request and the waiting period.
    let access = format!("/api/v1/emergency/grants/{grant_id}/access");
    let (status, body) = grantee.call(server, Method::GET, &access, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "emergency_access_waiting");
    let (status, _) = grantee
        .call(
            server,
            Method::POST,
            &format!("/api/v1/emergency/grants/{grant_id}/request"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        mails(server, &grantor.client.email)
            .await
            .contains(&"emergency_access".to_owned())
    );
    let (status, _) = grantee.call(server, Method::GET, &access, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "waiting");
    let (_, list) = grantee
        .call(server, Method::GET, "/api/v1/emergency", None)
        .await;
    let release = list["received"][0]["releaseAt"].as_i64().unwrap();
    let requested = list["received"][0]["requestedAt"].as_i64().unwrap();
    assert_eq!(release - requested, 7 * 24 * 60 * 60 * 1000);

    // The grantor declines.
    let (status, _) = grantor
        .call(
            server,
            Method::POST,
            &format!("/api/v1/emergency/grants/{grant_id}/deny"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        mails(server, &grantee.client.email)
            .await
            .contains(&"emergency_access_denied".to_owned())
    );
    let (status, _) = grantee.call(server, Method::GET, &access, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A new request; the waiting period passes without a decline.
    grantee
        .call(
            server,
            Method::POST,
            &format!("/api/v1/emergency/grants/{grant_id}/request"),
            None,
        )
        .await;
    sqlx::query("UPDATE emergency_grants SET requested_at = requested_at - $1 WHERE id = $2")
        .bind(7 * 24 * 60 * 60 * 1000_i64 + 1000)
        .bind(&grant_id)
        .execute(server.db())
        .await
        .unwrap();
    let (status, body) = grantee.call(server, Method::GET, &access, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    grantee.lookup(server, grantor.id()).await;
    let keys = grantee
        .keyring
        .open_emergency_access(
            body["grant"].as_str().unwrap(),
            body["grantSignature"].as_str().unwrap(),
            body["sealedKeys"].as_str().unwrap(),
        )
        .unwrap();
    let item = &body["items"][0];
    assert_eq!(
        keys.decrypt_item(
            item["vaultId"].as_str().unwrap(),
            0,
            item["id"].as_str().unwrap(),
            item["revision"].as_u64().unwrap(),
            item["encryptedData"].as_str().unwrap()
        )
        .unwrap(),
        r#"{"title":"Bank"}"#
    );
    assert_eq!(
        keys.decrypt_vault_meta(
            &vault.id,
            0,
            body["vaults"][0]["encryptedMeta"].as_str().unwrap()
        )
        .unwrap(),
        r#"{"name":"Notfall"}"#
    );
    assert!(
        mails(server, &grantor.client.email)
            .await
            .contains(&"emergency_access_used".to_owned())
    );
    assert!(
        event_kinds(server, &grantor.token)
            .await
            .contains(&"emergency_access_used".to_owned())
    );

    // Others cannot read it; removing the contact ends access.
    let stranger = Member::new(server, "10.42.0.4").await;
    let (status, _) = stranger.call(server, Method::GET, &access, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = grantor
        .call(
            server,
            Method::DELETE,
            &format!("/api/v1/emergency/grants/{grant_id}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = grantee.call(server, Method::GET, &access, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let _ = ip;
}

pub(super) async fn device_links(server: &TestServer) {
    let ip = "10.43.0.1";
    let member = Member::new(server, ip).await;
    let (status, body) = member
        .call(server, Method::POST, "/api/v1/device-links", None)
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let link_id = body["id"].as_str().unwrap().to_owned();
    let offer = DeviceLinkOffer::new(body["shortId"].as_str().unwrap()).unwrap();

    // The new device (no session) claims the link with the code.
    let device = DeviceLinkRequest::new(&offer.code()).unwrap();
    let claim = json!({
        "shortId": device.short_id(),
        "ephemeralKey": encoding::encode(&device.public_key()),
        "mac": encoding::encode(device.mac()),
        "deviceName": "Safari on iPhone",
    });
    let (status, body) = post_from(
        server,
        ip,
        "/api/v1/device-links/claim",
        None,
        claim.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let claim_token = body["claimToken"].as_str().unwrap().to_owned();
    let (status, body) = post_from(server, ip, "/api/v1/device-links/claim", None, claim).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "first claim wins");
    assert_eq!(body["error"], "device_link_expired");
    let poll = json!({ "claimToken": claim_token });
    let (_, body) = post_from(server, ip, "/api/v1/device-links/poll", None, poll.clone()).await;
    assert_eq!(body["status"], "claimed");

    // The signed-in device checks the claim and approves.
    let (status, link) = member
        .call(
            server,
            Method::GET,
            &format!("/api/v1/device-links/{link_id}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(link["status"], "claimed");
    assert_eq!(link["deviceName"], "Safari on iPhone");
    let payload =
        json!({ "email": member.client.email, "accountId": member.id(), "secretKey": "P1-TEST" })
            .to_string();
    let sealed = offer
        .seal(
            &encoding::decode(link["ephemeralKey"].as_str().unwrap()).unwrap(),
            &encoding::decode(link["mac"].as_str().unwrap()).unwrap(),
            &payload,
        )
        .unwrap();
    let (status, _) = member
        .call(
            server,
            Method::POST,
            &format!("/api/v1/device-links/{link_id}/approve"),
            Some(json!({ "sealedPayload": sealed })),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, body) = post_from(server, ip, "/api/v1/device-links/poll", None, poll.clone()).await;
    assert_eq!(body["status"], "approved");
    assert_eq!(
        device
            .open(body["sealedPayload"].as_str().unwrap())
            .unwrap(),
        payload
    );
    // Delivered once.
    let (status, _) = post_from(server, ip, "/api/v1/device-links/poll", None, poll).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        event_kinds(server, &member.token)
            .await
            .contains(&"device_link_approved".to_owned())
    );
}

impl Client {
    fn clone_with_secret(&self, auth_secret: [u8; 32]) -> Client {
        Client {
            email: self.email.clone(),
            account_id: self.account_id.clone(),
            auth_secret,
            auk: SymmetricKey::generate().unwrap(),
        }
    }
}
