//! Organization administration: signed policies and their
//! server-side enforcement, the hash-chained audit log with client events,
//! export and retention, reports, settings, offboarding and the events API.

use axum::http::{Method, StatusCode};
use passbox_core::audit::{AuditRecord, ClientAction, ClientEventInput, verify_chain};
use passbox_core::policy::{PolicyRules, ShareLinkRule};
use passbox_core::sharing::objects::{OrgKind, PrincipalType, VaultRole};
use serde_json::{Value, json};

use super::{Member, TestServer, enable_totp, invite_and_confirm};

async fn audit(server: &TestServer, member: &Member, org_id: &str, query: &str) -> Vec<Value> {
    let (status, body) = member
        .call(
            server,
            Method::GET,
            &format!("/api/v1/orgs/{org_id}/audit?{query}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["events"].as_array().unwrap().clone()
}

fn actions(events: &[Value]) -> Vec<String> {
    events
        .iter()
        .map(|e| e["action"].as_str().unwrap().to_owned())
        .collect()
}

async fn put_policy(
    server: &TestServer,
    admin: &mut Member,
    org_id: &str,
    rules: &PolicyRules,
) -> (StatusCode, Value) {
    admin.sync(server).await;
    let upload = admin.keyring.sign_org_policy(org_id, rules, 10).unwrap();
    admin
        .call(
            server,
            Method::PUT,
            &format!("/api/v1/orgs/{org_id}/policy"),
            Some(serde_json::to_value(&upload).unwrap()),
        )
        .await
}

async fn verify(server: &TestServer, admin: &Member, org_id: &str) -> Value {
    let (status, body) = admin
        .call(
            server,
            Method::GET,
            &format!("/api/v1/orgs/{org_id}/audit/verify"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

pub(super) async fn organization_administration(server: &TestServer) {
    let mut alice = Member::new(server, "10.51.0.1").await;
    let mut bob = Member::new(server, "10.51.0.2").await;
    let mut dave = Member::new(server, "10.51.0.4").await;
    let outsider = Member::new(server, "10.51.0.3").await;

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
    invite_and_confirm(server, &mut alice, &mut dave, &org_id, "member").await;
    bob.sync(server).await;

    // --- Audit log: membership is logged, admins only ---------------------------
    let events = audit(server, &alice, &org_id, "limit=100").await;
    let logged = actions(&events);
    for action in [
        "org_created",
        "member_invited",
        "member_joined",
        "member_confirmed",
    ] {
        assert!(
            logged.contains(&action.to_owned()),
            "{action} in {logged:?}"
        );
    }
    let (status, _) = bob
        .call(
            server,
            Method::GET,
            &format!("/api/v1/orgs/{org_id}/audit"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = outsider
        .call(
            server,
            Method::GET,
            &format!("/api/v1/orgs/{org_id}/audit"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(verify(server, &alice, &org_id).await["valid"], true);

    // --- Policies -----------------------------------------------------------------
    assert!(
        bob.keyring
            .sign_org_policy(&org_id, &PolicyRules::default(), 1)
            .is_err(),
        "members cannot sign policies"
    );
    let v1 = PolicyRules {
        allow_personal_vault: false,
        max_auto_lock_minutes: 15,
        ..PolicyRules::default()
    };
    let upload = alice.keyring.sign_org_policy(&org_id, &v1, 1).unwrap();
    let (status, _) = bob
        .call(
            server,
            Method::PUT,
            &format!("/api/v1/orgs/{org_id}/policy"),
            Some(serde_json::to_value(&upload).unwrap()),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "members cannot upload policies"
    );
    let (status, body) = put_policy(server, &mut alice, &org_id, &v1).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // A replayed or stale version is refused.
    let stale = alice.keyring.sign_org_policy(&org_id, &v1, 11).unwrap();
    let (status, _) = alice
        .call(
            server,
            Method::PUT,
            &format!("/api/v1/orgs/{org_id}/policy"),
            Some(serde_json::to_value(&stale).unwrap()),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "the client has not synced version 1 yet"
    );
    // A tampered signature is refused.
    let mut forged = alice.keyring.sign_org_policy(&org_id, &v1, 12).unwrap();
    forged.signature = passbox_core::encoding::encode(&[1u8; 64]);
    let (status, _) = alice
        .call(
            server,
            Method::PUT,
            &format!("/api/v1/orgs/{org_id}/policy"),
            Some(serde_json::to_value(&forged).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Members receive and verify it in sync.
    let (body, report) = bob.sync(server).await;
    assert_eq!(body["sharing"]["policies"][0]["version"], 1);
    let policy = report
        .view
        .policies
        .iter()
        .find(|p| p.org_id == org_id)
        .unwrap();
    assert_eq!(policy.source, "verified");
    assert!(!report.view.effective_policy.allow_personal_vault);
    assert_eq!(report.view.effective_policy.max_auto_lock_minutes, Some(15));

    // The server enforces what it can: no new personal vaults.
    let vault = bob.keyring.create_vault(r#"{"name":"Mine"}"#).unwrap();
    let (status, body) = bob
        .call(
            server,
            Method::POST,
            "/api/v1/vaults",
            Some(json!({ "id": vault.id, "encryptedKey": vault.encrypted_key, "encryptedMeta": vault.encrypted_meta })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "policy_violation");
    // Outsiders are not affected.
    let mut outsider_keyring = outsider.keyring;
    let other = outsider_keyring.create_vault(r#"{"name":"Mine"}"#).unwrap();
    let (status, _) = server
        .request(
            Method::POST,
            "/api/v1/vaults",
            Some(&outsider.token),
            Some(json!({ "id": other.id, "encryptedKey": other.encrypted_key, "encryptedMeta": other.encrypted_meta })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // Version 2: two-factor sign-in required, item usage reported.
    let v2 = PolicyRules {
        require_two_factor: true,
        report_item_usage: true,
        share_links: ShareLinkRule::Restricted,
        share_link_max_days: 7,
        ..v1.clone()
    };
    let (status, body) = put_policy(server, &mut alice, &org_id, &v2).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["version"], 2);
    let (status, body) = alice
        .call(
            server,
            Method::GET,
            &format!("/api/v1/orgs/{org_id}/policy"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let history: Vec<passbox_core::policy::PolicyRecord> =
        serde_json::from_value(body["history"].clone()).unwrap();
    passbox_core::policy::verify_policy_chain(&org_id, &history).unwrap();
    let (_, body) = bob
        .call(
            server,
            Method::GET,
            &format!("/api/v1/orgs/{org_id}/policy"),
            None,
        )
        .await;
    assert_eq!(body["current"]["version"], 2);
    assert_eq!(body["history"], json!([]), "history is for admins");

    // Dave turned two-factor sign-in on and cannot turn it off now.
    let dave_ip = "10.51.0.4";
    let (dave_token, _, recovery_codes) = enable_totp(server, &dave.client, dave_ip).await;
    dave.token = dave_token;
    let (status, body) = server
        .post(
            "/api/v1/account/two-factor/disable",
            Some(&dave.token),
            json!({ "method": "recovery", "code": recovery_codes[0] }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "policy_violation");

    // --- Shared vault, writes and client events ---------------------------------
    alice.sync(server).await;
    let shared = alice
        .keyring
        .create_shared_vault(&org_id, r#"{"name":"Ops"}"#, 3)
        .unwrap();
    let vault_id = shared.id.clone();
    let (status, body) = alice
        .call(
            server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/vaults"),
            Some(serde_json::to_value(&shared).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    alice.sync(server).await;
    let change = alice
        .keyring
        .share_vault(
            &vault_id,
            PrincipalType::Account,
            bob.id(),
            VaultRole::Edit,
            4,
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
    bob.sync(server).await;
    let item_id = passbox_core::id::new_id().unwrap();
    assert_eq!(
        bob.put_item(server, &vault_id, 1, &item_id, 1).await,
        StatusCode::OK
    );

    let events = bob
        .keyring
        .sign_client_events(
            &org_id,
            &[ClientEventInput {
                action: ClientAction::ItemCopied,
                vault_id: vault_id.clone(),
                item_id: item_id.clone(),
                field: "password".into(),
                occurred_at: passbox_core_now(),
            }],
        )
        .unwrap();
    let upload = json!({ "events": events });
    let (status, body) = bob
        .call(
            server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/audit/client-events"),
            Some(upload.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["accepted"], 1);
    let (_, body) = bob
        .call(
            server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/audit/client-events"),
            Some(upload),
        )
        .await;
    assert_eq!(body["duplicates"], 1, "replays are dropped");
    // Events signed by someone else do not pass.
    let (status, _) = dave
        .call(
            server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/audit/client-events"),
            Some(json!({ "events": events })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let events = audit(server, &alice, &org_id, "limit=500").await;
    let logged = actions(&events);
    for action in [
        "policy_updated",
        "vault_created",
        "vault_access_granted",
        "item_created",
        "item_copied",
    ] {
        assert!(
            logged.contains(&action.to_owned()),
            "{action} in {logged:?}"
        );
    }
    let client_events = audit(server, &alice, &org_id, "source=client").await;
    assert_eq!(actions(&client_events), vec!["item_copied".to_owned()]);
    let by_bob = audit(server, &alice, &org_id, &format!("actor={}", bob.id())).await;
    assert!(by_bob.iter().all(|e| e["actorId"] == bob.id()));
    let members_only = audit(server, &alice, &org_id, "action=member_*").await;
    assert!(
        !members_only.is_empty()
            && members_only
                .iter()
                .all(|e| e["action"].as_str().unwrap().starts_with("member_"))
    );

    // --- Export: JSON verifies with the core, CSV is quoted -----------------------
    let (status, body) = alice
        .call(
            server,
            Method::GET,
            &format!("/api/v1/orgs/{org_id}/audit/export?format=json"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let records: Vec<AuditRecord> = serde_json::from_value(body["events"].clone()).unwrap();
    assert!(records.len() > 5);
    let check = verify_chain(&records, Some(""));
    assert!(check.valid, "{check:?}");
    let csv = server_text(
        server,
        &alice.token,
        &format!("/api/v1/orgs/{org_id}/audit/export?format=csv"),
    )
    .await;
    assert!(csv.starts_with(passbox_server::api::org_audit::CSV_HEADER));
    assert!(
        audit(server, &alice, &org_id, "action=audit_exported")
            .await
            .len()
            >= 2
    );

    // --- Reports and security aggregates -----------------------------------------
    let (status, _) = bob
        .call(
            server,
            Method::PUT,
            &format!("/api/v1/orgs/{org_id}/security-report"),
            Some(json!({ "score": 101, "total": 1, "weak": 0, "reused": 0, "unsecured": 0 })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = bob
        .call(
            server,
            Method::PUT,
            &format!("/api/v1/orgs/{org_id}/security-report"),
            Some(json!({ "score": 72, "total": 10, "weak": 2, "reused": 1, "unsecured": 0, "passwordMeetsPolicy": true,
                "siteBreaches": [
                    { "name": "Adobe", "title": "Adobe", "open": 1, "fixed": 0 },
                    { "name": "Netflix", "title": "Netflix", "open": 0, "fixed": 2 }
                ] })),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = bob
        .call(
            server,
            Method::PUT,
            &format!("/api/v1/orgs/{org_id}/security-report"),
            Some(
                json!({ "score": 72, "total": 10, "weak": 2, "reused": 1, "unsecured": 0,
                "siteBreaches": [
                    { "name": "Adobe", "open": 1, "fixed": 0 },
                    { "name": "Adobe", "open": 0, "fixed": 1 }
                ] }),
            ),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "duplicate breaches are refused"
    );
    let (status, _) = dave
        .call(
            server,
            Method::PUT,
            &format!("/api/v1/orgs/{org_id}/security-report"),
            Some(
                json!({ "score": 90, "total": 3, "weak": 0, "reused": 0, "unsecured": 0,
                "siteBreaches": [{ "name": "Adobe", "title": "Adobe", "open": 0, "fixed": 1 }] }),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, report) = alice
        .call(
            server,
            Method::GET,
            &format!("/api/v1/orgs/{org_id}/reports"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{report}");
    let member = |id: &str| {
        report["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["accountId"] == id)
            .unwrap()
            .clone()
    };
    assert_eq!(member(bob.id())["twoFactor"], false);
    assert_eq!(member(dave.id())["twoFactor"], true);
    assert_eq!(member(bob.id())["security"]["score"], 72);
    // Breached websites: members per breach, never item details.
    assert_eq!(
        report["siteBreaches"],
        json!([
            { "name": "Adobe", "title": "Adobe", "affectedMembers": 1, "fixedMembers": 1 },
            { "name": "Netflix", "title": "Netflix", "affectedMembers": 0, "fixedMembers": 1 }
        ])
    );
    assert_eq!(member(bob.id())["vaultCount"], 1);
    let vault = report["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["vaultId"] == vault_id.as_str())
        .unwrap();
    assert_eq!(vault["itemCount"], 1);
    assert_eq!(vault["managers"], json!([alice.id()]));
    assert_eq!(vault["unused"], false);
    assert!(
        report["access"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["accountId"] == bob.id()
                && a["role"] == "edit"
                && a["via"] == json!(["direct"]))
    );
    let (status, _) = bob
        .call(
            server,
            Method::GET,
            &format!("/api/v1/orgs/{org_id}/reports"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // --- Settings -------------------------------------------------------------------
    let (status, _) = alice
        .call(
            server,
            Method::PUT,
            &format!("/api/v1/orgs/{org_id}/settings"),
            Some(json!({ "auditRetentionDays": 10 })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = alice
        .call(
            server,
            Method::PUT,
            &format!("/api/v1/orgs/{org_id}/settings"),
            Some(json!({ "auditRetentionDays": 30 })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // --- Offboarding: end a member's sessions ------------------------------------
    let (status, _) = bob
        .call(
            server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/members/{}/end-sessions", dave.id()),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = alice
        .call(
            server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/members/{}/end-sessions", bob.id()),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["sessions"].as_u64().unwrap() >= 1);
    let (status, _) = bob.call(server, Method::GET, "/api/v1/account", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "signed out everywhere");
    bob.token = bob
        .client
        .try_login(server, &bob.client.auth_secret, Some("10.51.0.2"), None)
        .await
        .unwrap()
        .token;
    let logged = actions(&audit(server, &alice, &org_id, "limit=20").await);
    assert!(logged.contains(&"member_sessions_ended".to_owned()));
    assert!(
        logged.contains(&"member_signed_in".to_owned()),
        "sign-ins of members are logged: {logged:?}"
    );

    // --- Events API (pull) and webhooks (push) -------------------------------------
    let (status, body) = alice
        .call(
            server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/event-tokens"),
            Some(json!({ "name": "Splunk" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let token = body["token"].as_str().unwrap().to_owned();
    let token_id = body["id"].as_str().unwrap().to_owned();
    assert!(token.starts_with("pbxe_"));
    let (status, page) = server
        .request(
            Method::GET,
            "/api/v1/org-events?after=0&limit=3",
            Some(&token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["events"].as_array().unwrap().len(), 3);
    assert_eq!(page["events"][0]["seq"], 1);
    assert_eq!(page["hasMore"], true);
    assert_eq!(page["nextAfter"], 3);
    let (status, _) = server
        .request(Method::GET, "/api/v1/org-events", Some(&alice.token), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "sessions are not tokens");
    let (status, _) = alice
        .call(
            server,
            Method::DELETE,
            &format!("/api/v1/orgs/{org_id}/event-tokens/{token_id}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = server
        .request(Method::GET, "/api/v1/org-events", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body) = alice
        .call(
            server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/webhooks"),
            Some(json!({ "url": "https://127.0.0.1/hook" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = alice
        .call(
            server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/webhooks"),
            Some(json!({ "url": "https://93.184.215.14/passbox" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert!(body["secret"].as_str().unwrap().starts_with("whsec_"));
    let webhook_id = body["id"].as_str().unwrap().to_owned();
    let (_, list) = alice
        .call(
            server,
            Method::GET,
            &format!("/api/v1/orgs/{org_id}/webhooks"),
            None,
        )
        .await;
    assert!(list[0].get("secret").is_none(), "secrets are shown once");
    let (status, _) = alice
        .call(
            server,
            Method::DELETE,
            &format!("/api/v1/orgs/{org_id}/webhooks/{webhook_id}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // --- Removal is logged; retention keeps the chain verifiable ----------------
    let (status, _) = alice
        .call(
            server,
            Method::DELETE,
            &format!("/api/v1/orgs/{org_id}/members/{}", dave.id()),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        actions(&audit(server, &alice, &org_id, "limit=5").await)
            .contains(&"member_removed".to_owned())
    );

    // Entries older than the retention period go; the rest still verifies.
    sqlx::query("UPDATE org_audit_events SET created_at = 1 WHERE org_id = $1 AND seq <= 3")
        .bind(&org_id)
        .execute(server.db())
        .await
        .unwrap();
    let deleted = passbox_server::api::org_audit::apply_retention(&server.state)
        .await
        .unwrap();
    assert!(deleted >= 3);
    let check = verify(server, &alice, &org_id).await;
    assert_eq!(check["valid"], true, "{check}");
    assert_eq!(check["firstSeq"], 4);

    // Changing an entry breaks the chain at that entry.
    sqlx::query(
        "UPDATE org_audit_events SET actor_email = 'x@example.com' WHERE org_id = $1 AND seq = 6",
    )
    .bind(&org_id)
    .execute(server.db())
    .await
    .unwrap();
    let check = verify(server, &alice, &org_id).await;
    assert_eq!(check["valid"], false);
    assert_eq!(check["brokenAt"], 6);
}

/// Policies and the activity log are for team organizations (Business).
/// A family keeps only the recovery rule its apps set up, keeps no log,
/// and the other rules of a policy it stored earlier stay in the database
/// without being enforced.
pub(super) async fn families_have_no_policies_or_activity_log(server: &TestServer) {
    let mut alice = Member::new(server, "10.52.0.1").await;
    let mut bob = Member::new(server, "10.52.0.2").await;
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

    // A strict policy the family stored before policies became a team
    // feature.
    let strict = PolicyRules {
        allow_personal_vault: false,
        require_two_factor: true,
        report_item_usage: true,
        ..PolicyRules::default()
    };
    let upload = alice.keyring.sign_org_policy(&org_id, &strict, 1).unwrap();
    sqlx::query(
        "INSERT INTO org_policies (org_id, version, policy, signature, signer_id, rules, seq, created_at) \
         VALUES ($1, 1, $2, $3, $4, $5, 0, 0)",
    )
    .bind(&org_id)
    .bind(&upload.policy)
    .bind(&upload.signature)
    .bind(alice.id())
    .bind(serde_json::to_value(&strict).unwrap())
    .execute(server.db())
    .await
    .unwrap();

    // No version that restricts more than recovery enrollment ...
    let stricter = PolicyRules {
        forbid_export: true,
        ..strict.clone()
    };
    let (status, body) = put_policy(server, &mut alice, &org_id, &stricter).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "policies_team_only");
    let agents = PolicyRules {
        allow_agent_reveal: true,
        ..PolicyRules::new_org_defaults()
    };
    let (status, body) = put_policy(server, &mut alice, &org_id, &agents).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "policies_team_only");
    // ... and nothing to read.
    for member in [&alice, &bob] {
        let (status, body) = member
            .call(
                server,
                Method::GET,
                &format!("/api/v1/orgs/{org_id}/policy"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"], "policies_team_only");
    }

    // The stored rules are not enforced: personal vaults stay allowed ...
    let vault = bob.keyring.create_vault(r#"{"name":"Mine"}"#).unwrap();
    let (status, body) = bob
        .call(
            server,
            Method::POST,
            "/api/v1/vaults",
            Some(json!({ "id": vault.id, "encryptedKey": vault.encrypted_key, "encryptedMeta": vault.encrypted_meta })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    // ... two-factor sign-in can be turned off again ...
    let bob_ip = "10.52.0.2";
    let (bob_token, _, recovery_codes) = enable_totp(server, &bob.client, bob_ip).await;
    bob.token = bob_token;
    let (status, body) = server
        .post(
            "/api/v1/account/two-factor/disable",
            Some(&bob.token),
            json!({ "method": "recovery", "code": recovery_codes[0] }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    // ... and no item usage is collected.
    let (status, body) = bob
        .call(
            server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/audit/client-events"),
            Some(json!({ "events": [] })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Apps sign the version in force again when its signer leaves, and set
    // the recovery rule when they create a family: both still work.
    let (status, body) = put_policy(server, &mut alice, &org_id, &strict).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["version"], 2);
    let (status, body) = put_policy(
        server,
        &mut alice,
        &org_id,
        &PolicyRules::new_org_defaults(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["version"], 3);
    // Every version is kept.
    let kept: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM org_policies WHERE org_id = $1")
        .bind(&org_id)
        .fetch_one(server.db())
        .await
        .unwrap();
    assert_eq!(kept, 3);

    // Activity log: nothing recorded, nothing to view, verify or export.
    let logged: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM org_audit_events WHERE org_id = $1")
        .bind(&org_id)
        .fetch_one(server.db())
        .await
        .unwrap();
    assert_eq!(logged, 0, "families keep no activity log");
    for uri in [
        format!("/api/v1/orgs/{org_id}/audit"),
        format!("/api/v1/orgs/{org_id}/audit/verify"),
        format!("/api/v1/orgs/{org_id}/audit/export?format=json"),
    ] {
        let (status, body) = alice.call(server, Method::GET, &uri, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}: {body}");
        assert_eq!(body["error"], "audit_team_only", "{uri}: {body}");
    }
    // Members still get 403 for admin-only reads.
    let (status, body) = bob
        .call(
            server,
            Method::GET,
            &format!("/api/v1/orgs/{org_id}/audit"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "forbidden");
    // The events API carries the log: no tokens, no webhooks.
    for (uri, body) in [
        (
            format!("/api/v1/orgs/{org_id}/event-tokens"),
            json!({ "name": "Splunk" }),
        ),
        (
            format!("/api/v1/orgs/{org_id}/webhooks"),
            json!({ "url": "https://siem.example.com/hook" }),
        ),
    ] {
        let (status, body) = alice.call(server, Method::POST, &uri, Some(body)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}: {body}");
        assert_eq!(body["error"], "audit_team_only", "{uri}: {body}");
    }
}

fn passbox_core_now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

async fn server_text(server: &TestServer, token: &str, uri: &str) -> String {
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let request = axum::http::Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let response = server.app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}
