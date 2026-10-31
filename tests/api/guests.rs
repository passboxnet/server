//! Guests are view-only and not billable, organization recovery is on by
//! default, and the server's part of agent reveals (`allow_agent_reveal`).

use axum::http::{Method, StatusCode};
use passbox_core::policy::PolicyRules;
use passbox_core::share_link;
use passbox_core::sharing::objects::{OrgKind, OrgRole, PrincipalType, VaultRole};
use serde_json::{Value, json};

use super::{Member, TestServer};

async fn put_policy(server: &TestServer, admin: &mut Member, org_id: &str, rules: &PolicyRules) {
    admin.sync(server).await;
    let upload = admin.keyring.sign_org_policy(org_id, rules, 10).unwrap();
    let (status, body) = admin
        .call(
            server,
            Method::PUT,
            &format!("/api/v1/orgs/{org_id}/policy"),
            Some(serde_json::to_value(&upload).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

fn link_body(vault_id: &str) -> Value {
    let link_id = passbox_core::id::new_id().unwrap();
    let link = share_link::create(&link_id, r#"{"title":"Wi-Fi"}"#, None).unwrap();
    json!({
        "id": link_id,
        "encryptedLabel": "bGFiZWw",
        "blob": link.blob,
        "authHash": link.auth_hash,
        "salt": link.salt,
        "expiresAt": passbox_server::db::now_ms() + 60_000,
        "maxViews": 0,
        "vaultId": vault_id,
    })
}

/// Invites, previews, accepts and confirms; returns the preview.
async fn invite(
    server: &TestServer,
    admin: &mut Member,
    member: &mut Member,
    org_id: &str,
    role: &str,
) -> Value {
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
    let (status, preview) = server
        .request(
            Method::GET,
            &format!("/api/v1/invitations/{token}"),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
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
    admin.lookup(server, member.id()).await;
    let confirm = admin
        .keyring
        .confirm_member(org_id, member.id(), 2)
        .unwrap();
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
    preview
}

pub(super) async fn guests_and_defaults(server: &TestServer) {
    let mut alice = Member::new(server, "10.81.0.1").await;
    let mut bob = Member::new(server, "10.81.0.2").await;
    let mut gina = Member::new(server, "10.81.0.3").await;

    let org = alice
        .keyring
        .create_org(OrgKind::Team, r#"{"name":"Agency"}"#, None, 1)
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

    // --- Recovery on by default: key + policy that requires enrollment ------------
    let upload = alice
        .keyring
        .create_org_recovery_key(&org_id, 1, 5)
        .unwrap();
    let (status, body) = alice
        .call(
            server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/recovery/keys"),
            Some(serde_json::to_value(&upload).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    put_policy(
        server,
        &mut alice,
        &org_id,
        &PolicyRules::new_org_defaults(),
    )
    .await;

    // The invitation preview says so; never for guests.
    let preview = invite(server, &mut alice, &mut bob, &org_id, "member").await;
    assert_eq!(preview["recovery"], true, "{preview}");
    let preview = invite(server, &mut alice, &mut gina, &org_id, "guest").await;
    assert_eq!(preview["recovery"], false, "{preview}");

    // Recovery cannot be turned off while the policy requires it.
    let recovery = format!("/api/v1/orgs/{org_id}/recovery");
    let (status, body) = bob.call(server, Method::DELETE, &recovery, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "members cannot: {body}");
    let (status, body) = alice.call(server, Method::DELETE, &recovery, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "recovery_required");

    // --- Shared vault: Bob edits, Gina views ----------------------------------------
    alice.sync(server).await;
    let shared = alice
        .keyring
        .create_shared_vault(&org_id, r#"{"name":"Client"}"#, 3)
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
    for (who, role) in [
        (bob.id().to_owned(), VaultRole::Edit),
        (gina.id().to_owned(), VaultRole::View),
    ] {
        alice.sync(server).await;
        let change = alice
            .keyring
            .share_vault(&vault_id, PrincipalType::Account, &who, role, 4)
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
    }
    // The core refuses more than view for a guest.
    alice.sync(server).await;
    assert!(
        alice
            .keyring
            .share_vault(
                &vault_id,
                PrincipalType::Account,
                gina.id(),
                VaultRole::Edit,
                5
            )
            .is_err()
    );

    bob.sync(server).await;
    let item_id = passbox_core::id::new_id().unwrap();
    assert_eq!(
        bob.put_item(server, &vault_id, 1, &item_id, 1).await,
        StatusCode::OK
    );

    // Gina reads it, and nothing else.
    let (_, report) = gina.sync(server).await;
    let view = report
        .view
        .vaults
        .iter()
        .find(|v| v.vault_id == vault_id)
        .unwrap();
    assert_eq!(view.role.as_deref(), Some("view"));
    let (status, body) = gina
        .call(server, Method::GET, "/api/v1/sync?since=0&sharing=1", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["id"] == item_id.as_str())
    );
    let (status, body) = gina
        .call(
            server,
            Method::POST,
            "/api/v1/share-links",
            Some(link_body(&vault_id)),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "guest_view_only");
    let (status, body) = gina
        .call(
            server,
            Method::POST,
            &format!("/api/v1/vaults/{vault_id}/access-requests"),
            Some(json!({ "role": "edit" })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "guest_view_only");
    let (status, _) = gina
        .call(
            server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/invitations"),
            Some(json!({ "email": "friend@example.com", "role": "guest" })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "guests cannot invite");

    // A member who becomes a guest keeps the signed `edit` entry, but the
    // server caps it: writes are refused with a clear code.
    alice.sync(server).await;
    let change = alice
        .keyring
        .set_member_role(&org_id, bob.id(), OrgRole::Guest, 6)
        .unwrap();
    let (status, body) = alice
        .call(
            server,
            Method::PUT,
            &format!("/api/v1/orgs/{org_id}/members/{}", bob.id()),
            Some(serde_json::to_value(&change).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (_, report) = bob.sync(server).await;
    let view = report
        .view
        .vaults
        .iter()
        .find(|v| v.vault_id == vault_id)
        .unwrap();
    assert_eq!(view.role.as_deref(), Some("view"), "the client caps it too");
    assert!(
        !report
            .view
            .warnings
            .iter()
            .any(|w| w.kind == "role_mismatch"),
        "{:?}",
        report.view.warnings
    );
    let (status, body) = bob
        .call(
            server,
            Method::PUT,
            &format!("/api/v1/items/{item_id}"),
            Some(json!({
                "vaultId": vault_id,
                "revision": 2,
                "encryptedData": bob.keyring.encrypt_item_at(&vault_id, 1, &item_id, 2, r#"{"title":"x"}"#).unwrap(),
                "keyEpoch": 1,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "guest_view_only");
    let (status, body) = bob
        .call(
            server,
            Method::DELETE,
            &format!("/api/v1/items/{item_id}?revision=2"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // --- Reports count members and guests separately ----------------------------------
    let (status, report) = alice
        .call(
            server,
            Method::GET,
            &format!("/api/v1/orgs/{org_id}/reports"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{report}");
    assert_eq!(report["memberCount"], 1, "only Alice is billable: {report}");
    assert_eq!(report["guestCount"], 2);
    assert_eq!(report["serviceAccountCount"], 0);

    // --- Agent reveals: refused for this organization without the rule ---------------
    let (status, body) = alice
        .call(
            server,
            Method::POST,
            "/api/v1/agent-events",
            Some(json!({
                "grantId": passbox_core::id::new_id().unwrap(),
                "tool": "reveal",
                "itemIds": [item_id],
                "target": "field:password",
                "result": "ok",
            })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "agent_reveal_not_allowed");
    // A blocked attempt is just logged.
    let (status, _) = alice
        .call(
            server,
            Method::POST,
            "/api/v1/agent-events",
            Some(json!({ "tool": "reveal", "itemIds": [item_id], "result": "blocked" })),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // --- Turning recovery off: after the policy no longer requires it ------------------
    put_policy(server, &mut alice, &org_id, &PolicyRules::default()).await;
    let (status, body) = alice.call(server, Method::DELETE, &recovery, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, state) = alice.call(server, Method::GET, &recovery, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(state["key"].is_null(), "{state}");
    let (status, _) = alice.call(server, Method::DELETE, &recovery, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "already off");
}
