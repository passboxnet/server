//! Moving items between vaults (B5), attachments (G2), share links (B7)
//! and access requests (B9).

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use passbox_core::policy::{PolicyRules, ShareLinkRule};
use passbox_core::sharing::objects::{OrgKind, PrincipalType, VaultRole};
use passbox_core::{file_crypto, id, share_link};
use passbox_server::api::attachments::AttachmentLimits;
use passbox_server::state::AppState;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::{Member, TestServer, invite_and_confirm};

async fn personal_vault(server: &TestServer, member: &Member) -> String {
    let (status, body) = member.call(server, Method::GET, "/api/v1/sync", None).await;
    assert_eq!(status, StatusCode::OK);
    body["vaults"][0]["id"].as_str().unwrap().to_owned()
}

async fn cursor(server: &TestServer, member: &Member) -> i64 {
    let (_, body) = member
        .call(server, Method::GET, "/api/v1/sync?sharing=1", None)
        .await;
    body["cursor"].as_i64().unwrap()
}

async fn put(
    server: &TestServer,
    member: &Member,
    vault_id: &str,
    epoch: u32,
    item_id: &str,
    revision: u64,
    json: &str,
) {
    let encrypted = member
        .keyring
        .encrypt_item_at(vault_id, epoch, item_id, revision, json)
        .unwrap();
    let (status, body) = member
        .call(
            server,
            Method::PUT,
            &format!("/api/v1/items/{item_id}"),
            Some(json!({ "vaultId": vault_id, "revision": revision, "encryptedData": encrypted, "keyEpoch": epoch })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// The body of a move request, re-encrypted like the clients do.
async fn move_body(
    server: &TestServer,
    member: &Member,
    item_id: &str,
    from: (&str, u32),
    to: (&str, u32),
    revision: u64,
    data: &str,
) -> Value {
    let (_, history) = member
        .call(
            server,
            Method::GET,
            &format!("/api/v1/items/{item_id}/versions"),
            None,
        )
        .await;
    let mut versions = Vec::new();
    for v in history["versions"].as_array().unwrap() {
        let rev = v["revision"].as_u64().unwrap();
        let plain = member
            .keyring
            .decrypt_item_at(
                from.0,
                from.1,
                item_id,
                rev,
                v["encryptedData"].as_str().unwrap(),
            )
            .unwrap();
        versions.push(json!({
            "revision": rev,
            "encryptedData": member.keyring.encrypt_item_at(to.0, to.1, item_id, rev, &plain).unwrap(),
        }));
    }
    // The version being replaced belongs to the history too.
    versions.push(json!({
        "revision": revision - 1,
        "encryptedData": member.keyring.encrypt_item_at(to.0, to.1, item_id, revision - 1, data).unwrap(),
    }));
    json!({
        "targetVaultId": to.0,
        "keyEpoch": to.1,
        "items": [{
            "id": item_id,
            "revision": revision,
            "encryptedData": member.keyring.encrypt_item_at(to.0, to.1, item_id, revision, data).unwrap(),
            "versions": versions,
        }],
    })
}

async fn raw(
    app: &axum::Router,
    method: Method,
    uri: &str,
    token: &str,
    body: Vec<u8>,
) -> (StatusCode, Vec<u8>) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/octet-stream")
        .body(Body::from(body))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, bytes.to_vec())
}

pub async fn comfort(server: &TestServer) {
    let mut alice = Member::new(server, "10.9.6.1").await;
    let mut bob = Member::new(server, "10.9.6.2").await;
    let mut carol = Member::new(server, "10.9.6.3").await;
    let mallory = Member::new(server, "10.9.6.4").await;

    // A team with a shared vault; Bob may only view it, Carol is a member
    // of the team without access to the vault.
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
    invite_and_confirm(server, &mut alice, &mut carol, &org_id, "member").await;
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
            VaultRole::View,
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

    moves(server, &mut alice, &mut bob, &vault_id, &org_id).await;
    attachments(server, &alice, &bob, &mallory, &vault_id).await;
    share_links(server, &mut alice, &mallory, &vault_id, &org_id).await;
    access_requests(server, &mut alice, &mut carol, &mallory, &vault_id).await;
}

async fn moves(
    server: &TestServer,
    alice: &mut Member,
    bob: &mut Member,
    vault_id: &str,
    org_id: &str,
) {
    let personal = personal_vault(server, alice).await;
    let item_id = id::new_id().unwrap();
    put(
        server,
        alice,
        &personal,
        0,
        &item_id,
        1,
        r#"{"title":"v1"}"#,
    )
    .await;
    put(
        server,
        alice,
        &personal,
        0,
        &item_id,
        2,
        r#"{"title":"v2"}"#,
    )
    .await;
    let (_, first) = alice
        .call(server, Method::GET, "/api/v1/sync?sharing=1", None)
        .await;
    let created_at = first["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == item_id.as_str())
        .unwrap()["createdAt"]
        .as_i64()
        .unwrap();
    let alice_cursor = cursor(server, alice).await;
    let bob_cursor = cursor(server, bob).await;

    // A stale revision is a conflict that names the item.
    let mut body = move_body(
        server,
        alice,
        &item_id,
        (&personal, 0),
        (vault_id, 1),
        3,
        r#"{"title":"v2"}"#,
    )
    .await;
    body["items"][0]["revision"] = json!(2);
    body["items"][0]["versions"] = json!([]);
    let (status, conflict) = alice
        .call(
            server,
            Method::POST,
            "/api/v1/items/move",
            Some(body.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
    assert_eq!(conflict["details"]["itemId"], item_id.as_str());
    assert_eq!(conflict["details"]["currentRevision"], 2);
    // The wrong key epoch for the target is refused too.
    body = move_body(
        server,
        alice,
        &item_id,
        (&personal, 0),
        (vault_id, 1),
        3,
        r#"{"title":"v2"}"#,
    )
    .await;
    let mut wrong_epoch = body.clone();
    wrong_epoch["keyEpoch"] = json!(7);
    let (status, _) = alice
        .call(
            server,
            Method::POST,
            "/api/v1/items/move",
            Some(wrong_epoch),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    // Strangers cannot move it, Bob (view only) cannot move into the vault.
    let (status, _) = bob
        .call(
            server,
            Method::POST,
            "/api/v1/items/move",
            Some(body.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "view-only target");

    let (status, moved) = alice
        .call(
            server,
            Method::POST,
            "/api/v1/items/move",
            Some(body.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{moved}");
    assert_eq!(moved["moved"][0]["revision"], 3);
    let (status, _) = alice
        .call(server, Method::POST, "/api/v1/items/move", Some(body))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "already there");

    // The history moved along, re-encrypted for the shared vault.
    let (_, history) = bob
        .call(
            server,
            Method::GET,
            &format!("/api/v1/items/{item_id}/versions"),
            None,
        )
        .await;
    let versions = history["versions"].as_array().unwrap();
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0]["revision"], 2, "newest first");
    for v in versions {
        let rev = v["revision"].as_u64().unwrap();
        let plain = bob
            .keyring
            .decrypt_item_at(
                vault_id,
                1,
                &item_id,
                rev,
                v["encryptedData"].as_str().unwrap(),
            )
            .unwrap();
        assert_eq!(plain, format!(r#"{{"title":"v{rev}"}}"#));
    }

    // Alice's other devices get a tombstone for the personal vault first,
    // then the item in the shared vault; Bob gets the item.
    let (_, delta) = alice
        .call(
            server,
            Method::GET,
            &format!("/api/v1/sync?since={alice_cursor}&sharing=1"),
            None,
        )
        .await;
    let items = delta["items"].as_array().unwrap();
    let tomb = items
        .iter()
        .position(|i| i["id"] == item_id.as_str() && i["deleted"] == true)
        .unwrap();
    let new = items
        .iter()
        .position(|i| i["id"] == item_id.as_str() && i["deleted"] == false)
        .unwrap();
    assert!(tomb < new, "{delta}");
    assert_eq!(items[tomb]["vaultId"], personal.as_str());
    assert_eq!(items[new]["vaultId"], vault_id);
    assert_eq!(items[new]["createdAt"], created_at);
    // Without sharing (older apps) only the tombstone arrives.
    let (_, old) = alice
        .call(
            server,
            Method::GET,
            &format!("/api/v1/sync?since={alice_cursor}"),
            None,
        )
        .await;
    assert!(
        old["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|i| i["deleted"] == true)
    );
    let (_, delta) = bob
        .call(
            server,
            Method::GET,
            &format!("/api/v1/sync?since={bob_cursor}&sharing=1"),
            None,
        )
        .await;
    let bobs: Vec<&Value> = delta["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["id"] == item_id.as_str())
        .collect();
    assert_eq!(bobs.len(), 1);
    assert_eq!(bobs[0]["deleted"], false);

    // Bob (view only) cannot move it out; the policy can keep items inside.
    let back = move_body(
        server,
        alice,
        &item_id,
        (vault_id, 1),
        (&personal, 0),
        4,
        r#"{"title":"v2"}"#,
    )
    .await;
    let (status, _) = bob
        .call(
            server,
            Method::POST,
            "/api/v1/items/move",
            Some(back.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "not Bob's personal vault");
    alice.sync(server).await;
    let rules = PolicyRules {
        forbid_external_sharing: true,
        ..PolicyRules::default()
    };
    let upload = alice.keyring.sign_org_policy(org_id, &rules, 10).unwrap();
    let (status, body) = alice
        .call(
            server,
            Method::PUT,
            &format!("/api/v1/orgs/{org_id}/policy"),
            Some(serde_json::to_value(&upload).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = alice
        .call(
            server,
            Method::POST,
            "/api/v1/items/move",
            Some(back.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "policy_violation");
    alice.sync(server).await;
    let upload = alice
        .keyring
        .sign_org_policy(org_id, &PolicyRules::default(), 11)
        .unwrap();
    let (status, _) = alice
        .call(
            server,
            Method::PUT,
            &format!("/api/v1/orgs/{org_id}/policy"),
            Some(serde_json::to_value(&upload).unwrap()),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = alice
        .call(server, Method::POST, "/api/v1/items/move", Some(back))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, delta) = bob
        .call(
            server,
            Method::GET,
            &format!("/api/v1/sync?since={bob_cursor}&sharing=1"),
            None,
        )
        .await;
    let last = delta["items"]
        .as_array()
        .unwrap()
        .iter()
        .rfind(|i| i["id"] == item_id.as_str())
        .unwrap()
        .clone();
    assert_eq!(last["deleted"], true, "Bob lost the item: {delta}");
}

async fn attachments(
    server: &TestServer,
    alice: &Member,
    bob: &Member,
    mallory: &Member,
    vault_id: &str,
) {
    let item_id = id::new_id().unwrap();
    put(
        server,
        alice,
        vault_id,
        1,
        &item_id,
        1,
        r#"{"title":"Doc"}"#,
    )
    .await;
    let file_id = id::new_id().unwrap();
    let key = file_crypto::parse_key(&file_crypto::generate_key().unwrap()).unwrap();
    let blob = file_crypto::encrypt_file(&key, &file_id, b"hello attachment").unwrap();
    let uri = format!("/api/v1/attachments/{file_id}?itemId={item_id}");

    // Only writers of the item's vault can upload; garbage is refused.
    let (status, _) = raw(&server.app, Method::PUT, &uri, &bob.token, blob.clone()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = raw(&server.app, Method::PUT, &uri, &mallory.token, blob.clone()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = raw(
        &server.app,
        Method::PUT,
        &format!(
            "/api/v1/attachments/{}?itemId={item_id}",
            id::new_id().unwrap()
        ),
        &alice.token,
        vec![1, 2],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = raw(&server.app, Method::PUT, &uri, &alice.token, blob.clone()).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let (status, _) = raw(&server.app, Method::PUT, &uri, &alice.token, blob.clone()).await;
    assert_eq!(status, StatusCode::CONFLICT, "no replacing");

    // Readers download it (Bob can view the vault); strangers cannot.
    let download = format!("/api/v1/attachments/{file_id}");
    let (status, bytes) = raw(&server.app, Method::GET, &download, &bob.token, Vec::new()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        file_crypto::decrypt_file(&key, &file_id, &bytes).unwrap(),
        b"hello attachment"
    );
    let (status, _) = raw(
        &server.app,
        Method::GET,
        &download,
        &mallory.token,
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, usage) = alice
        .call(server, Method::GET, "/api/v1/attachments/usage", None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(usage["usage"][0]["owner"], "account");
    assert!(
        usage["usage"]
            .as_array()
            .unwrap()
            .iter()
            .any(|u| u["used"] == blob.len() as u64)
    );
    let (status, _) = raw(
        &server.app,
        Method::DELETE,
        &download,
        &bob.token,
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Deleting the item permanently removes the attachment.
    let (status, _) = alice
        .call(
            server,
            Method::DELETE,
            &format!("/api/v1/items/{item_id}?revision=2"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = raw(
        &server.app,
        Method::GET,
        &download,
        &alice.token,
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Size limit and quota, on a server with small limits.
    let mut state = AppState::load(server.db().clone()).await.unwrap();
    state.attachment_limits = AttachmentLimits {
        max_file: 200,
        account_quota: 300,
        org_quota: 300,
    };
    let small =
        passbox_server::routes::router(&passbox_server::config::Config::default(), state.clone());
    let personal = personal_vault(server, alice).await;
    let item = id::new_id().unwrap();
    put(server, alice, &personal, 0, &item, 1, r#"{"title":"Big"}"#).await;
    let upload = |len: usize| {
        let id = id::new_id().unwrap();
        (
            format!("/api/v1/attachments/{id}?itemId={item}"),
            vec![7u8; len],
        )
    };
    let (uri, body) = upload(250);
    let (status, resp) = raw(&small, Method::PUT, &uri, &alice.token, body).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(String::from_utf8_lossy(&resp).contains("file_too_large"));
    let (uri, body) = upload(180);
    assert_eq!(
        raw(&small, Method::PUT, &uri, &alice.token, body).await.0,
        StatusCode::CREATED
    );
    let (uri, body) = upload(180);
    let (status, resp) = raw(&small, Method::PUT, &uri, &alice.token, body).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(String::from_utf8_lossy(&resp).contains("quota_exceeded"));
    // Unreferenced blobs are swept (none here: the one stored is in use).
    assert_eq!(
        passbox_server::api::attachments::sweep(&state)
            .await
            .unwrap(),
        0
    );
}

async fn share_links(
    server: &TestServer,
    alice: &mut Member,
    mallory: &Member,
    vault_id: &str,
    org_id: &str,
) {
    let now = passbox_server::db::now_ms();
    let create = |link_id: &str, passphrase: Option<&str>, max_views: i64, vault: Option<&str>| {
        let link = share_link::create(link_id, r#"{"title":"Wi-Fi"}"#, passphrase).unwrap();
        let body = json!({
            "id": link_id,
            "encryptedLabel": "bGFiZWw",
            "blob": link.blob,
            "authHash": link.auth_hash,
            "salt": link.salt,
            "expiresAt": now + 60_000,
            "maxViews": max_views,
            "vaultId": vault,
        });
        (link, body)
    };
    let link_id = id::new_id().unwrap();
    let (link, body) = create(&link_id, Some("open sesame"), 2, None);
    let (status, created) = alice
        .call(server, Method::POST, "/api/v1/share-links", Some(body))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["hasPassphrase"], true);

    // Anyone can see that it needs a passphrase; opening needs the token.
    let (status, info) = server
        .request(
            Method::GET,
            &format!("/api/v1/public/share-links/{link_id}"),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(info["salt"], link.salt.clone().unwrap().as_str());
    assert_eq!(info["viewsLeft"], 2);
    let salt = link.salt.as_deref();
    let wrong = share_link::auth_token(&link_id, &link.key, Some("guess"), salt).unwrap();
    let open = format!("/api/v1/public/share-links/{link_id}/open");
    let (status, body) = server.post(&open, None, json!({ "auth": wrong })).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "wrong_passphrase");
    let right = share_link::auth_token(&link_id, &link.key, Some("open sesame"), salt).unwrap();
    let (status, body) = server.post(&open, None, json!({ "auth": right })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["viewsLeft"], 1);
    assert_eq!(
        share_link::open(
            &link_id,
            &link.key,
            Some("open sesame"),
            salt,
            body["blob"].as_str().unwrap()
        )
        .unwrap(),
        r#"{"title":"Wi-Fi"}"#
    );
    let (_, list) = alice
        .call(server, Method::GET, "/api/v1/share-links", None)
        .await;
    assert_eq!(list["links"][0]["views"], 1);
    // The last view deletes the link.
    let (status, _) = server.post(&open, None, json!({ "auth": right })).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = server.post(&open, None, json!({ "auth": right })).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Too many wrong passphrases delete a link; creators delete their own.
    let link_id = id::new_id().unwrap();
    let (link, body) = create(&link_id, None, 0, None);
    assert_eq!(
        alice
            .call(server, Method::POST, "/api/v1/share-links", Some(body))
            .await
            .0,
        StatusCode::CREATED
    );
    let open = format!("/api/v1/public/share-links/{link_id}/open");
    let bad = share_link::auth_token(
        &link_id,
        &passbox_core::encoding::encode(&[9u8; 32]),
        None,
        None,
    )
    .unwrap();
    for _ in 0..10 {
        assert_eq!(
            server.post(&open, None, json!({ "auth": bad })).await.0,
            StatusCode::FORBIDDEN
        );
    }
    let good = share_link::auth_token(&link_id, &link.key, None, None).unwrap();
    assert_eq!(
        server.post(&open, None, json!({ "auth": good })).await.0,
        StatusCode::NOT_FOUND
    );
    let link_id = id::new_id().unwrap();
    let (_, body) = create(&link_id, None, 0, None);
    assert_eq!(
        alice
            .call(server, Method::POST, "/api/v1/share-links", Some(body))
            .await
            .0,
        StatusCode::CREATED
    );
    assert_eq!(
        mallory
            .call(
                server,
                Method::DELETE,
                &format!("/api/v1/share-links/{link_id}"),
                None
            )
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        alice
            .call(
                server,
                Method::DELETE,
                &format!("/api/v1/share-links/{link_id}"),
                None
            )
            .await
            .0,
        StatusCode::NO_CONTENT
    );

    // Policies: links for the organization's items can be restricted.
    alice.sync(server).await;
    let rules = PolicyRules {
        share_links: ShareLinkRule::Restricted,
        share_link_max_days: 1,
        share_link_max_views: 3,
        ..PolicyRules::default()
    };
    let upload = alice.keyring.sign_org_policy(org_id, &rules, 20).unwrap();
    assert_eq!(
        alice
            .call(
                server,
                Method::PUT,
                &format!("/api/v1/orgs/{org_id}/policy"),
                Some(serde_json::to_value(&upload).unwrap())
            )
            .await
            .0,
        StatusCode::OK
    );
    let (_, body) = create(&id::new_id().unwrap(), None, 0, Some(vault_id));
    let (status, err) = alice
        .call(server, Method::POST, "/api/v1/share-links", Some(body))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(err["error"], "policy_violation");
    let (_, body) = create(&id::new_id().unwrap(), None, 3, Some(vault_id));
    assert_eq!(
        alice
            .call(server, Method::POST, "/api/v1/share-links", Some(body))
            .await
            .0,
        StatusCode::CREATED
    );
    let (_, body) = create(&id::new_id().unwrap(), None, 0, Some(vault_id));
    assert_eq!(
        mallory
            .call(server, Method::POST, "/api/v1/share-links", Some(body))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    alice.sync(server).await;
    let upload = alice
        .keyring
        .sign_org_policy(org_id, &PolicyRules::default(), 21)
        .unwrap();
    assert_eq!(
        alice
            .call(
                server,
                Method::PUT,
                &format!("/api/v1/orgs/{org_id}/policy"),
                Some(serde_json::to_value(&upload).unwrap())
            )
            .await
            .0,
        StatusCode::OK
    );
}

async fn access_requests(
    server: &TestServer,
    alice: &mut Member,
    carol: &mut Member,
    mallory: &Member,
    vault_id: &str,
) {
    let uri = format!("/api/v1/vaults/{vault_id}/access-requests");
    // Outsiders cannot even tell that the vault exists.
    let (status, _) = mallory
        .call(server, Method::POST, &uri, Some(json!({ "role": "view" })))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, state) = carol
        .call(
            server,
            Method::GET,
            &format!("/api/v1/vaults/{vault_id}/access-request"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(state["hasAccess"], false);
    assert!(state["request"].is_null());

    let (status, request) = carol
        .call(server, Method::POST, &uri, Some(json!({ "role": "edit" })))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{request}");
    let request_id = request["id"].as_str().unwrap().to_owned();
    let (status, _) = carol
        .call(server, Method::POST, &uri, Some(json!({ "role": "edit" })))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "one pending request");
    let (_, lists) = alice
        .call(server, Method::GET, "/api/v1/access-requests", None)
        .await;
    assert_eq!(lists["incoming"][0]["id"], request_id.as_str());
    assert_eq!(lists["incoming"][0]["email"], carol.client.email.as_str());
    let (_, lists) = mallory
        .call(server, Method::GET, "/api/v1/access-requests", None)
        .await;
    assert!(lists["incoming"].as_array().unwrap().is_empty());
    // Carol cannot decide her own request; approving needs the share first.
    let approve = format!("/api/v1/access-requests/{request_id}/approve");
    assert_eq!(
        carol.call(server, Method::POST, &approve, None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        alice.call(server, Method::POST, &approve, None).await.0,
        StatusCode::CONFLICT
    );
    alice.sync(server).await;
    let change = alice
        .keyring
        .share_vault(
            vault_id,
            PrincipalType::Account,
            carol.id(),
            VaultRole::Edit,
            30,
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
    assert_eq!(
        alice.call(server, Method::POST, &approve, None).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        alice.call(server, Method::POST, &approve, None).await.0,
        StatusCode::CONFLICT
    );
    let (_, lists) = carol
        .call(server, Method::GET, "/api/v1/access-requests", None)
        .await;
    assert_eq!(lists["outgoing"][0]["status"], "approved");
    // Already has it; asking for more is possible and can be denied.
    let (status, _) = carol
        .call(server, Method::POST, &uri, Some(json!({ "role": "view" })))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, request) = carol
        .call(
            server,
            Method::POST,
            &uri,
            Some(json!({ "role": "manage" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = request["id"].as_str().unwrap();
    assert_eq!(
        alice
            .call(
                server,
                Method::POST,
                &format!("/api/v1/access-requests/{id}/deny"),
                None
            )
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    let (_, state) = carol
        .call(
            server,
            Method::GET,
            &format!("/api/v1/vaults/{vault_id}/access-request"),
            None,
        )
        .await;
    assert_eq!(state["hasAccess"], true);
    assert_eq!(state["request"]["status"], "denied");
    // A pending request can be withdrawn.
    let (_, request) = carol
        .call(
            server,
            Method::POST,
            &uri,
            Some(json!({ "role": "manage" })),
        )
        .await;
    let id = request["id"].as_str().unwrap();
    assert_eq!(
        carol
            .call(
                server,
                Method::DELETE,
                &format!("/api/v1/access-requests/{id}"),
                None
            )
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        carol
            .call(
                server,
                Method::DELETE,
                &format!("/api/v1/access-requests/{id}"),
                None
            )
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}
