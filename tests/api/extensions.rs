//! Extension points (`passbox_server::ext`): the organization gate, extra
//! routes and meta, read-only organizations, the `ext` database context
//! and the family member limit.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{Method, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use passbox_core::id;
use passbox_core::policy::PolicyRules;
use passbox_core::sharing::objects::OrgKind;
use passbox_server::api::auth::Session;
use passbox_server::error::ApiResult;
use passbox_server::ext::{self, Denial, Extensions, OrgEvent, OrgFacts, OrgFeature, OrgGate};
use passbox_server::state::AppState;
use passbox_server::testing::TestDatabase;
use serde_json::{Value, json};
use sqlx::PgConnection;

use super::{Member, TestServer, invite_and_confirm};

pub(super) async fn extensions(server: &TestServer, database: &TestDatabase) {
    allow_all_changes_nothing(server).await;
    gate_decides(server).await;
    read_only_organizations(server).await;
    extension_context(server, database).await;
    family_member_limit(server).await;
}

/// A gate that refuses on demand and records what it saw.
#[derive(Default)]
struct FakeGate {
    deny_add: AtomicBool,
    deny_use: AtomicBool,
    events: Mutex<Vec<OrgEvent>>,
}

#[async_trait::async_trait]
impl OrgGate for FakeGate {
    async fn may_add_member(
        &self,
        org: &OrgFacts,
        role: passbox_server::ext::OrgRole,
    ) -> Result<(), Denial> {
        if self.deny_add.load(Ordering::SeqCst) {
            return Err(Denial::new(
                "seat_limit",
                "no seat left",
                json!({ "seats": org.seats, "people": org.people, "role": role.as_str() }),
            ));
        }
        Ok(())
    }

    async fn may_use(&self, _org: &OrgFacts, feature: OrgFeature) -> Result<(), Denial> {
        if self.deny_use.load(Ordering::SeqCst) {
            return Err(Denial::new(
                "plan_required",
                "upgrade to use this",
                json!({ "feature": feature.as_str() }),
            ));
        }
        Ok(())
    }

    fn on_event(&self, event: OrgEvent) {
        self.events.lock().unwrap().push(event);
    }
}

impl FakeGate {
    fn take_events(&self) -> Vec<OrgEvent> {
        std::mem::take(&mut *self.events.lock().unwrap())
    }
}

/// An extension route: the signed-in account and its organizations.
async fn whoami(State(state): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    let mut tx = state.db.as_account(&session.account_id).await?;
    let orgs: i64 = sqlx::query_scalar("SELECT count(*) FROM org_members WHERE account_id = $1")
        .bind(&session.account_id)
        .fetch_one(&mut *tx)
        .await?;
    Ok(Json(
        json!({ "accountId": session.account_id, "orgs": orgs }),
    ))
}

async fn create_org(server: &TestServer, owner: &mut Member, kind: OrgKind) -> (String, String) {
    let vault = (kind == OrgKind::Family).then_some(r#"{"name":"Family"}"#);
    let org = owner
        .keyring
        .create_org(kind, r#"{"name":"Org"}"#, vault, 1)
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
    let vault_id = org.vault.map(|v| v.id).unwrap_or_default();
    (org.id, vault_id)
}

async fn invite(
    server: &TestServer,
    admin: &Member,
    org_id: &str,
    email: &str,
    role: &str,
) -> (StatusCode, Value) {
    admin
        .call(
            server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/invitations"),
            Some(json!({ "email": email, "role": role })),
        )
        .await
}

async fn accept(server: &TestServer, member: &Member, token: &str) -> (StatusCode, Value) {
    member
        .call(
            server,
            Method::POST,
            "/api/v1/invitations/accept",
            Some(json!({ "token": token })),
        )
        .await
}

async fn put_policy(server: &TestServer, admin: &mut Member, org_id: &str) -> (StatusCode, Value) {
    admin.sync(server).await;
    let upload = admin
        .keyring
        .sign_org_policy(org_id, &PolicyRules::new_org_defaults(), 10)
        .unwrap();
    admin
        .call(
            server,
            Method::PUT,
            &format!("/api/v1/orgs/{org_id}/policy"),
            Some(serde_json::to_value(&upload).unwrap()),
        )
        .await
}

async fn meta(server: &TestServer) -> Value {
    let (status, meta) = server
        .request(Method::GET, "/api/v1/meta", None, None)
        .await;
    assert_eq!(status, StatusCode::OK);
    meta
}

async fn allow_all_changes_nothing(server: &TestServer) {
    // The server of the other tests runs with the default extensions.
    let meta = meta(server).await;
    assert!(meta.get("familyMemberLimit").is_none(), "{meta}");
    assert!(meta.get("extensions").is_none(), "{meta}");
    let mut alice = Member::new(server, "10.90.0.1").await;
    let bob = Member::new(server, "10.90.0.2").await;
    let (org_id, _) = create_org(server, &mut alice, OrgKind::Family).await;
    let (status, body) = invite(server, &alice, &org_id, &bob.client.email, "member").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = accept(server, &bob, body["token"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = put_policy(server, &mut alice, &org_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, orgs) = alice.call(server, Method::GET, "/api/v1/orgs", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(orgs[0]["id"], org_id.as_str());
    assert_eq!(orgs[0]["lock"], Value::Null);
}

async fn gate_decides(base: &TestServer) {
    let gate = Arc::new(FakeGate::default());
    let ext = Extensions {
        gate: gate.clone(),
        routes: Some(Arc::new(|_: &AppState| {
            Router::new().route("/api/v1/ext/whoami", get(whoami))
        })),
        on_start: None,
        meta: Some(Arc::new(|| json!({ "plan": "test" }))),
    };
    let server =
        TestServer::with_extensions(base.pools().clone(), base.db().clone(), &ext, |state| {
            state.trust_proxy = true;
        })
        .await;

    // Meta and routes of the extension.
    let meta = meta(&server).await;
    assert_eq!(meta["extensions"], json!({ "plan": "test" }));
    let mut alice = Member::new(&server, "10.90.1.1").await;
    let bob = Member::new(&server, "10.90.1.2").await;
    let (status, me) = alice
        .call(&server, Method::GET, "/api/v1/ext/whoami", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{me}");
    assert_eq!(me["accountId"], alice.id());
    let (status, _) = server
        .request(Method::GET, "/api/v1/ext/whoami", None, None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Creating an organization is reported.
    let (org_id, _) = create_org(&server, &mut alice, OrgKind::Team).await;
    assert_eq!(
        gate.take_events(),
        vec![OrgEvent::Created {
            org_id: org_id.clone(),
            kind: OrgKind::Team,
            owner_id: alice.id().to_owned(),
        }]
    );

    // Adding members: the gate's refusal reaches the client.
    gate.deny_add.store(true, Ordering::SeqCst);
    let (status, body) = invite(&server, &alice, &org_id, &bob.client.email, "member").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "seat_limit");
    assert_eq!(body["message"], "no seat left");
    assert_eq!(
        body["details"],
        json!({ "seats": 1, "people": 1, "role": "member" })
    );
    gate.deny_add.store(false, Ordering::SeqCst);
    let (status, body) = invite(&server, &alice, &org_id, &bob.client.email, "member").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let token = body["token"].as_str().unwrap().to_owned();
    gate.deny_add.store(true, Ordering::SeqCst);
    let (status, body) = accept(&server, &bob, &token).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["details"]["people"], 2, "{body}");
    gate.deny_add.store(false, Ordering::SeqCst);
    let (status, body) = accept(&server, &bob, &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let members_changed = OrgEvent::MembersChanged {
        org_id: org_id.clone(),
    };
    assert_eq!(
        gate.take_events(),
        vec![members_changed.clone(), members_changed.clone()],
        "invited, joined"
    );

    // Features: changes are refused, reading stays allowed.
    gate.deny_use.store(true, Ordering::SeqCst);
    let (status, body) = put_policy(&server, &mut alice, &org_id).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "plan_required");
    assert_eq!(body["details"], json!({ "feature": "policies" }));
    for (method, uri, body, feature) in [
        (
            Method::POST,
            format!("/api/v1/orgs/{org_id}/event-tokens"),
            Some(json!({ "name": "Splunk" })),
            "events_api",
        ),
        (
            Method::POST,
            format!("/api/v1/orgs/{org_id}/scim/tokens"),
            Some(json!({ "name": "Okta" })),
            "scim",
        ),
        (
            Method::GET,
            format!("/api/v1/orgs/{org_id}/audit/export?format=json"),
            None,
            "audit_log",
        ),
        (
            Method::PUT,
            format!("/api/v1/orgs/{org_id}/settings"),
            Some(json!({ "auditRetentionDays": 0 })),
            "admin_console",
        ),
    ] {
        let (status, body) = alice.call(&server, method, &uri, body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}: {body}");
        assert_eq!(body["details"]["feature"], feature, "{uri}: {body}");
    }
    for uri in [
        format!("/api/v1/orgs/{org_id}/policy"),
        format!("/api/v1/orgs/{org_id}/audit"),
        format!("/api/v1/orgs/{org_id}/event-tokens"),
        format!("/api/v1/orgs/{org_id}/settings"),
        format!("/api/v1/orgs/{org_id}/scim"),
    ] {
        let (status, body) = alice.call(&server, Method::GET, &uri, None).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {body}");
    }
    gate.deny_use.store(false, Ordering::SeqCst);
    let (status, body) = put_policy(&server, &mut alice, &org_id).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // SCIM provisioning asks the gate too.
    let (status, created) = alice
        .call(
            &server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/scim/tokens"),
            Some(json!({ "name": "Okta", "expiresInDays": 30 })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let scim_token = created["token"].as_str().unwrap().to_owned();
    let user = |email: &str| {
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": email,
            "emails": [{ "value": email, "primary": true }],
            "active": true,
        })
    };
    gate.deny_add.store(true, Ordering::SeqCst);
    let (status, error) = super::sso::scim(
        &server,
        Method::POST,
        "/Users",
        &scim_token,
        Some(user("scim-denied@example.com")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{error}");
    assert_eq!(error["passboxError"], "seat_limit");
    gate.deny_add.store(false, Ordering::SeqCst);
    gate.take_events();
    let (status, created) = super::sso::scim(
        &server,
        Method::POST,
        "/Users",
        &scim_token,
        Some(user("scim-allowed@example.com")),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(gate.take_events(), vec![members_changed.clone()]);

    // Removing a member is reported; so is deleting the organization.
    let (status, body) = alice
        .call(
            &server,
            Method::DELETE,
            &format!("/api/v1/orgs/{org_id}/members/{}", bob.id()),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = alice
        .call(
            &server,
            Method::DELETE,
            &format!("/api/v1/orgs/{org_id}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        gate.take_events(),
        vec![members_changed, OrgEvent::Deleted { org_id }]
    );
}

async fn read_only_organizations(base: &TestServer) {
    let server = base.sibling().await;
    let db = server.pools().clone();
    let mut alice = Member::new(&server, "10.90.2.1").await;
    let mut bob = Member::new(&server, "10.90.2.2").await;
    let carol = Member::new(&server, "10.90.2.3").await;
    let (org_id, vault_id) = create_org(&server, &mut alice, OrgKind::Family).await;
    invite_and_confirm(&server, &mut alice, &mut bob, &org_id, "member").await;
    assert_eq!(
        alice
            .put_item(&server, &vault_id, 1, &id::new_id().unwrap(), 1)
            .await,
        StatusCode::OK
    );

    assert!(
        !ext::lock_org(&db, &id::new_id().unwrap(), "billing", "unpaid")
            .await
            .unwrap()
    );
    assert!(
        ext::lock_org(&db, &org_id, "billing", "unpaid")
            .await
            .unwrap()
    );
    let lock = json!({ "reason": "unpaid", "source": "billing" });
    assert_eq!(
        ext::org_lock(&db, &org_id).await.unwrap(),
        Some(ext::OrgLock {
            reason: "unpaid".into(),
            source: "billing".into()
        })
    );

    // Clients see the lock on the organization records.
    let (status, orgs) = alice.call(&server, Method::GET, "/api/v1/orgs", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(orgs[0]["lock"], lock);
    let (status, detail) = bob
        .call(
            &server,
            Method::GET,
            &format!("/api/v1/orgs/{org_id}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["lock"], lock);
    let (body, report) = bob.sync(&server).await;
    assert_eq!(body["sharing"]["orgs"][0]["lock"], lock);
    assert!(
        report.view.warnings.is_empty(),
        "{:?}",
        report.view.warnings
    );
    let (status, body) = bob
        .call(&server, Method::GET, "/api/v1/sync?since=0", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Writes are refused.
    let item_id = id::new_id().unwrap();
    assert_eq!(
        alice.put_item(&server, &vault_id, 1, &item_id, 1).await,
        StatusCode::FORBIDDEN
    );
    let (status, body) = invite(&server, &alice, &org_id, &carol.client.email, "member").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "org_read_only");
    assert_eq!(body["details"], lock);
    let (status, body) = put_policy(&server, &mut alice, &org_id).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "org_read_only");
    let (status, body) = alice
        .call(
            &server,
            Method::POST,
            &format!("/api/v1/orgs/{org_id}/event-tokens"),
            Some(json!({ "name": "Splunk" })),
        )
        .await;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::FORBIDDEN, json!("org_read_only"))
    );

    // Reading, suspending and removing members, deleting stay possible.
    let (status, _) = alice
        .call(
            &server,
            Method::GET,
            &format!("/api/v1/orgs/{org_id}/reports"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let member = format!("/api/v1/orgs/{org_id}/members/{}", bob.id());
    let (status, body) = alice
        .call(&server, Method::POST, &format!("{member}/suspend"), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, body) = alice
        .call(&server, Method::POST, &format!("{member}/reactivate"), None)
        .await;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::FORBIDDEN, json!("org_read_only"))
    );
    let (status, body) = alice.call(&server, Method::DELETE, &member, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Only the source that set the lock removes it.
    assert!(!ext::unlock_org(&db, &org_id, "support").await.unwrap());
    assert!(ext::unlock_org(&db, &org_id, "billing").await.unwrap());
    assert_eq!(ext::org_lock(&db, &org_id).await.unwrap(), None);
    alice.sync(&server).await;
    assert_eq!(
        alice.put_item(&server, &vault_id, 1, &item_id, 1).await,
        StatusCode::OK
    );
    let (_, orgs) = alice.call(&server, Method::GET, "/api/v1/orgs", None).await;
    assert_eq!(orgs[0]["lock"], Value::Null);

    // A locked organization can be deleted.
    assert!(ext::lock_org(&db, &org_id, "billing", "").await.unwrap());
    let (status, _) = alice
        .call(
            &server,
            Method::DELETE,
            &format!("/api/v1/orgs/{org_id}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(ext::org_lock(&db, &org_id).await.unwrap(), None);
}

async fn begin(conn: &mut PgConnection, account_id: &str, system: &str) {
    sqlx::query("BEGIN").execute(&mut *conn).await.unwrap();
    sqlx::query(
        "SELECT set_config('passbox.account_id', $1, true), set_config('passbox.context', '', true), \
         set_config('passbox.org_id', '', true), set_config('passbox.system', $2, true)",
    )
    .bind(account_id)
    .bind(system)
    .execute(&mut *conn)
    .await
    .unwrap();
}

async fn rollback(conn: &mut PgConnection) {
    sqlx::query("ROLLBACK").execute(&mut *conn).await.unwrap();
}

async fn count(conn: &mut PgConnection, sql: &str, id: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
}

/// Rows a statement changes, or `None` if the database refuses it.
async fn changes(conn: &mut PgConnection, sql: &str, id: &str) -> Option<u64> {
    sqlx::query("SAVEPOINT attempt")
        .execute(&mut *conn)
        .await
        .unwrap();
    let result = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .execute(&mut *conn)
        .await;
    match result {
        Ok(done) => Some(done.rows_affected()),
        Err(_) => {
            sqlx::query("ROLLBACK TO SAVEPOINT attempt")
                .execute(&mut *conn)
                .await
                .unwrap();
            None
        }
    }
}

async fn extension_context(base: &TestServer, database: &TestDatabase) {
    let server = base.sibling().await;
    let mut alice = Member::new(&server, "10.90.3.1").await;
    let mut bob = Member::new(&server, "10.90.3.2").await;
    let stranger = Member::new(&server, "10.90.3.3").await;
    let (org_id, vault_id) = create_org(&server, &mut alice, OrgKind::Family).await;
    invite_and_confirm(&server, &mut alice, &mut bob, &org_id, "member").await;
    let (status, _) = invite(&server, &alice, &org_id, "pending@example.com", "member").await;
    assert_eq!(status, StatusCode::CREATED);

    // The helpers for extensions.
    let db = server.pools();
    let facts = ext::org_facts(db, &org_id).await.unwrap().unwrap();
    assert_eq!(
        facts,
        OrgFacts {
            id: org_id.clone(),
            kind: OrgKind::Family,
            owner_id: alice.id().to_owned(),
            seats: 2,
            people: 3,
        }
    );
    assert!(
        ext::all_org_facts(db)
            .await
            .unwrap()
            .iter()
            .any(|f| f == &facts)
    );
    assert_eq!(
        ext::account_emails(db, &[alice.id().to_owned(), id::new_id().unwrap()])
            .await
            .unwrap(),
        vec![(alice.id().to_owned(), alice.client.email.clone())]
    );

    let mut app = database.connect_as("passbox_app").await;
    begin(&mut app, "", "ext").await;
    for sql in [
        "SELECT count(*) FROM organizations WHERE id = $1",
        "SELECT count(*) FROM org_members WHERE org_id = $1",
        "SELECT count(*) FROM org_invitations WHERE org_id = $1",
        "SELECT count(*) FROM passbox.org_facts($1, 0)",
    ] {
        assert!(count(&mut app, sql, &org_id).await > 0, "{sql}");
    }
    // Nothing else of the organization, and no account columns.
    for sql in [
        "SELECT count(*) FROM vaults WHERE org_id = $1",
        "SELECT count(*) FROM org_keys WHERE org_id = $1",
        "SELECT count(*) FROM org_policies WHERE org_id = $1",
        "SELECT count(*) FROM accounts WHERE id <> $1",
        "SELECT count(*) FROM account_directory WHERE id <> $1",
        "SELECT count(*) FROM sessions WHERE account_id <> $1",
    ] {
        assert_eq!(count(&mut app, sql, &org_id).await, 0, "{sql}");
    }
    assert_eq!(
        count(
            &mut app,
            "SELECT count(*) FROM items WHERE vault_id = $1",
            &vault_id
        )
        .await,
        0
    );
    // Writes outside org_locks change nothing or are refused.
    for sql in [
        "UPDATE organizations SET updated_at = 0 WHERE id = $1",
        "DELETE FROM organizations WHERE id = $1",
        "UPDATE org_members SET role = 'admin' WHERE org_id = $1",
        "DELETE FROM org_members WHERE org_id = $1",
        "UPDATE org_invitations SET status = 'revoked' WHERE org_id = $1",
        "DELETE FROM org_invitations WHERE org_id = $1",
        "DELETE FROM vaults WHERE org_id = $1",
        "UPDATE accounts SET disabled_at = 1 WHERE id <> $1",
    ] {
        let changed = changes(&mut app, sql, &org_id).await;
        assert!(
            changed.is_none() || changed == Some(0),
            "{sql}: {changed:?}"
        );
    }
    let join = format!(
        "INSERT INTO org_members (org_id, account_id, role, status, invited_by, seq, created_at, updated_at) \
         VALUES ($1, '{}', 'member', 'confirmed', 'x', 0, 0, 0)",
        stranger.id()
    );
    for sql in [
        join.as_str(),
        "INSERT INTO org_invitations (id, org_id, email, role, token_hash, status, created_by, created_at, expires_at) \
         VALUES ($1, $1, 'x@example.com', 'member', repeat('a', 64), 'pending', 'x', 0, 0)",
        "INSERT INTO org_settings (org_id, audit_retention_days, updated_by, updated_at) VALUES ($1, 0, $1, 0)",
    ] {
        assert_eq!(changes(&mut app, sql, &org_id).await, None, "{sql}");
    }
    // org_locks: read, insert, delete.
    assert_eq!(
        changes(
            &mut app,
            "INSERT INTO org_locks (org_id, reason, source, locked_at) VALUES ($1, 'r', 's', 0)",
            &org_id,
        )
        .await,
        Some(1)
    );
    assert_eq!(
        count(
            &mut app,
            "SELECT count(*) FROM org_locks WHERE org_id = $1",
            &org_id
        )
        .await,
        1
    );
    assert_eq!(
        changes(&mut app, "DELETE FROM org_locks WHERE org_id = $1", &org_id).await,
        Some(1)
    );
    rollback(&mut app).await;

    // Members read the lock but cannot set it; strangers see nothing.
    assert!(
        ext::lock_org(db, &org_id, "billing", "unpaid")
            .await
            .unwrap()
    );
    begin(&mut app, bob.id(), "").await;
    assert_eq!(
        count(
            &mut app,
            "SELECT count(*) FROM org_locks WHERE org_id = $1",
            &org_id
        )
        .await,
        1
    );
    assert_eq!(
        changes(&mut app, "DELETE FROM org_locks WHERE org_id = $1", &org_id).await,
        Some(0)
    );
    rollback(&mut app).await;
    begin(&mut app, stranger.id(), "").await;
    for sql in [
        "SELECT count(*) FROM org_locks WHERE org_id = $1",
        "SELECT count(*) FROM passbox.org_facts($1, 0)",
    ] {
        assert_eq!(count(&mut app, sql, &org_id).await, 0, "{sql}");
    }
    assert_eq!(
        changes(
            &mut app,
            "INSERT INTO org_locks (org_id, reason, source, locked_at) VALUES ($1, 'r', 's', 1)",
            &org_id,
        )
        .await,
        None
    );
    rollback(&mut app).await;
    // Other system contexts do not reach org_locks or the account emails.
    begin(&mut app, "", "worker:mail").await;
    assert_eq!(
        count(
            &mut app,
            "SELECT count(*) FROM org_locks WHERE org_id = $1",
            &org_id
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &mut app,
            "SELECT count(*) FROM passbox.ext_accounts(ARRAY[$1])",
            alice.id()
        )
        .await,
        0
    );
    rollback(&mut app).await;
    assert!(ext::unlock_org(db, &org_id, "billing").await.unwrap());
}

async fn family_member_limit(base: &TestServer) {
    let default = Extensions::default();
    let with_limit = |limit: u32| {
        TestServer::with_extensions(
            base.pools().clone(),
            base.db().clone(),
            &default,
            move |state| {
                state.trust_proxy = true;
                state.family_member_limit = limit;
            },
        )
    };
    let two = with_limit(2).await;
    let three = with_limit(3).await;
    assert_eq!(meta(&two).await["familyMemberLimit"], 2);

    let mut alice = Member::new(&two, "10.90.4.1").await;
    let bob = Member::new(&two, "10.90.4.2").await;
    let carol = Member::new(&two, "10.90.4.3").await;
    let gina = Member::new(&two, "10.90.4.4").await;
    let (org_id, _) = create_org(&two, &mut alice, OrgKind::Family).await;

    // The owner and one invitation fill a family of two; guests do not count.
    let (status, body) = invite(&two, &alice, &org_id, &bob.client.email, "member").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let bob_token = body["token"].as_str().unwrap().to_owned();
    let (status, body) = invite(&two, &alice, &org_id, &carol.client.email, "admin").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "family_limit_reached");
    assert_eq!(body["details"], json!({ "limit": 2 }));
    let (status, body) = invite(&two, &alice, &org_id, &gina.client.email, "guest").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let gina_token = body["token"].as_str().unwrap().to_owned();

    // Accepting checks the limit as well (here: lowered after inviting).
    let (status, body) = invite(&three, &alice, &org_id, &carol.client.email, "member").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let carol_invitation = body["id"].as_str().unwrap().to_owned();
    let carol_token = body["token"].as_str().unwrap().to_owned();
    let (status, body) = accept(&two, &carol, &carol_token).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "family_limit_reached");
    let (status, _) = alice
        .call(
            &two,
            Method::DELETE,
            &format!("/api/v1/orgs/{org_id}/invitations/{carol_invitation}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = accept(&two, &bob, &bob_token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = accept(&two, &gina, &gina_token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Full: owner and bob; gina is a guest.
    let (status, body) = invite(&two, &alice, &org_id, &carol.client.email, "member").await;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::FORBIDDEN, json!("family_limit_reached"))
    );

    // Teams have no such limit.
    let mut tom = Member::new(&two, "10.90.4.5").await;
    let (team_id, _) = create_org(&two, &mut tom, OrgKind::Team).await;
    for member in [&bob, &carol, &gina] {
        let (status, body) = invite(&two, &tom, &team_id, &member.client.email, "member").await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
}
