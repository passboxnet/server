//! Row level security: the database itself keeps tenants apart, also for
//! raw SQL that forgets a tenant filter. These tests connect as the
//! production roles (`passbox_app`, `passbox_worker`) and set the contexts
//! the server sets (docs/architecture/database-security.md).

use axum::http::{Method, StatusCode};
use passbox_core::id;
use passbox_server::testing::TestDatabase;
use serde_json::json;
use sqlx::{Connection, PgConnection};

use super::{Client, TestServer};

/// Tables without row level security (no tenant data). Every other table
/// must have it enabled and forced.
const WITHOUT_RLS: &[&str] = &["counters", "_sqlx_migrations"];

/// What one account owns, created through the API and (for rows the API
/// would need real cryptography for) directly as the owner.
struct Tenant {
    account_id: String,
    vault_id: String,
    item_id: String,
    org_id: String,
    org_vault_id: String,
    org_item_id: String,
    attachment_id: String,
    share_link_id: String,
    token: String,
}

async fn tenant(server: &TestServer) -> Tenant {
    let client = Client::new();
    let (keyring, vault_id) = client.register(server).await;
    let token = client.login(server).await;
    let item_id = id::new_id().unwrap();
    let (status, body) = server
        .request(
            Method::PUT,
            &format!("/api/v1/items/{item_id}"),
            Some(&token),
            Some(json!({
                "vaultId": vault_id,
                "revision": 1,
                "encryptedData": keyring.encrypt_item(&vault_id, &item_id, 1, "{}").unwrap(),
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // An organization with a shared vault, an item, an attachment and a
    // share link, inserted as the owner (bypassing the policies).
    let org_id = id::new_id().unwrap();
    let org_vault_id = id::new_id().unwrap();
    let org_item_id = id::new_id().unwrap();
    let attachment_id = id::new_id().unwrap();
    let share_link_id = id::new_id().unwrap();
    let a = &client.account_id;
    let blob = vec![1u8, 2, 3];
    let mut conn = server.db().acquire().await.unwrap();
    let statements: Vec<(&str, Vec<String>)> = vec![
        (
            "INSERT INTO organizations (id, kind, owner_id, genesis, genesis_signature, encrypted_meta, \
             meta_epoch, revision, seq, created_at, updated_at) \
             VALUES ($1, 'team', $2, '', '', '\\x01', 1, 1, 0, 0, 0)",
            vec![org_id.clone(), a.clone()],
        ),
        (
            "INSERT INTO org_members (org_id, account_id, role, status, invited_by, seq, created_at, updated_at) \
             VALUES ($1, $2, 'owner', 'confirmed', '', 0, 0, 0)",
            vec![org_id.clone(), a.clone()],
        ),
        (
            "INSERT INTO vaults (id, account_id, encrypted_key, encrypted_meta, revision, seq, created_at, \
             updated_at, org_id, key_epoch) VALUES ($1, $2, '\\x', '\\x01', 1, 0, 0, 0, $3, 1)",
            vec![org_vault_id.clone(), a.clone(), org_id.clone()],
        ),
        (
            "INSERT INTO items (id, vault_id, encrypted_data, revision, deleted, seq, created_at, updated_at, \
             key_epoch) VALUES ($1, $2, '\\x01', 1, false, 0, 0, 0, 1)",
            vec![org_item_id.clone(), org_vault_id.clone()],
        ),
        (
            "INSERT INTO attachments (id, item_id, vault_id, uploaded_by, owner_type, owner_id, size, created_at) \
             VALUES ($1, $2, $3, $4, 'org', $5, 10, 0)",
            vec![
                attachment_id.clone(),
                org_item_id.clone(),
                org_vault_id.clone(),
                a.clone(),
                org_id.clone(),
            ],
        ),
    ];
    for (sql, binds) in statements {
        let mut query = sqlx::query(sqlx::AssertSqlSafe(sql));
        for bind in binds {
            query = query.bind(bind);
        }
        query.execute(&mut *conn).await.unwrap();
    }
    sqlx::query(
        "INSERT INTO share_links (id, account_id, encrypted_label, blob, auth_hash, expires_at, max_views, \
         views, failed_attempts, created_at, last_viewed_at) VALUES ($1, $2, $3, $3, 'x', $4, 0, 0, 0, 0, 0)",
    )
    .bind(&share_link_id)
    .bind(a)
    .bind(&blob)
    .bind(passbox_server::db::now_ms() + 3_600_000)
    .execute(&mut *conn)
    .await
    .unwrap();
    Tenant {
        account_id: client.account_id.clone(),
        vault_id,
        item_id,
        org_id,
        org_vault_id,
        org_item_id,
        attachment_id,
        share_link_id,
        token,
    }
}

/// Starts a transaction with the settings the server uses.
async fn begin(
    conn: &mut PgConnection,
    account_id: &str,
    context: &str,
    org_id: &str,
    system: &str,
) {
    sqlx::query("BEGIN").execute(&mut *conn).await.unwrap();
    sqlx::query(
        "SELECT set_config('passbox.account_id', $1, true), set_config('passbox.context', $2, true), \
         set_config('passbox.org_id', $3, true), set_config('passbox.system', $4, true)",
    )
    .bind(account_id)
    .bind(context)
    .bind(org_id)
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

async fn affected(conn: &mut PgConnection, sql: &str, id: &str) -> u64 {
    sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .execute(&mut *conn)
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
        .rows_affected()
}

/// The ways to address another tenant's rows.
fn reads(b: &Tenant) -> Vec<(&'static str, String)> {
    vec![
        (
            "SELECT count(*) FROM accounts WHERE id = $1",
            b.account_id.clone(),
        ),
        (
            "SELECT count(*) FROM sessions WHERE account_id = $1",
            b.account_id.clone(),
        ),
        (
            "SELECT count(*) FROM device_tokens WHERE account_id = $1",
            b.account_id.clone(),
        ),
        (
            "SELECT count(*) FROM account_events WHERE account_id = $1",
            b.account_id.clone(),
        ),
        (
            "SELECT count(*) FROM vaults WHERE id = $1",
            b.vault_id.clone(),
        ),
        (
            "SELECT count(*) FROM vaults WHERE id = $1",
            b.org_vault_id.clone(),
        ),
        (
            "SELECT count(*) FROM items WHERE id = $1",
            b.item_id.clone(),
        ),
        (
            "SELECT count(*) FROM items WHERE id = $1",
            b.org_item_id.clone(),
        ),
        (
            "SELECT count(*) FROM organizations WHERE id = $1",
            b.org_id.clone(),
        ),
        (
            "SELECT count(*) FROM org_members WHERE org_id = $1",
            b.org_id.clone(),
        ),
        (
            "SELECT count(*) FROM attachments WHERE id = $1",
            b.attachment_id.clone(),
        ),
        (
            "SELECT count(*) FROM share_links WHERE id = $1",
            b.share_link_id.clone(),
        ),
        (
            "SELECT count(*) FROM account_directory WHERE id = $1",
            b.account_id.clone(),
        ),
    ]
}

fn writes(b: &Tenant) -> Vec<(&'static str, String)> {
    vec![
        (
            "UPDATE accounts SET locale = 'de' WHERE id = $1",
            b.account_id.clone(),
        ),
        (
            "DELETE FROM sessions WHERE account_id = $1",
            b.account_id.clone(),
        ),
        (
            "UPDATE vaults SET revision = revision + 1 WHERE id = $1",
            b.vault_id.clone(),
        ),
        ("DELETE FROM vaults WHERE id = $1", b.org_vault_id.clone()),
        (
            "UPDATE items SET revision = revision + 1 WHERE id = $1",
            b.item_id.clone(),
        ),
        ("DELETE FROM items WHERE id = $1", b.org_item_id.clone()),
        (
            "UPDATE organizations SET revision = revision + 1 WHERE id = $1",
            b.org_id.clone(),
        ),
        (
            "DELETE FROM org_members WHERE org_id = $1",
            b.org_id.clone(),
        ),
        (
            "DELETE FROM attachments WHERE id = $1",
            b.attachment_id.clone(),
        ),
        (
            "DELETE FROM share_links WHERE id = $1",
            b.share_link_id.clone(),
        ),
    ]
}

pub async fn policies(server: &TestServer, database: &TestDatabase) {
    every_table_has_forced_rls(server).await;
    let a = tenant(server).await;
    let b = tenant(server).await;
    let mut app = database.connect_as("passbox_app").await;

    // The owner's view: the rows exist (the directory view filters by
    // context even for the owner).
    for (sql, id) in reads(&b)
        .into_iter()
        .filter(|(sql, _)| !sql.contains("account_directory"))
    {
        let mut owner = server.db().acquire().await.unwrap();
        assert!(count(&mut owner, sql, &id).await > 0, "{sql} as owner");
    }

    // Without any context nothing is visible, in any table.
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relkind IN ('r', 'v') ORDER BY 1",
    )
    .fetch_all(server.db())
    .await
    .unwrap();
    for table in &tables {
        if WITHOUT_RLS.contains(&table.as_str()) {
            continue;
        }
        begin(&mut app, "", "", "", "").await;
        let rows: i64 =
            sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
                .fetch_one(&mut app)
                .await
                .unwrap();
        rollback(&mut app).await;
        assert_eq!(rows, 0, "{table} shows rows without a context");
    }

    // Account A cannot read, change or delete B's rows, even with raw SQL.
    for (sql, id) in reads(&b) {
        begin(&mut app, &a.account_id, "", "", "").await;
        assert_eq!(
            count(&mut app, sql, &id).await,
            0,
            "{sql} as another account"
        );
        rollback(&mut app).await;
    }
    for (sql, id) in writes(&b) {
        begin(&mut app, &a.account_id, "", "", "").await;
        assert_eq!(
            affected(&mut app, sql, &id).await,
            0,
            "{sql} as another account"
        );
        rollback(&mut app).await;
    }
    // ...nor write into B's vaults or B's name.
    for (vault, item) in [
        (&b.vault_id, id::new_id().unwrap()),
        (&b.org_vault_id, id::new_id().unwrap()),
    ] {
        begin(&mut app, &a.account_id, "", "", "").await;
        let inserted = sqlx::query(
            "INSERT INTO items (id, vault_id, encrypted_data, revision, deleted, seq, created_at, \
             updated_at) VALUES ($1, $2, '\\x01', 1, false, 0, 0, 0)",
        )
        .bind(&item)
        .bind(vault)
        .execute(&mut app)
        .await;
        rollback(&mut app).await;
        assert_policy_violation(inserted, "an item in another account's vault");
    }
    begin(&mut app, &a.account_id, "", "", "").await;
    let inserted = sqlx::query(
        "INSERT INTO org_members (org_id, account_id, role, status, invited_by, seq, created_at, updated_at) \
         VALUES ($1, $2, 'admin', 'confirmed', '', 0, 0, 0)",
    )
    .bind(&b.org_id)
    .bind(&a.account_id)
    .execute(&mut app)
    .await;
    rollback(&mut app).await;
    assert_policy_violation(inserted, "joining another organization uninvited");

    // The own rows are there (the policies are not simply closed).
    for (sql, id) in reads(&a) {
        begin(&mut app, &a.account_id, "", "", "").await;
        assert!(
            count(&mut app, sql, &id).await > 0,
            "{sql} for the own account"
        );
        rollback(&mut app).await;
    }

    // Nobody can make an account instance admin with a query.
    begin(&mut app, &a.account_id, "", "", "").await;
    let escalated = sqlx::query("UPDATE accounts SET instance_admin = true WHERE id = $1")
        .bind(&a.account_id)
        .execute(&mut app)
        .await;
    rollback(&mut app).await;
    let error = escalated.expect_err("instance_admin must not be writable");
    assert!(error.to_string().contains("permission denied"), "{error}");

    // The sign-in context finds accounts by email, but no vault data.
    begin(&mut app, "", "auth", "", "").await;
    assert_eq!(
        count(
            &mut app,
            "SELECT count(*) FROM accounts WHERE id = $1",
            &b.account_id
        )
        .await,
        1
    );
    for (sql, id) in reads(&b)
        .into_iter()
        .filter(|(sql, _)| !sql.contains("FROM accounts") && !sql.contains("device_tokens"))
    {
        assert_eq!(
            count(&mut app, sql, &id).await,
            0,
            "{sql} in the sign-in context"
        );
    }
    rollback(&mut app).await;

    // A machine context (SCIM) sees its organization's roster, never vaults.
    begin(&mut app, "", "scim", &b.org_id, "").await;
    assert_eq!(
        count(
            &mut app,
            "SELECT count(*) FROM org_members WHERE org_id = $1",
            &b.org_id
        )
        .await,
        1
    );
    assert_eq!(
        count(
            &mut app,
            "SELECT count(*) FROM vaults WHERE id = $1",
            &b.org_vault_id
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &mut app,
            "SELECT count(*) FROM org_members WHERE org_id = $1",
            &a.org_id
        )
        .await,
        0
    );
    rollback(&mut app).await;

    // Workers: only their tables, and only in their own job's context.
    let mut worker = database.connect_as("passbox_worker").await;
    begin(&mut worker, "", "", "", "worker:mail").await;
    let denied = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM items")
        .fetch_one(&mut worker)
        .await;
    rollback(&mut worker).await;
    let error = denied.expect_err("the worker role has no access to items");
    assert!(error.to_string().contains("permission denied"), "{error}");
    begin(&mut worker, "", "", "", "worker:mail").await;
    let mail: i64 = sqlx::query_scalar("SELECT count(*) FROM mail_outbox")
        .fetch_one(&mut worker)
        .await
        .unwrap();
    rollback(&mut worker).await;
    assert!(mail > 0, "the mail worker sees the outbox");
    begin(&mut worker, "", "", "", "worker:breach").await;
    let other_job: i64 = sqlx::query_scalar("SELECT count(*) FROM mail_outbox")
        .fetch_one(&mut worker)
        .await
        .unwrap();
    rollback(&mut worker).await;
    assert_eq!(other_job, 0, "another job does not see the outbox");

    // The share-link viewer reads links through functions only.
    begin(&mut app, "", "share_link", "", "").await;
    assert_eq!(
        count(
            &mut app,
            "SELECT count(*) FROM share_links WHERE id = $1",
            &b.share_link_id
        )
        .await,
        0
    );
    let info: i64 = sqlx::query_scalar("SELECT count(*) FROM passbox.share_link_info($1, 0)")
        .bind(&b.share_link_id)
        .fetch_one(&mut app)
        .await
        .unwrap();
    assert_eq!(info, 1);
    rollback(&mut app).await;
    app.close().await.unwrap();
    worker.close().await.unwrap();

    // And through the API: A's token gets 404 for B's things.
    let (status, _) = server
        .request(
            Method::GET,
            &format!("/api/v1/items/{}/versions", b.item_id),
            Some(&a.token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = server
        .request(
            Method::DELETE,
            &format!("/api/v1/share-links/{}", b.share_link_id),
            Some(&a.token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

fn assert_policy_violation(result: Result<sqlx::postgres::PgQueryResult, sqlx::Error>, what: &str) {
    match result {
        Err(sqlx::Error::Database(error)) => assert!(
            error.message().contains("row-level security")
                || error.code().as_deref() == Some("42501"),
            "{what}: {error}"
        ),
        other => panic!("{what} was not refused: {other:?}"),
    }
}

/// Every table but the allowlist has row level security enabled and forced.
async fn every_table_has_forced_rls(server: &TestServer) {
    let rows: Vec<(String, bool, bool)> = sqlx::query_as(
        "SELECT c.relname::text, c.relrowsecurity, c.relforcerowsecurity FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind = 'r' \
         ORDER BY 1",
    )
    .fetch_all(server.db())
    .await
    .unwrap();
    assert!(rows.len() > 50, "{rows:?}");
    for (table, enabled, forced) in rows {
        if WITHOUT_RLS.contains(&table.as_str()) {
            continue;
        }
        assert!(
            enabled && forced,
            "{table}: row level security enabled {enabled}, forced {forced}"
        );
    }
}
