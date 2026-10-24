//! The audit log of an organization (wave D3).
//!
//! The server appends what it sees (sign-ins of members, membership,
//! groups, vault access, writes to shared vaults, recovery, policies,
//! settings); members' apps add what only they see (viewing, revealing,
//! copying and filling items), signed with the account key and only when
//! the organization's signed policy turns `report_item_usage` on.
//!
//! Entries are hash-chained per organization with
//! [`passbox_core::audit::AuditRecord::compute_hash`], so an export can be
//! checked by anyone. Retention deletes old entries and remembers the hash
//! the first remaining entry links to.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use passbox_core::audit::{self, AuditRecord, ChainCheck, MAX_CLIENT_EVENTS, SignedClientEvent};
use passbox_core::{encoding, id};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::AnyConnection;

use super::access;
use super::auth::Session;
use super::validate;
use crate::db::now_ms;
use crate::error::{ApiError, ApiResult};
use crate::security::ClientIp;
use crate::state::AppState;

/// Who caused an entry.
#[derive(Debug, Clone, Default)]
pub struct Actor {
    pub account_id: String,
    pub device_name: String,
    pub client_kind: String,
    pub ip: String,
}

impl Actor {
    pub fn of(session: &Session, ip: &str) -> Self {
        Self {
            account_id: session.account_id.clone(),
            device_name: session.device_name.clone(),
            client_kind: session.client_kind.clone(),
            ip: ip.to_owned(),
        }
    }

    pub fn account(account_id: &str, device_name: &str, client_kind: &str, ip: &str) -> Self {
        Self {
            account_id: account_id.to_owned(),
            device_name: device_name.to_owned(),
            client_kind: client_kind.to_owned(),
            ip: ip.to_owned(),
        }
    }
}

/// What an entry is about.
pub struct Target<'a> {
    pub kind: &'a str,
    pub id: &'a str,
}

impl<'a> Target<'a> {
    pub fn account(id: &'a str) -> Self {
        Self {
            kind: "account",
            id,
        }
    }
    pub fn vault(id: &'a str) -> Self {
        Self { kind: "vault", id }
    }
    pub fn group(id: &'a str) -> Self {
        Self { kind: "group", id }
    }
    pub fn org(id: &'a str) -> Self {
        Self { kind: "org", id }
    }
    pub fn item(id: &'a str) -> Self {
        Self { kind: "item", id }
    }
    pub fn none() -> Self {
        Self { kind: "", id: "" }
    }
}

struct Append<'a> {
    action: &'a str,
    target: Target<'a>,
    details: &'a Value,
    client_event: &'a str,
    client_signature: &'a str,
    client_nonce: Option<&'a str>,
}

async fn append(
    conn: &mut AnyConnection,
    org_id: &str,
    actor: &Actor,
    entry: Append<'_>,
) -> ApiResult<u64> {
    let actor_email: String = sqlx::query_scalar("SELECT email FROM accounts WHERE id = $1")
        .bind(&actor.account_id)
        .fetch_optional(&mut *conn)
        .await?
        .unwrap_or_default();
    sqlx::query(
        "INSERT INTO org_audit_heads (org_id, seq, hash, pruned_seq, pruned_hash) \
         VALUES ($1, 0, '', 0, '') ON CONFLICT (org_id) DO NOTHING",
    )
    .bind(org_id)
    .execute(&mut *conn)
    .await?;
    // The row lock orders concurrent writers of the same organization.
    let (seq, prev_hash): (i64, String) = sqlx::query_as(
        "UPDATE org_audit_heads SET seq = seq + 1 WHERE org_id = $1 RETURNING seq, hash",
    )
    .bind(org_id)
    .fetch_one(&mut *conn)
    .await?;
    let mut record = AuditRecord {
        org_id: org_id.to_owned(),
        seq: u64::try_from(seq).map_err(|_| ApiError::Internal(anyhow::anyhow!("bad seq")))?,
        id: id::new_id().map_err(|e| ApiError::Internal(e.into()))?,
        created_at: now_ms(),
        actor_id: actor.account_id.clone(),
        actor_email,
        device_name: actor.device_name.clone(),
        client_kind: actor.client_kind.clone(),
        ip: actor.ip.clone(),
        action: entry.action.to_owned(),
        target_type: entry.target.kind.to_owned(),
        target_id: entry.target.id.to_owned(),
        details: entry.details.to_string(),
        client_event: entry.client_event.to_owned(),
        client_signature: entry.client_signature.to_owned(),
        prev_hash,
        hash: String::new(),
    };
    record.hash = record.compute_hash();
    sqlx::query(
        "INSERT INTO org_audit_events (org_id, seq, id, created_at, actor_id, actor_email, device_name, \
         client_kind, ip, action, target_type, target_id, details, client_event, client_signature, \
         client_nonce, prev_hash, hash) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)",
    )
    .bind(&record.org_id)
    .bind(seq)
    .bind(&record.id)
    .bind(record.created_at)
    .bind(&record.actor_id)
    .bind(&record.actor_email)
    .bind(&record.device_name)
    .bind(&record.client_kind)
    .bind(&record.ip)
    .bind(&record.action)
    .bind(&record.target_type)
    .bind(&record.target_id)
    .bind(&record.details)
    .bind(&record.client_event)
    .bind(&record.client_signature)
    .bind(entry.client_nonce)
    .bind(&record.prev_hash)
    .bind(&record.hash)
    .execute(&mut *conn)
    .await?;
    sqlx::query("UPDATE org_audit_heads SET hash = $1 WHERE org_id = $2")
        .bind(&record.hash)
        .bind(org_id)
        .execute(&mut *conn)
        .await?;
    Ok(record.seq)
}

/// Appends a server-side entry inside the caller's transaction, so the
/// entry exists exactly when the change does.
pub async fn record_in(
    conn: &mut AnyConnection,
    org_id: &str,
    actor: &Actor,
    action: &str,
    target: Target<'_>,
    details: Value,
) -> ApiResult<()> {
    append(
        conn,
        org_id,
        actor,
        Append {
            action,
            target,
            details: &details,
            client_event: "",
            client_signature: "",
            client_nonce: None,
        },
    )
    .await?;
    Ok(())
}

/// Appends an entry in its own transaction (after the change committed).
/// A failure is logged and never fails the request.
pub async fn record(
    state: &AppState,
    org_id: &str,
    actor: &Actor,
    action: &str,
    target: Target<'_>,
    details: Value,
) {
    let result = async {
        let mut tx = crate::db::begin_write(&state.db).await?;
        record_in(&mut tx, org_id, actor, action, target, details).await?;
        tx.commit().await?;
        Ok::<_, ApiError>(())
    }
    .await;
    if let Err(err) = result {
        tracing::warn!(error = ?err, org_id, action, "could not write the organization audit log");
    }
}

/// Account events that organizations the account belongs to also log, with
/// their audit action.
fn mirrored_action(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "login" | "login_two_factor" | "login_recovered" => "member_signed_in",
        "login_failed" => "member_sign_in_failed",
        "two_factor_failed" => "member_two_factor_failed",
        "password_changed" => "member_password_changed",
        "two_factor_method_added" => "member_two_factor_added",
        "two_factor_method_removed" => "member_two_factor_removed",
        "two_factor_disabled" => "member_two_factor_disabled",
        "recovery_codes_regenerated" => "member_recovery_codes_regenerated",
        "recovery_code_used" => "member_recovery_code_used",
        "account_recovery_code_created" => "member_account_recovery_code_created",
        "account_recovery_code_removed" => "member_account_recovery_code_removed",
        "device_link_approved" => "member_device_added",
        "other_sessions_revoked" => "member_sessions_revoked",
        "emergency_access_used" => "member_emergency_access_used",
        _ => return None,
    })
}

/// Logs an account's security event (sign-ins, password and two-factor
/// changes) in every organization it is an active member of. Called from
/// `auth::record_event`; never fails the caller.
pub async fn mirror_account_event(
    state: &AppState,
    account_id: &str,
    kind: &str,
    device_name: &str,
    client_kind: &str,
    ip: &str,
) {
    let Some(action) = mirrored_action(kind) else {
        return;
    };
    let orgs: Vec<String> = match sqlx::query_scalar(
        "SELECT org_id FROM org_members WHERE account_id = $1 AND status IN ('confirmed', 'suspended')",
    )
    .bind(account_id)
    .fetch_all(&state.db)
    .await
    {
        Ok(orgs) => orgs,
        Err(err) => {
            tracing::warn!(error = ?err, "could not look up organizations for the audit log");
            return;
        }
    };
    let actor = Actor::account(account_id, device_name, client_kind, ip);
    for org_id in orgs {
        record(
            state,
            &org_id,
            &actor,
            action,
            Target::account(account_id),
            json!({}),
        )
        .await;
    }
}

// --- Reading ---------------------------------------------------------------------------

const COLUMNS: &str = "org_id, seq, id, created_at, actor_id, actor_email, device_name, client_kind, ip, \
     action, target_type, target_id, details, client_event, client_signature, prev_hash, hash";

#[derive(sqlx::FromRow)]
struct Row {
    org_id: String,
    seq: i64,
    id: String,
    created_at: i64,
    actor_id: String,
    actor_email: String,
    device_name: String,
    client_kind: String,
    ip: String,
    action: String,
    target_type: String,
    target_id: String,
    details: String,
    client_event: String,
    client_signature: String,
    prev_hash: String,
    hash: String,
}

fn from_row(row: Row) -> AuditRecord {
    AuditRecord {
        org_id: row.org_id,
        seq: u64::try_from(row.seq).unwrap_or_default(),
        id: row.id,
        created_at: row.created_at,
        actor_id: row.actor_id,
        actor_email: row.actor_email,
        device_name: row.device_name,
        client_kind: row.client_kind,
        ip: row.ip,
        action: row.action,
        target_type: row.target_type,
        target_id: row.target_id,
        details: row.details,
        client_event: row.client_event,
        client_signature: row.client_signature,
        prev_hash: row.prev_hash,
        hash: row.hash,
    }
}

/// Filters for listing and exporting.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AuditQuery {
    /// Entries with a lower sequence number (paging backwards).
    pub before: Option<i64>,
    /// Entries with a higher sequence number (paging forwards, events API).
    pub after: Option<i64>,
    pub limit: Option<i64>,
    /// Exact action, a prefix ending in `*` (`member_*`), or a
    /// comma-separated list of exact actions.
    pub action: Option<String>,
    /// Actor account ID.
    pub actor: Option<String>,
    /// Target ID (account, vault, group or item).
    pub target: Option<String>,
    /// Time range (Unix ms, inclusive).
    pub from: Option<i64>,
    pub to: Option<i64>,
    /// `client` or `server`.
    pub source: Option<String>,
    /// `csv` or `json` (export only).
    pub format: Option<String>,
}

fn like_prefix(value: &str) -> String {
    let mut out = String::new();
    for c in value.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    out
}

/// Runs a filtered query. Ascending order when paging forwards (`after`),
/// newest first otherwise.
pub async fn query(
    conn: &mut AnyConnection,
    org_id: &str,
    q: &AuditQuery,
    max: i64,
) -> ApiResult<Vec<AuditRecord>> {
    let mut sql = format!("SELECT {COLUMNS} FROM org_audit_events WHERE org_id = $1");
    let mut binds: Vec<Value> = vec![json!(org_id)];
    fn push(sql: &mut String, binds: &mut Vec<Value>, clause: &str, value: Value) {
        binds.push(value);
        sql.push_str(&format!(" AND {clause} ${}", binds.len()));
    }
    if let Some(before) = q.before {
        push(&mut sql, &mut binds, "seq <", json!(before));
    }
    if let Some(after) = q.after {
        push(&mut sql, &mut binds, "seq >", json!(after));
    }
    if let Some(action) = q.action.as_deref().filter(|a| !a.is_empty()) {
        if action.len() > 2048 {
            return Err(ApiError::bad_request("action is too long"));
        }
        let list: Vec<&str> = action.split(',').filter(|a| !a.is_empty()).collect();
        if list.len() > 1 {
            if list.len() > 50 || list.iter().any(|a| a.len() > 64 || a.contains('*')) {
                return Err(ApiError::bad_request("list at most 50 exact actions"));
            }
            let mut placeholders = Vec::with_capacity(list.len());
            for item in list {
                binds.push(json!(item));
                placeholders.push(format!("${}", binds.len()));
            }
            sql.push_str(&format!(" AND action IN ({})", placeholders.join(", ")));
        } else {
            match action.strip_suffix('*') {
                Some(prefix) => {
                    binds.push(json!(like_prefix(prefix)));
                    sql.push_str(&format!(" AND action LIKE ${} ESCAPE '\\'", binds.len()));
                }
                None => push(&mut sql, &mut binds, "action =", json!(action)),
            }
        }
    }
    if let Some(actor) = q.actor.as_deref().filter(|a| !a.is_empty()) {
        validate::id("actor", actor)?;
        push(&mut sql, &mut binds, "actor_id =", json!(actor));
    }
    if let Some(target) = q.target.as_deref().filter(|a| !a.is_empty()) {
        validate::id("target", target)?;
        push(&mut sql, &mut binds, "target_id =", json!(target));
    }
    if let Some(from) = q.from {
        push(&mut sql, &mut binds, "created_at >=", json!(from));
    }
    if let Some(to) = q.to {
        push(&mut sql, &mut binds, "created_at <=", json!(to));
    }
    match q.source.as_deref() {
        Some("client") => sql.push_str(" AND client_event <> ''"),
        Some("server") => sql.push_str(" AND client_event = ''"),
        Some("") | None => {}
        Some(_) => return Err(ApiError::bad_request("source must be client or server")),
    }
    let ascending = q.after.is_some();
    let limit = q.limit.unwrap_or(100).clamp(1, max);
    sql.push_str(if ascending {
        " ORDER BY seq ASC"
    } else {
        " ORDER BY seq DESC"
    });
    binds.push(json!(limit));
    sql.push_str(&format!(" LIMIT ${}", binds.len()));
    // Only fixed clauses and placeholders are added; values are bound.
    let mut query = sqlx::query_as::<_, Row>(sqlx::AssertSqlSafe(sql));
    for value in &binds {
        query = match value {
            Value::String(s) => query.bind(s.clone()),
            Value::Number(n) => query.bind(n.as_i64().unwrap_or_default()),
            _ => query,
        };
    }
    Ok(query
        .fetch_all(&mut *conn)
        .await?
        .into_iter()
        .map(from_row)
        .collect())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditHead {
    pub seq: u64,
    pub hash: String,
    /// Entries up to here were deleted by retention.
    pub pruned_seq: u64,
    /// The hash the first remaining entry links to.
    pub pruned_hash: String,
}

pub async fn head(conn: &mut AnyConnection, org_id: &str) -> ApiResult<AuditHead> {
    let row: Option<(i64, String, i64, String)> = sqlx::query_as(
        "SELECT seq, hash, pruned_seq, pruned_hash FROM org_audit_heads WHERE org_id = $1",
    )
    .bind(org_id)
    .fetch_optional(&mut *conn)
    .await?;
    let (seq, hash, pruned_seq, pruned_hash) = row.unwrap_or((0, String::new(), 0, String::new()));
    Ok(AuditHead {
        seq: u64::try_from(seq).unwrap_or_default(),
        hash,
        pruned_seq: u64::try_from(pruned_seq).unwrap_or_default(),
        pruned_hash,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditPage {
    events: Vec<AuditRecord>,
    head: AuditHead,
}

/// `GET /orgs/{id}/audit`: a page of entries, newest first (admins).
pub async fn list(
    State(state): State<AppState>,
    session: Session,
    Path(org_id): Path<String>,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<AuditPage>> {
    validate::id("organization id", &org_id)?;
    let mut conn = state.db.acquire().await?;
    access::require_admin(&mut conn, &org_id, &session.account_id).await?;
    let events = query(&mut conn, &org_id, &q, 500).await?;
    let head = head(&mut conn, &org_id).await?;
    Ok(Json(AuditPage { events, head }))
}

/// Checks the whole remaining chain of an organization.
pub async fn verify_org_chain(conn: &mut AnyConnection, org_id: &str) -> ApiResult<ChainCheck> {
    let head = head(&mut *conn, org_id).await?;
    let rows: Vec<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM org_audit_events WHERE org_id = $1 ORDER BY seq"
    )))
    .bind(org_id)
    .fetch_all(&mut *conn)
    .await?;
    let records: Vec<AuditRecord> = rows.into_iter().map(from_row).collect();
    let mut check = audit::verify_chain(&records, Some(&head.pruned_hash));
    if check.valid {
        let expected_first = head.pruned_seq + 1;
        if records.first().is_some_and(|r| r.seq != expected_first) {
            check.valid = false;
            check.broken_at = Some(expected_first);
            check.problem = Some("entries are missing at the start".into());
        } else if records.last().map_or(head.pruned_seq, |r| r.seq) != head.seq {
            check.valid = false;
            check.broken_at = Some(records.last().map_or(head.pruned_seq, |r| r.seq) + 1);
            check.problem = Some("entries are missing at the end".into());
        }
    }
    Ok(check)
}

/// `GET /orgs/{id}/audit/verify`: checks the hash chain (admins).
pub async fn verify(
    State(state): State<AppState>,
    session: Session,
    Path(org_id): Path<String>,
) -> ApiResult<Json<ChainCheck>> {
    validate::id("organization id", &org_id)?;
    let mut conn = state.db.acquire().await?;
    access::require_admin(&mut conn, &org_id, &session.account_id).await?;
    Ok(Json(verify_org_chain(&mut conn, &org_id).await?))
}

fn csv_field(value: &str) -> String {
    // Quote everything; neutralize spreadsheet formulas (CSV injection).
    let value = if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    format!("\"{}\"", value.replace('"', "\"\""))
}

/// The CSV columns of an export, in order.
pub const CSV_HEADER: &str = "seq,id,created_at,actor_id,actor_email,device_name,client_kind,ip,action,target_type,target_id,details,client_event,client_signature,prev_hash,hash";

pub fn to_csv(records: &[AuditRecord]) -> String {
    let mut out = String::from(CSV_HEADER);
    out.push('\n');
    for r in records {
        let fields = [
            r.seq.to_string(),
            r.id.clone(),
            r.created_at.to_string(),
            r.actor_id.clone(),
            r.actor_email.clone(),
            r.device_name.clone(),
            r.client_kind.clone(),
            r.ip.clone(),
            r.action.clone(),
            r.target_type.clone(),
            r.target_id.clone(),
            r.details.clone(),
            r.client_event.clone(),
            r.client_signature.clone(),
            r.prev_hash.clone(),
            r.hash.clone(),
        ];
        let line: Vec<String> = fields.iter().map(|f| csv_field(f)).collect();
        out.push_str(&line.join(","));
        out.push('\n');
    }
    out
}

/// `GET /orgs/{id}/audit/export?format=csv|json&…`: up to 100,000 entries
/// matching the filters, oldest first (admins). The export itself is
/// logged.
pub async fn export(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(org_id): Path<String>,
    Query(mut q): Query<AuditQuery>,
) -> ApiResult<Response> {
    validate::id("organization id", &org_id)?;
    let format = q.format.clone().unwrap_or_else(|| "json".into());
    if format != "json" && format != "csv" {
        return Err(ApiError::bad_request("format must be csv or json"));
    }
    let mut conn = state.db.acquire().await?;
    access::require_admin(&mut conn, &org_id, &session.account_id).await?;
    q.limit = Some(100_000);
    if q.after.is_none() {
        q.after = Some(0);
    }
    let records = query(&mut conn, &org_id, &q, 100_000).await?;
    let head = head(&mut conn, &org_id).await?;
    drop(conn);
    record(
        &state,
        &org_id,
        &Actor::of(&session, &ip),
        "audit_exported",
        Target::org(&org_id),
        json!({ "format": format, "count": records.len() }),
    )
    .await;
    let filename = format!("passbox-audit-{org_id}.{format}");
    let disposition = format!("attachment; filename=\"{filename}\"");
    if format == "csv" {
        return Ok((
            [
                (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_owned()),
                (header::CONTENT_DISPOSITION, disposition),
            ],
            to_csv(&records),
        )
            .into_response());
    }
    Ok((
        [(header::CONTENT_DISPOSITION, disposition)],
        Json(json!({
            "format": "passbox-audit-log",
            "version": 1,
            "orgId": org_id,
            "exportedAt": now_ms(),
            "head": head,
            "events": records,
        })),
    )
        .into_response())
}

// --- Client events ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ClientEventsRequest {
    events: Vec<SignedClientEvent>,
}

#[derive(Serialize)]
pub struct ClientEventsResponse {
    accepted: usize,
    duplicates: usize,
}

/// Client events may be this old (a device that was offline).
const CLIENT_EVENT_MAX_AGE_MS: i64 = 7 * 24 * 60 * 60 * 1000;
const CLIENT_EVENT_MAX_SKEW_MS: i64 = 10 * 60 * 1000;

/// `POST /orgs/{id}/audit/client-events`: events a member's app signed
/// about items of the organization's vaults it can open. Only accepted
/// while the organization's policy turns `report_item_usage` on.
pub async fn client_events(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(org_id): Path<String>,
    Json(req): Json<ClientEventsRequest>,
) -> ApiResult<Json<ClientEventsResponse>> {
    validate::id("organization id", &org_id)?;
    if req.events.len() > MAX_CLIENT_EVENTS {
        return Err(ApiError::bad_request("too many events at once"));
    }
    if let Some(wait) = state.limiter.hit(
        &format!("client-events:{}", session.account_id),
        120,
        std::time::Duration::from_secs(60),
    ) {
        return Err(ApiError::RateLimited(wait));
    }
    let mut tx = crate::db::begin_write(&state.db).await?;
    access::require_confirmed(&mut tx, &org_id, &session.account_id).await?;
    let rules = super::org_policy::current_rules(&mut tx, &org_id).await?;
    if !rules.is_some_and(|r| r.report_item_usage) {
        return Err(ApiError::forbidden(
            "forbidden",
            "the organization's policy does not ask for item usage",
        ));
    }
    let bundle = super::signed::own_bundle(&mut tx, &session.account_id).await?;
    let actor = Actor::of(&session, &ip);
    let now = now_ms();
    let mut accepted = 0;
    let mut duplicates = 0;
    for signed in &req.events {
        validate::base64("event", &signed.event, 2048)?;
        validate::base64("signature", &signed.signature, 128)?;
        let event = audit::verify_client_event(&bundle, signed)
            .map_err(|e| ApiError::bad_request(format!("invalid event: {e}")))?;
        if event.org_id != org_id {
            return Err(ApiError::bad_request(
                "the event belongs to another organization",
            ));
        }
        if event.occurred_at > now + CLIENT_EVENT_MAX_SKEW_MS
            || event.occurred_at < now - CLIENT_EVENT_MAX_AGE_MS
        {
            return Err(ApiError::bad_request("the event time is out of range"));
        }
        validate::id("vaultId", &event.vault_id)?;
        validate::id("itemId", &event.item_id)?;
        match access::vault_access(&mut tx, &event.vault_id, &session.account_id).await? {
            Some(access::VaultAccess::Shared { org_id: o, .. }) if o == org_id => {}
            _ => {
                return Err(ApiError::bad_request(
                    "the event names a vault you cannot open",
                ));
            }
        }
        let nonce = encoding::encode(&event.nonce);
        let seen: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM org_audit_events WHERE org_id = $1 AND client_nonce = $2",
        )
        .bind(&org_id)
        .bind(&nonce)
        .fetch_optional(&mut *tx)
        .await?;
        if seen.is_some() {
            duplicates += 1;
            continue;
        }
        append(
            &mut tx,
            &org_id,
            &actor,
            Append {
                action: event.action.as_str(),
                target: Target::item(&event.item_id),
                details: &json!({
                    "vaultId": event.vault_id,
                    "field": event.field,
                    "occurredAt": event.occurred_at,
                }),
                client_event: &signed.event,
                client_signature: &signed.signature,
                client_nonce: Some(&nonce),
            },
        )
        .await?;
        accepted += 1;
    }
    tx.commit().await?;
    Ok(Json(ClientEventsResponse {
        accepted,
        duplicates,
    }))
}

// --- Retention -------------------------------------------------------------------------

/// Deletes entries older than each organization's retention setting and
/// records the hash the first remaining entry links to.
pub async fn apply_retention(state: &AppState) -> ApiResult<u64> {
    let settings: Vec<(String, i64)> = sqlx::query_as(
        "SELECT org_id, audit_retention_days FROM org_settings WHERE audit_retention_days > 0",
    )
    .fetch_all(&state.db)
    .await?;
    let mut deleted = 0;
    for (org_id, days) in settings {
        let cutoff = now_ms() - days.saturating_mul(24 * 60 * 60 * 1000);
        let mut tx = crate::db::begin_write(&state.db).await?;
        let last: Option<(i64, String)> = sqlx::query_as(
            "SELECT seq, hash FROM org_audit_events WHERE org_id = $1 AND created_at < $2 \
             ORDER BY seq DESC LIMIT 1",
        )
        .bind(&org_id)
        .bind(cutoff)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((seq, hash)) = last {
            let result =
                sqlx::query("DELETE FROM org_audit_events WHERE org_id = $1 AND seq <= $2")
                    .bind(&org_id)
                    .bind(seq)
                    .execute(&mut *tx)
                    .await?;
            sqlx::query(
                "UPDATE org_audit_heads SET pruned_seq = $1, pruned_hash = $2 WHERE org_id = $3",
            )
            .bind(seq)
            .bind(&hash)
            .bind(&org_id)
            .execute(&mut *tx)
            .await?;
            deleted += result.rows_affected();
        }
        tx.commit().await?;
    }
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_quotes_and_neutralizes_formulas() {
        assert_eq!(csv_field("plain"), "\"plain\"");
        assert_eq!(csv_field("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_field("=SUM(A1)"), "\"'=SUM(A1)\"");
        assert_eq!(csv_field("-1"), "\"'-1\"");
        assert_eq!(csv_field("@x"), "\"'@x\"");
    }

    #[test]
    fn like_prefix_escapes_wildcards() {
        assert_eq!(like_prefix("member_"), "member\\_%");
        assert_eq!(like_prefix("a%"), "a\\%%");
    }

    #[test]
    fn only_security_events_are_mirrored() {
        assert_eq!(mirrored_action("login"), Some("member_signed_in"));
        assert_eq!(mirrored_action("org_created"), None);
        assert_eq!(mirrored_action("logout"), None);
    }
}
