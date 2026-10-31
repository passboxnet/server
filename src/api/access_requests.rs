//! Access requests: a member of an organization asks the managers of
//! one of its shared vaults for access. Approving is a normal share (the
//! manager's client signs the next manifest version and seals the vault
//! key); this module only keeps the requests and their status.
//!
//! Only confirmed members of the vault's organization can see that a vault
//! ID exists (everyone else gets 404), and only managers of the vault (or
//! organization admins who are members of it) see and decide its requests.

use std::time::Duration;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use passbox_core::sharing::objects::VaultRole;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgConnection;

use super::access;
use super::auth::Session;
use super::org_audit::{self, Actor, Target};
use super::validate;
use crate::db::now_ms;
use crate::error::{ApiError, ApiResult};
use crate::security::ClientIp;
use crate::state::AppState;

const DAY_MS: i64 = 24 * 60 * 60 * 1000;

#[derive(Deserialize)]
pub struct CreateRequest {
    /// `view`, `edit` or `manage`.
    role: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessRequest {
    id: String,
    vault_id: String,
    org_id: String,
    account_id: String,
    /// The requester's email (for managers).
    email: String,
    role: String,
    status: String,
    created_at: i64,
    decided_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultRequestState {
    org_id: String,
    has_access: bool,
    /// The account's newest request for this vault (pending, or decided in
    /// the last 30 days).
    request: Option<AccessRequest>,
}

#[derive(Serialize)]
pub struct ListResponse {
    /// Pending requests for vaults the account manages.
    incoming: Vec<AccessRequest>,
    /// The account's own requests (pending, or decided in the last 30 days).
    outgoing: Vec<AccessRequest>,
}

type Row = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    i64,
    i64,
);

fn request(row: Row) -> AccessRequest {
    let (id, vault_id, org_id, account_id, email, role, status, created_at, decided_at) = row;
    AccessRequest {
        id,
        vault_id,
        org_id,
        account_id,
        email,
        role,
        status,
        created_at,
        decided_at,
    }
}

const SELECT: &str = "SELECT r.id, r.vault_id, r.org_id, r.account_id, a.email, r.role, r.status, \
     r.created_at, r.decided_at FROM access_requests r JOIN account_directory a ON a.id = r.account_id";

/// The vault's organization, if the account is a confirmed member of it.
async fn vault_org(conn: &mut PgConnection, vault_id: &str, account_id: &str) -> ApiResult<String> {
    let org: Option<Option<String>> =
        sqlx::query_scalar!("SELECT org_id FROM vaults WHERE id = $1", vault_id,)
            .fetch_optional(&mut *conn)
            .await?;
    let org = org.flatten().ok_or(ApiError::NotFound)?;
    match access::membership(conn, &org, account_id).await? {
        Some(m) if m.is_confirmed() => Ok(org),
        _ => Err(ApiError::NotFound),
    }
}

async fn newest_own(
    conn: &mut PgConnection,
    vault_id: &str,
    account_id: &str,
) -> ApiResult<Option<AccessRequest>> {
    let row: Option<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{SELECT} WHERE r.vault_id = $1 AND r.account_id = $2 AND r.status <> 'cancelled' \
         AND (r.status = 'pending' OR r.decided_at > $3) ORDER BY r.created_at DESC LIMIT 1"
    )))
    .bind(vault_id)
    .bind(account_id)
    .bind(now_ms() - 30 * DAY_MS)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(row.map(request))
}

/// `GET /api/v1/vaults/{id}/access-request`: whether the account can open
/// the vault and its own request, for the "request access" screen.
pub async fn state_for_vault(
    State(state): State<AppState>,
    session: Session,
    Path(vault_id): Path<String>,
) -> ApiResult<Json<VaultRequestState>> {
    validate::id("vault id", &vault_id)?;
    let mut conn = state.db.as_account(&session.account_id).await?;
    let org_id = vault_org(&mut conn, &vault_id, &session.account_id).await?;
    let has_access = access::shared_role(&mut conn, &vault_id, &org_id, &session.account_id)
        .await?
        .is_some();
    let request = newest_own(&mut conn, &vault_id, &session.account_id).await?;
    Ok(Json(VaultRequestState {
        org_id,
        has_access,
        request,
    }))
}

/// `POST /api/v1/vaults/{id}/access-requests`.
pub async fn create(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(vault_id): Path<String>,
    Json(req): Json<CreateRequest>,
) -> ApiResult<(StatusCode, Json<AccessRequest>)> {
    validate::id("vault id", &vault_id)?;
    let role = VaultRole::parse(&req.role).map_err(|_| ApiError::bad_request("invalid role"))?;
    if let Some(wait) = state.limiter.hit(
        &format!("access-request:{}", session.account_id),
        20,
        Duration::from_secs(24 * 60 * 60),
    ) {
        return Err(ApiError::RateLimited(wait));
    }
    let mut tx = state.db.as_account(&session.account_id).await?;
    let org_id = vault_org(&mut tx, &vault_id, &session.account_id).await?;
    if role > VaultRole::View && access::is_guest(&mut tx, &org_id, &session.account_id).await? {
        return Err(access::guest_view_only());
    }
    if let Some(current) =
        access::shared_role(&mut tx, &vault_id, &org_id, &session.account_id).await?
        && current >= role
    {
        return Err(ApiError::bad_request("you already have this access"));
    }
    if let Some(existing) = newest_own(&mut tx, &vault_id, &session.account_id).await?
        && existing.status == "pending"
    {
        return Err(ApiError::conflict(
            "you already asked for access to this vault",
            json!({ "requestId": existing.id }),
        ));
    }
    let id = passbox_core::id::new_id().map_err(|e| ApiError::Internal(e.into()))?;
    let now = now_ms();
    sqlx::query!(
        "INSERT INTO access_requests (id, vault_id, org_id, account_id, role, status, created_at, decided_by, decided_at) \
         VALUES ($1, $2, $3, $4, $5, 'pending', $6, NULL, 0)",
        &id,
        &vault_id,
        &org_id,
        &session.account_id,
        role.as_str(),
        now,
    )
    .execute(&mut *tx)
    .await?;
    org_audit::record_in(
        &mut tx,
        &org_id,
        &Actor::of(&session, &ip),
        "vault_access_requested",
        Target::vault(&vault_id),
        json!({ "role": role.as_str(), "requestId": id }),
    )
    .await?;
    let email: String = sqlx::query_scalar!(
        "SELECT email FROM accounts WHERE id = $1",
        &session.account_id,
    )
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(AccessRequest {
            id,
            vault_id,
            org_id,
            account_id: session.account_id,
            email,
            role: role.as_str().to_owned(),
            status: "pending".into(),
            created_at: now,
            decided_at: 0,
        }),
    ))
}

/// `GET /api/v1/access-requests`.
pub async fn list(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<Json<ListResponse>> {
    let mut conn = state.db.as_account(&session.account_id).await?;
    let pending: Vec<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{SELECT} JOIN org_members m ON m.org_id = r.org_id AND m.account_id = $1 \
         WHERE r.status = 'pending' AND m.status = 'confirmed' ORDER BY r.created_at"
    )))
    .bind(&session.account_id)
    .fetch_all(&mut *conn)
    .await?;
    let mut incoming = Vec::new();
    for row in pending {
        if row.3 == session.account_id {
            continue;
        }
        if access::require_vault_manager(&mut conn, &row.1, &session.account_id)
            .await
            .is_ok()
        {
            incoming.push(request(row));
        }
    }
    let outgoing: Vec<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{SELECT} WHERE r.account_id = $1 AND r.status <> 'cancelled' \
         AND (r.status = 'pending' OR r.decided_at > $2) ORDER BY r.created_at DESC"
    )))
    .bind(&session.account_id)
    .bind(now_ms() - 30 * DAY_MS)
    .fetch_all(&mut *conn)
    .await?;
    Ok(Json(ListResponse {
        incoming,
        outgoing: outgoing.into_iter().map(request).collect(),
    }))
}

async fn pending(conn: &mut PgConnection, id: &str) -> ApiResult<AccessRequest> {
    let row: Option<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!("{SELECT} WHERE r.id = $1")))
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;
    let request = row.map(request).ok_or(ApiError::NotFound)?;
    if request.status != "pending" {
        return Err(ApiError::conflict(
            "this request was already decided",
            json!({ "status": request.status }),
        ));
    }
    Ok(request)
}

async fn decide(
    state: &AppState,
    session: &Session,
    ip: &str,
    id: &str,
    approve: bool,
) -> ApiResult<StatusCode> {
    validate::id("request id", id)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    let req = pending(&mut tx, id).await?;
    // Non-managers get 404, like for other vault management calls.
    match access::require_vault_manager(&mut tx, &req.vault_id, &session.account_id).await {
        Ok(_) => {}
        Err(ApiError::Forbidden { .. }) => return Err(ApiError::NotFound),
        Err(e) => return Err(e),
    }
    if approve
        && access::shared_role(&mut tx, &req.vault_id, &req.org_id, &req.account_id)
            .await?
            .is_none()
    {
        return Err(ApiError::conflict(
            "share the vault with this person first",
            json!({}),
        ));
    }
    let status = if approve { "approved" } else { "denied" };
    sqlx::query!(
        "UPDATE access_requests SET status = $1, decided_by = $2, decided_at = $3 WHERE id = $4",
        status,
        &session.account_id,
        now_ms(),
        id,
    )
    .execute(&mut *tx)
    .await?;
    org_audit::record_in(
        &mut tx,
        &req.org_id,
        &Actor::of(session, ip),
        if approve {
            "vault_access_request_approved"
        } else {
            "vault_access_request_denied"
        },
        Target::vault(&req.vault_id),
        json!({ "requestId": id, "accountId": req.account_id }),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/v1/access-requests/{id}/approve`: after the manager shared
/// the vault with the requester.
pub async fn approve(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    decide(&state, &session, &ip, &id, true).await
}

/// `POST /api/v1/access-requests/{id}/deny`.
pub async fn deny(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    decide(&state, &session, &ip, &id, false).await
}

/// `DELETE /api/v1/access-requests/{id}`: the requester withdraws it.
pub async fn cancel(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    validate::id("request id", &id)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    let result = sqlx::query!(
        "UPDATE access_requests SET status = 'cancelled', decided_at = $1 \
         WHERE id = $2 AND account_id = $3 AND status = 'pending'",
        now_ms(),
        &id,
        &session.account_id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}
