//! Organization recovery (wave C1), organization side: the recovery key,
//! which admins hold it, members' escrows (opt-in) and approving requests.
//!
//! The server checks that uploads parse, name the right IDs and are signed
//! by the uploader; clients verify everything against the organization's
//! signed roster themselves (`passbox_core::recovery::org`).

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use passbox_core::encoding;
use passbox_core::identity::sealed_hash;
use passbox_core::recovery::ephemeral_key_hash;
use passbox_core::recovery::org::{
    OrgRecoveryKeyUpload, RecoveryApproval, RecoveryApprovalUpload, RecoveryEscrow,
    RecoveryEscrowUpload, RecoveryGrantUpload, RecoveryKeyBundle, RecoveryKeyGrant, request_code,
};
use serde::Serialize;
use serde_json::json;
use sqlx::AnyConnection;

use super::access;
use super::auth::{Session, record_event};
use super::signed::{self, bad};
use super::validate;
use crate::db::{self, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::mail::Template;
use crate::security::ClientIp;
use crate::state::AppState;

/// Admins (confirmed owners and admins) who hold the current recovery key.
pub(crate) async fn recovery_admins(state: &AppState, org_id: &str) -> ApiResult<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT g.account_id FROM org_recovery_grants g \
         JOIN org_members m ON m.org_id = g.org_id AND m.account_id = g.account_id \
         WHERE g.org_id = $1 AND m.status = 'confirmed' AND m.role IN ('owner', 'admin') \
         AND g.key_version = (SELECT MAX(key_version) FROM org_recovery_keys WHERE org_id = $2) \
         ORDER BY g.account_id",
    )
    .bind(org_id)
    .bind(org_id)
    .fetch_all(&state.db)
    .await?)
}

async fn current_key(
    conn: &mut AnyConnection,
    org_id: &str,
) -> ApiResult<Option<(i64, String, String, String, String)>> {
    Ok(sqlx::query_as(
        "SELECT key_version, bundle, bundle_signature, bundle_hash, created_by FROM org_recovery_keys \
         WHERE org_id = $1 ORDER BY key_version DESC LIMIT 1",
    )
    .bind(org_id)
    .fetch_optional(&mut *conn)
    .await?)
}

async fn holds_key(conn: &mut AnyConnection, org_id: &str, account_id: &str) -> ApiResult<bool> {
    let found: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM org_recovery_grants WHERE org_id = $1 AND account_id = $2 \
         AND key_version = (SELECT MAX(key_version) FROM org_recovery_keys WHERE org_id = $3)",
    )
    .bind(org_id)
    .bind(account_id)
    .bind(org_id)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(found.is_some())
}

async fn event(
    state: &AppState,
    account_id: &str,
    kind: &str,
    session: &Session,
    ip: &str,
) -> ApiResult<()> {
    record_event(
        state,
        account_id,
        kind,
        &session.device_name,
        &session.client_kind,
        ip,
    )
    .await
}

// --- State --------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantView {
    account_id: String,
    key_version: i64,
    grant: String,
    grant_signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sealed_key: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyView {
    key_version: i64,
    bundle: String,
    bundle_signature: String,
    grants: Vec<GrantView>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnEscrow {
    key_version: i64,
    created_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryState {
    /// `null` until an admin set up recovery.
    key: Option<KeyView>,
    /// This account's escrow, if it opted in.
    escrow: Option<OwnEscrow>,
    /// For admins: members who opted in (with the current key).
    #[serde(skip_serializing_if = "Option::is_none")]
    enrolled: Option<Vec<String>>,
    /// For admins who hold the key: open requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pending_requests: Option<i64>,
}

/// `GET /orgs/{id}/recovery` (confirmed members).
pub async fn get(
    State(state): State<AppState>,
    session: Session,
    Path(org_id): Path<String>,
) -> ApiResult<Json<RecoveryState>> {
    validate::id("organization id", &org_id)?;
    let mut conn = state.db.acquire().await?;
    let me = access::require_confirmed(&mut conn, &org_id, &session.account_id).await?;
    let key = match current_key(&mut conn, &org_id).await? {
        Some((key_version, bundle, bundle_signature, _, _)) => {
            let rows: Vec<(String, String, String, String)> = sqlx::query_as(
                "SELECT account_id, grant_data, grant_signature, sealed_key FROM org_recovery_grants \
                 WHERE org_id = $1 AND key_version = $2 ORDER BY account_id",
            )
            .bind(&org_id)
            .bind(key_version)
            .fetch_all(&mut *conn)
            .await?;
            Some(KeyView {
                key_version,
                bundle,
                bundle_signature,
                grants: rows
                    .into_iter()
                    .map(|(account_id, grant, grant_signature, sealed)| GrantView {
                        sealed_key: (account_id == session.account_id).then_some(sealed),
                        account_id,
                        key_version,
                        grant,
                        grant_signature,
                    })
                    .collect(),
            })
        }
        None => None,
    };
    let escrow: Option<(i64, i64)> = sqlx::query_as(
        "SELECT key_version, created_at FROM org_recovery_escrows WHERE org_id = $1 AND account_id = $2",
    )
    .bind(&org_id)
    .bind(&session.account_id)
    .fetch_optional(&mut *conn)
    .await?;
    let (enrolled, pending) = if me.is_admin() {
        let enrolled: Vec<String> = sqlx::query_scalar(
            "SELECT e.account_id FROM org_recovery_escrows e WHERE e.org_id = $1 \
             AND e.key_version = (SELECT MAX(key_version) FROM org_recovery_keys WHERE org_id = $2) \
             ORDER BY e.account_id",
        )
        .bind(&org_id)
        .bind(&org_id)
        .fetch_all(&mut *conn)
        .await?;
        let pending = if holds_key(&mut conn, &org_id, &session.account_id).await? {
            Some(
                sqlx::query_scalar(
                    "SELECT COUNT(*) FROM org_recovery_requests WHERE org_id = $1 AND status = 'pending' \
                     AND expires_at > $2",
                )
                .bind(&org_id)
                .bind(now_ms())
                .fetch_one(&mut *conn)
                .await?,
            )
        } else {
            None
        };
        (Some(enrolled), pending)
    } else {
        (None, None)
    };
    Ok(Json(RecoveryState {
        key,
        escrow: escrow.map(|(key_version, created_at)| OwnEscrow {
            key_version,
            created_at,
        }),
        enrolled,
        pending_requests: pending,
    }))
}

// --- Recovery key and grants ----------------------------------------------------------

fn check_grant(
    grant: &passbox_core::sharing::objects::Signed<RecoveryKeyGrant>,
    upload: &RecoveryGrantUpload,
    org_id: &str,
    granter: &str,
    holder_bundle_hash: &[u8; 32],
) -> ApiResult<()> {
    let g = &grant.value;
    let sealed = signed::sealed("sealedKey", &upload.sealed_key)?;
    if g.org_id != org_id
        || g.key_version != upload.key_version
        || g.account_id != upload.account_id
        || g.granter_id != granter
        || &g.account_bundle_hash != holder_bundle_hash
        || g.sealed_hash != sealed_hash(&sealed)
    {
        return Err(bad("the grant does not match the request"));
    }
    Ok(())
}

/// `POST /orgs/{id}/recovery/keys`: sets up (or replaces) the recovery key.
/// Owners and admins.
pub async fn create_key(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(org_id): Path<String>,
    Json(req): Json<OrgRecoveryKeyUpload>,
) -> ApiResult<StatusCode> {
    validate::id("organization id", &org_id)?;
    let mut tx = db::begin_write(&state.db).await?;
    access::require_admin(&mut tx, &org_id, &session.account_id).await?;
    let latest = current_key(&mut tx, &org_id).await?.map_or(0, |k| k.0);
    if i64::from(req.key_version) != latest + 1 {
        return Err(ApiError::conflict(
            "the recovery key version must be the next one",
            json!({ "currentKeyVersion": latest }),
        ));
    }
    let me = signed::own_bundle(&mut tx, &session.account_id).await?;
    let bundle =
        signed::parse::<RecoveryKeyBundle>("bundle", &req.bundle, &req.bundle_signature, &me)?;
    if bundle.value.org_id != org_id
        || bundle.value.key_version != req.key_version
        || bundle.value.creator_id != session.account_id
    {
        return Err(bad("the recovery key does not match the request"));
    }
    if req.grant.account_id != session.account_id || req.grant.key_version != req.key_version {
        return Err(bad("seal the first copy of the recovery key for yourself"));
    }
    let grant = signed::parse::<RecoveryKeyGrant>(
        "grant",
        &req.grant.grant,
        &req.grant.grant_signature,
        &me,
    )?;
    check_grant(&grant, &req.grant, &org_id, &session.account_id, &me.hash())?;
    let now = now_ms();
    sqlx::query(
        "INSERT INTO org_recovery_keys (org_id, key_version, bundle, bundle_signature, bundle_hash, created_by, \
         created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&org_id)
    .bind(i64::from(req.key_version))
    .bind(&req.bundle)
    .bind(&req.bundle_signature)
    .bind(encoding::encode(&bundle.hash()))
    .bind(&session.account_id)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    insert_grant(&mut tx, &org_id, &req.grant, &session.account_id).await?;
    tx.commit().await?;
    event(
        &state,
        &session.account_id,
        "org_recovery_enabled",
        &session,
        &ip,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn insert_grant(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: &str,
    upload: &RecoveryGrantUpload,
    granted_by: &str,
) -> ApiResult<()> {
    sqlx::query("DELETE FROM org_recovery_grants WHERE org_id = $1 AND key_version = $2 AND account_id = $3")
        .bind(org_id)
        .bind(i64::from(upload.key_version))
        .bind(&upload.account_id)
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "INSERT INTO org_recovery_grants (org_id, key_version, account_id, sealed_key, grant_data, \
         grant_signature, granted_by, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(org_id)
    .bind(i64::from(upload.key_version))
    .bind(&upload.account_id)
    .bind(&upload.sealed_key)
    .bind(&upload.grant)
    .bind(&upload.grant_signature)
    .bind(granted_by)
    .bind(now_ms())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// `POST /orgs/{id}/recovery/grants`: lets another admin approve requests.
/// Only admins who hold the key can seal it for others.
pub async fn add_grant(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(org_id): Path<String>,
    Json(req): Json<RecoveryGrantUpload>,
) -> ApiResult<StatusCode> {
    validate::id("organization id", &org_id)?;
    validate::id("account id", &req.account_id)?;
    let mut tx = db::begin_write(&state.db).await?;
    access::require_admin(&mut tx, &org_id, &session.account_id).await?;
    if !holds_key(&mut tx, &org_id, &session.account_id).await? {
        return Err(ApiError::forbidden(
            "forbidden",
            "only admins who hold the recovery key can share it",
        ));
    }
    let target = access::membership(&mut tx, &org_id, &req.account_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if !target.is_admin() {
        return Err(bad(
            "only confirmed owners and admins can hold the recovery key",
        ));
    }
    let latest = current_key(&mut tx, &org_id).await?.map_or(0, |k| k.0);
    if i64::from(req.key_version) != latest {
        return Err(ApiError::conflict(
            "the recovery key changed",
            json!({ "currentKeyVersion": latest }),
        ));
    }
    let me = signed::own_bundle(&mut tx, &session.account_id).await?;
    let holder = signed::own_bundle(&mut tx, &req.account_id).await?;
    let grant = signed::parse::<RecoveryKeyGrant>("grant", &req.grant, &req.grant_signature, &me)?;
    check_grant(&grant, &req, &org_id, &session.account_id, &holder.hash())?;
    insert_grant(&mut tx, &org_id, &req, &session.account_id).await?;
    tx.commit().await?;
    event(
        &state,
        &req.account_id,
        "org_recovery_admin_added",
        &session,
        &ip,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Escrow (members) -------------------------------------------------------------------

/// `PUT /orgs/{id}/recovery/escrow`: opt in (or renew after a key change).
pub async fn put_escrow(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(org_id): Path<String>,
    Json(req): Json<RecoveryEscrowUpload>,
) -> ApiResult<StatusCode> {
    validate::id("organization id", &org_id)?;
    let mut tx = db::begin_write(&state.db).await?;
    access::require_confirmed(&mut tx, &org_id, &session.account_id).await?;
    let (key_version, _, _, bundle_hash, _) = current_key(&mut tx, &org_id)
        .await?
        .ok_or_else(|| bad("the organization has not set up recovery"))?;
    if i64::from(req.key_version) != key_version {
        return Err(ApiError::conflict(
            "the recovery key changed",
            json!({ "currentKeyVersion": key_version }),
        ));
    }
    let me = signed::own_bundle(&mut tx, &session.account_id).await?;
    let escrow =
        signed::parse::<RecoveryEscrow>("escrow", &req.escrow, &req.escrow_signature, &me)?;
    let sealed = signed::sealed("sealedKey", &req.sealed_key)?;
    let e = &escrow.value;
    if e.org_id != org_id
        || e.account_id != session.account_id
        || e.key_version != req.key_version
        || encoding::encode(&e.recovery_bundle_hash) != bundle_hash
        || e.account_bundle_hash != me.hash()
        || e.sealed_hash != sealed_hash(&sealed)
    {
        return Err(bad("the escrow does not match the request"));
    }
    sqlx::query("DELETE FROM org_recovery_escrows WHERE org_id = $1 AND account_id = $2")
        .bind(&org_id)
        .bind(&session.account_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO org_recovery_escrows (org_id, account_id, key_version, escrow, escrow_signature, \
         sealed_key, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&org_id)
    .bind(&session.account_id)
    .bind(key_version)
    .bind(&req.escrow)
    .bind(&req.escrow_signature)
    .bind(&req.sealed_key)
    .bind(now_ms())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    event(
        &state,
        &session.account_id,
        "org_recovery_enrolled",
        &session,
        &ip,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /orgs/{id}/recovery/escrow`: opt out.
pub async fn delete_escrow(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(org_id): Path<String>,
) -> ApiResult<StatusCode> {
    validate::id("organization id", &org_id)?;
    let deleted =
        sqlx::query("DELETE FROM org_recovery_escrows WHERE org_id = $1 AND account_id = $2")
            .bind(&org_id)
            .bind(&session.account_id)
            .execute(&state.db)
            .await?;
    if deleted.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    sqlx::query(
        "UPDATE org_recovery_requests SET status = 'cancelled' WHERE org_id = $1 AND account_id = $2 \
         AND status IN ('pending', 'approved')",
    )
    .bind(&org_id)
    .bind(&session.account_id)
    .execute(&state.db)
    .await?;
    event(
        &state,
        &session.account_id,
        "org_recovery_withdrawn",
        &session,
        &ip,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Requests (admins) -------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestView {
    id: String,
    org_id: String,
    account_id: String,
    email: String,
    device_name: String,
    ip: String,
    created_at: i64,
    expires_at: i64,
    ephemeral_key: String,
    key_version: i64,
    escrow: String,
    escrow_signature: String,
    sealed_key: String,
}

async fn require_key_holder(
    conn: &mut AnyConnection,
    org_id: &str,
    account_id: &str,
) -> ApiResult<()> {
    access::require_admin(conn, org_id, account_id).await?;
    if !holds_key(conn, org_id, account_id).await? {
        return Err(ApiError::forbidden(
            "forbidden",
            "only admins who hold the recovery key can do this",
        ));
    }
    Ok(())
}

/// `GET /orgs/{id}/recovery/requests`: open requests with the escrows to open.
pub async fn requests(
    State(state): State<AppState>,
    session: Session,
    Path(org_id): Path<String>,
) -> ApiResult<Json<Vec<RequestView>>> {
    validate::id("organization id", &org_id)?;
    let mut conn = state.db.acquire().await?;
    require_key_holder(&mut conn, &org_id, &session.account_id).await?;
    type Row = (
        String,
        String,
        String,
        String,
        String,
        i64,
        i64,
        String,
        i64,
        String,
        String,
        String,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT r.id, r.account_id, a.email, r.device_name, r.ip, r.created_at, r.expires_at, r.ephemeral_key, \
         e.key_version, e.escrow, e.escrow_signature, e.sealed_key FROM org_recovery_requests r \
         JOIN accounts a ON a.id = r.account_id \
         JOIN org_recovery_escrows e ON e.org_id = r.org_id AND e.account_id = r.account_id \
         WHERE r.org_id = $1 AND r.status = 'pending' AND r.expires_at > $2 ORDER BY r.created_at",
    )
    .bind(&org_id)
    .bind(now_ms())
    .fetch_all(&mut *conn)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(
                |(
                    id,
                    account_id,
                    email,
                    device_name,
                    ip,
                    created_at,
                    expires_at,
                    ephemeral_key,
                    key_version,
                    escrow,
                    escrow_signature,
                    sealed_key,
                )| RequestView {
                    id,
                    org_id: org_id.clone(),
                    account_id,
                    email,
                    device_name,
                    ip,
                    created_at,
                    expires_at,
                    ephemeral_key,
                    key_version,
                    escrow,
                    escrow_signature,
                    sealed_key,
                },
            )
            .collect(),
    ))
}

async fn pending_request(
    conn: &mut AnyConnection,
    org_id: &str,
    request_id: &str,
) -> ApiResult<(String, String)> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT account_id, ephemeral_key FROM org_recovery_requests WHERE id = $1 AND org_id = $2 \
         AND status = 'pending' AND expires_at > $3",
    )
    .bind(request_id)
    .bind(org_id)
    .bind(now_ms())
    .fetch_optional(&mut *conn)
    .await?;
    row.ok_or(ApiError::NotFound)
}

/// `POST /orgs/{id}/recovery/requests/{rid}/approve`.
pub async fn approve(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path((org_id, request_id)): Path<(String, String)>,
    Json(req): Json<RecoveryApprovalUpload>,
) -> ApiResult<StatusCode> {
    validate::id("organization id", &org_id)?;
    validate::id("request id", &request_id)?;
    let mut tx = db::begin_write(&state.db).await?;
    require_key_holder(&mut tx, &org_id, &session.account_id).await?;
    let (account_id, ephemeral_key) = pending_request(&mut tx, &org_id, &request_id).await?;
    if account_id == session.account_id {
        return Err(ApiError::forbidden(
            "forbidden",
            "you cannot approve your own recovery",
        ));
    }
    let me = signed::own_bundle(&mut tx, &session.account_id).await?;
    let approval =
        signed::parse::<RecoveryApproval>("approval", &req.approval, &req.approval_signature, &me)?;
    let sealed = signed::sealed("sealedKey", &req.sealed_key)?;
    let ephemeral = encoding::decode(&ephemeral_key).map_err(|e| ApiError::Internal(e.into()))?;
    let a = &approval.value;
    if a.request_id != request_id
        || a.org_id != org_id
        || a.account_id != account_id
        || a.approver_id != session.account_id
        || a.ephemeral_key_hash != ephemeral_key_hash(&ephemeral)
        || a.sealed_hash != sealed_hash(&sealed)
    {
        return Err(bad("the approval does not match the request"));
    }
    let now = now_ms();
    sqlx::query(
        "UPDATE org_recovery_requests SET status = 'approved', approval = $1, approval_signature = $2, \
         sealed_key = $3, request_code = $4, decided_by = $5, decided_at = $6 WHERE id = $7",
    )
    .bind(&req.approval)
    .bind(&req.approval_signature)
    .bind(&req.sealed_key)
    .bind(request_code(&ephemeral))
    .bind(&session.account_id)
    .bind(now)
    .bind(&request_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    event(
        &state,
        &session.account_id,
        "org_recovery_approved",
        &session,
        &ip,
    )
    .await?;
    record_event(&state, &account_id, "org_recovery_approved", "", "", &ip).await?;
    let approver: String = sqlx::query_scalar("SELECT email FROM accounts WHERE id = $1")
        .bind(&session.account_id)
        .fetch_one(&state.db)
        .await?;
    if let Err(err) = state
        .mailer
        .enqueue_for_account(
            &account_id,
            Template::RecoveryApproved,
            json!({ "approver": approver }),
        )
        .await
    {
        tracing::warn!(error = ?err, "could not queue the recovery mail");
    }
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /orgs/{id}/recovery/requests/{rid}/deny`.
pub async fn deny(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path((org_id, request_id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    validate::id("organization id", &org_id)?;
    validate::id("request id", &request_id)?;
    let mut tx = db::begin_write(&state.db).await?;
    require_key_holder(&mut tx, &org_id, &session.account_id).await?;
    let (account_id, _) = pending_request(&mut tx, &org_id, &request_id).await?;
    sqlx::query(
        "UPDATE org_recovery_requests SET status = 'denied', decided_by = $1, decided_at = $2 WHERE id = $3",
    )
    .bind(&session.account_id)
    .bind(now_ms())
    .bind(&request_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    event(
        &state,
        &session.account_id,
        "org_recovery_denied",
        &session,
        &ip,
    )
    .await?;
    record_event(&state, &account_id, "org_recovery_denied", "", "", &ip).await?;
    let approver: String = sqlx::query_scalar("SELECT email FROM accounts WHERE id = $1")
        .bind(&session.account_id)
        .fetch_one(&state.db)
        .await?;
    if let Err(err) = state
        .mailer
        .enqueue_for_account(
            &account_id,
            Template::RecoveryDenied,
            json!({ "approver": approver }),
        )
        .await
    {
        tracing::warn!(error = ?err, "could not queue the recovery mail");
    }
    Ok(StatusCode::NO_CONTENT)
}
