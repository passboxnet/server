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
use sqlx::PgConnection;

use super::access;
use super::auth::{Session, record_event};
use super::signed::{self, bad};
use super::validate;
use crate::db::{Public, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::mail::Template;
use crate::security::ClientIp;
use crate::state::AppState;

/// Admins (confirmed owners and admins) who hold the current recovery key,
/// for notifications. Also called by the signed-out requesting device, so
/// it goes through a function that reveals the account IDs only.
pub(crate) async fn recovery_admins_from(state: &AppState, org_id: &str) -> ApiResult<Vec<String>> {
    Ok(sqlx::query_scalar!(
        r#"SELECT admin AS "admin!" FROM passbox.org_recovery_admins($1) AS admin"#,
        org_id,
    )
    .fetch_all(&mut *state.db.public(Public::Auth).await?)
    .await?)
}

async fn current_key(
    conn: &mut PgConnection,
    org_id: &str,
) -> ApiResult<Option<(i64, String, String, String, String)>> {
    Ok(sqlx::query!(
        "SELECT key_version, bundle, bundle_signature, bundle_hash, created_by FROM org_recovery_keys \
         WHERE org_id = $1 ORDER BY key_version DESC LIMIT 1",
        org_id,
    ).map(|row| (row.key_version, row.bundle, row.bundle_signature, row.bundle_hash, row.created_by))
    .fetch_optional(&mut *conn)
    .await?)
}

async fn holds_key(conn: &mut PgConnection, org_id: &str, account_id: &str) -> ApiResult<bool> {
    let found: Option<i64> = sqlx::query_scalar!(
        "SELECT 1::BIGINT AS \"one!\" FROM org_recovery_grants WHERE org_id = $1 AND account_id = $2 \
         AND key_version = (SELECT MAX(key_version) FROM org_recovery_keys WHERE org_id = $3)",
        org_id,
        account_id,
        org_id,
    )
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
    let mut conn = state.db.as_account(&session.account_id).await?;
    let me = access::require_confirmed(&mut conn, &org_id, &session.account_id).await?;
    let key = match current_key(&mut conn, &org_id).await? {
        Some((key_version, bundle, bundle_signature, _, _)) => {
            let rows: Vec<(String, String, String, Vec<u8>)> = sqlx::query!(
                "SELECT account_id, grant_data, grant_signature, sealed_key FROM org_recovery_grants \
                 WHERE org_id = $1 AND key_version = $2 ORDER BY account_id",
                &org_id,
                key_version,
            ).map(|row| (row.account_id, row.grant_data, row.grant_signature, row.sealed_key))
            .fetch_all(&mut *conn)
            .await?;
            Some(KeyView {
                key_version,
                bundle,
                bundle_signature,
                grants: rows
                    .into_iter()
                    .map(|(account_id, grant, grant_signature, sealed)| GrantView {
                        sealed_key: (account_id == session.account_id)
                            .then(|| encoding::encode(&sealed)),
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
    let escrow: Option<(i64, i64)> = sqlx::query!(
        "SELECT key_version, created_at FROM org_recovery_escrows WHERE org_id = $1 AND account_id = $2",
        &org_id,
        &session.account_id,
    ).map(|row| (row.key_version, row.created_at))
    .fetch_optional(&mut *conn)
    .await?;
    let (enrolled, pending) = if me.is_admin() {
        let enrolled: Vec<String> = sqlx::query_scalar!(
            "SELECT e.account_id FROM org_recovery_escrows e WHERE e.org_id = $1 \
             AND e.key_version = (SELECT MAX(key_version) FROM org_recovery_keys WHERE org_id = $2) \
             ORDER BY e.account_id",
            &org_id,
            &org_id,
        )
        .fetch_all(&mut *conn)
        .await?;
        let pending = if holds_key(&mut conn, &org_id, &session.account_id).await? {
            Some(
                sqlx::query_scalar!(
                    "SELECT COUNT(*) AS \"count!\" FROM org_recovery_requests WHERE org_id = $1 AND status = 'pending' \
                     AND expires_at > $2",
                    &org_id,
                    now_ms(),
                )
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
    let mut tx = state.db.as_account(&session.account_id).await?;
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
    sqlx::query!(
        "INSERT INTO org_recovery_keys (org_id, key_version, bundle, bundle_signature, bundle_hash, created_by, \
         created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        &org_id,
        i64::from(req.key_version),
        &req.bundle,
        &req.bundle_signature,
        encoding::encode(&bundle.hash()),
        &session.account_id,
        now,
    )
    .execute(&mut *tx)
    .await?;
    insert_grant(&mut tx, &org_id, &req.grant, &session.account_id).await?;
    tx.commit().await?;
    super::org_audit::record(
        &state,
        &org_id,
        &super::org_audit::Actor::of(&session, &ip),
        "recovery_key_created",
        super::org_audit::Target::org(&org_id),
        json!({}),
    )
    .await;
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
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: &str,
    upload: &RecoveryGrantUpload,
    granted_by: &str,
) -> ApiResult<()> {
    sqlx::query!(
        "INSERT INTO org_recovery_grants (org_id, key_version, account_id, sealed_key, grant_data, \
         grant_signature, granted_by, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         ON CONFLICT (org_id, key_version, account_id) DO UPDATE SET sealed_key = excluded.sealed_key, \
         grant_data = excluded.grant_data, grant_signature = excluded.grant_signature, \
         granted_by = excluded.granted_by, created_at = excluded.created_at",
        org_id,
        i64::from(upload.key_version),
        &upload.account_id,
        super::vaults::decode(&upload.sealed_key)?,
        &upload.grant,
        &upload.grant_signature,
        granted_by,
        now_ms(),
    )
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
    let mut tx = state.db.as_account(&session.account_id).await?;
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
    super::org_audit::record(
        &state,
        &org_id,
        &super::org_audit::Actor::of(&session, &ip),
        "recovery_admin_added",
        super::org_audit::Target::account(&req.account_id),
        json!({}),
    )
    .await;
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
    let mut tx = state.db.as_account(&session.account_id).await?;
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
    // One statement, so two enrollments at the same time (the app enrolls
    // on its own when a policy requires it) do not collide.
    sqlx::query!(
        "INSERT INTO org_recovery_escrows (org_id, account_id, key_version, escrow, escrow_signature, \
         sealed_key, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (org_id, account_id) DO UPDATE SET key_version = excluded.key_version, \
         escrow = excluded.escrow, escrow_signature = excluded.escrow_signature, \
         sealed_key = excluded.sealed_key, created_at = excluded.created_at",
        &org_id,
        &session.account_id,
        key_version,
        &req.escrow,
        &req.escrow_signature,
        super::vaults::decode(&req.sealed_key)?,
        now_ms(),
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    super::org_audit::record(
        &state,
        &org_id,
        &super::org_audit::Actor::of(&session, &ip),
        "recovery_enrolled",
        super::org_audit::Target::account(&session.account_id),
        json!({}),
    )
    .await;
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
    let mut tx = state.db.as_account(&session.account_id).await?;
    let deleted = sqlx::query!(
        "DELETE FROM org_recovery_escrows WHERE org_id = $1 AND account_id = $2",
        &org_id,
        &session.account_id,
    )
    .execute(&mut *tx)
    .await?;
    if deleted.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    sqlx::query!(
        "UPDATE org_recovery_requests SET status = 'cancelled' WHERE org_id = $1 AND account_id = $2 \
         AND status IN ('pending', 'approved')",
        &org_id,
        &session.account_id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    super::org_audit::record(
        &state,
        &org_id,
        &super::org_audit::Actor::of(&session, &ip),
        "recovery_withdrawn",
        super::org_audit::Target::account(&session.account_id),
        json!({}),
    )
    .await;
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

/// `DELETE /orgs/{id}/recovery`: turns recovery off for the whole
/// organization (owners and admins). Deletes the recovery key, every
/// admin's copy and every member's escrow, and cancels open requests.
/// Refused while the policy requires recovery (403 `recovery_required`):
/// change the policy first. Recovery can be set up again later; members
/// then enroll again.
pub async fn turn_off(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(org_id): Path<String>,
) -> ApiResult<StatusCode> {
    validate::id("organization id", &org_id)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    access::require_admin(&mut tx, &org_id, &session.account_id).await?;
    if current_key(&mut tx, &org_id).await?.is_none() {
        return Err(ApiError::NotFound);
    }
    if super::org_policy::current_rules(&mut tx, &org_id)
        .await?
        .is_some_and(|r| r.require_recovery_enrollment)
    {
        return Err(ApiError::forbidden(
            "recovery_required",
            "the organization's policy requires recovery; turn off \"Require recovery\" in the policy first",
        ));
    }
    sqlx::query!(
        "UPDATE org_recovery_requests SET status = 'cancelled' WHERE org_id = $1 \
         AND status IN ('pending', 'approved')",
        &org_id,
    )
    .execute(&mut *tx)
    .await?;
    for sql in [
        "DELETE FROM org_recovery_escrows WHERE org_id = $1",
        "DELETE FROM org_recovery_grants WHERE org_id = $1",
        "DELETE FROM org_recovery_keys WHERE org_id = $1",
    ] {
        sqlx::query(sql).bind(&org_id).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    super::org_audit::record(
        &state,
        &org_id,
        &super::org_audit::Actor::of(&session, &ip),
        "recovery_turned_off",
        super::org_audit::Target::org(&org_id),
        json!({}),
    )
    .await;
    event(
        &state,
        &session.account_id,
        "org_recovery_disabled",
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
    conn: &mut PgConnection,
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
    let mut conn = state.db.as_account(&session.account_id).await?;
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
        Vec<u8>,
    );
    let rows: Vec<Row> = sqlx::query!(
        "SELECT r.id, r.account_id, a.email AS \"email!\", r.device_name, r.ip, r.created_at, r.expires_at, r.ephemeral_key, \
         e.key_version, e.escrow, e.escrow_signature, e.sealed_key FROM org_recovery_requests r \
         JOIN account_directory a ON a.id = r.account_id \
         JOIN org_recovery_escrows e ON e.org_id = r.org_id AND e.account_id = r.account_id \
         WHERE r.org_id = $1 AND r.status = 'pending' AND r.expires_at > $2 ORDER BY r.created_at",
        &org_id,
        now_ms(),
    ).map(|row| (row.id, row.account_id, row.email, row.device_name, row.ip, row.created_at, row.expires_at, row.ephemeral_key, row.key_version, row.escrow, row.escrow_signature, row.sealed_key))
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
                    sealed_key: encoding::encode(&sealed_key),
                },
            )
            .collect(),
    ))
}

async fn pending_request(
    conn: &mut PgConnection,
    org_id: &str,
    request_id: &str,
) -> ApiResult<(String, String)> {
    let row: Option<(String, String)> = sqlx::query!(
        "SELECT account_id, ephemeral_key FROM org_recovery_requests WHERE id = $1 AND org_id = $2 \
         AND status = 'pending' AND expires_at > $3",
        request_id,
        org_id,
        now_ms(),
    )
    .map(|row| (row.account_id, row.ephemeral_key))
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
    let mut tx = state.db.as_account(&session.account_id).await?;
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
    sqlx::query!(
        "UPDATE org_recovery_requests SET status = 'approved', approval = $1, approval_signature = $2, \
         sealed_key = $3, request_code = $4, decided_by = $5, decided_at = $6 WHERE id = $7",
        &req.approval,
        &req.approval_signature,
        &req.sealed_key,
        request_code(&ephemeral),
        &session.account_id,
        now,
        &request_id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    super::org_audit::record(
        &state,
        &org_id,
        &super::org_audit::Actor::of(&session, &ip),
        "recovery_request_approved",
        super::org_audit::Target::account(&account_id),
        json!({ "requestId": request_id }),
    )
    .await;
    event(
        &state,
        &session.account_id,
        "org_recovery_approved",
        &session,
        &ip,
    )
    .await?;
    record_event(&state, &account_id, "org_recovery_approved", "", "", &ip).await?;
    let approver: String = sqlx::query_scalar!(
        "SELECT email FROM accounts WHERE id = $1",
        &session.account_id,
    )
    .fetch_one(&mut *state.db.as_account(&session.account_id).await?)
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
    let mut tx = state.db.as_account(&session.account_id).await?;
    require_key_holder(&mut tx, &org_id, &session.account_id).await?;
    let (account_id, _) = pending_request(&mut tx, &org_id, &request_id).await?;
    sqlx::query!(
        "UPDATE org_recovery_requests SET status = 'denied', decided_by = $1, decided_at = $2 WHERE id = $3",
        &session.account_id,
        now_ms(),
        &request_id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    super::org_audit::record(
        &state,
        &org_id,
        &super::org_audit::Actor::of(&session, &ip),
        "recovery_request_denied",
        super::org_audit::Target::account(&account_id),
        json!({ "requestId": request_id }),
    )
    .await;
    event(
        &state,
        &session.account_id,
        "org_recovery_denied",
        &session,
        &ip,
    )
    .await?;
    record_event(&state, &account_id, "org_recovery_denied", "", "", &ip).await?;
    let approver: String = sqlx::query_scalar!(
        "SELECT email FROM accounts WHERE id = $1",
        &session.account_id,
    )
    .fetch_one(&mut *state.db.as_account(&session.account_id).await?)
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
