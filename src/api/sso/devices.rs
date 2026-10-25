//! Trusted devices: unlocking with SSO instead of the master password
//! (wave E2). The cryptography is in `passbox_core::trusted_device`; the
//! server stores the account key sealed to each device and hands it out
//! only after an SSO sign-in of that account.
//!
//! - `POST /account/trusted-devices`: an unlocked device trusts itself
//!   (login in the last 10 minutes; the organization must allow it).
//! - `POST /sso/device-requests`: a new device asks to be trusted, with an
//!   SSO proof and its public key. A trusted (or unlocked) device of the
//!   account approves it after comparing the approval code.
//! - `POST /sso/unlock`: a trusted device trades an SSO proof for a session
//!   and its sealed account key.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use passbox_core::identity::sealed_hash;
use passbox_core::sharing::objects::Signed;
use passbox_core::trusted_device::{
    TrustedDeviceGrant, TrustedDeviceUnlock, TrustedDeviceUpload, approval_code, device_key_hash,
};
use passbox_core::{encoding, identity};
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;

use super::login::{self, hash, remember, take_proof};
use super::{load_config, sso_error};
use crate::api::account::require_recent_login;
use crate::api::auth::{
    self, CLIENT_KINDS, NewSession, Session, SessionResponse, clean_device_name, record_event,
};
use crate::api::{access, signed, validate};
use crate::db::{Public, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::security::ClientIp;
use crate::state::AppState;

const REQUEST_TTL_MS: i64 = 30 * 60 * 1000;
const MAX_TRUSTED_DEVICES: i64 = 20;
const MAX_OPEN_REQUESTS: i64 = 5;

fn client_kind(kind: &str) -> String {
    if CLIENT_KINDS.contains(&kind) {
        kind.to_owned()
    } else {
        String::new()
    }
}

/// The organization through which the account may unlock with SSO.
async fn unlock_org(conn: &mut PgConnection, account_id: &str) -> ApiResult<Option<String>> {
    Ok(sqlx::query_scalar!(
        "SELECT org_sso.org_id FROM org_sso JOIN org_members ON org_members.org_id = org_sso.org_id \
         WHERE org_members.account_id = $1 AND org_members.status IN ('accepted', 'confirmed') \
         AND org_sso.enabled = true AND org_sso.allow_device_unlock = true ORDER BY org_sso.org_id LIMIT 1",
        account_id,
    )
    .fetch_optional(&mut *conn)
    .await?)
}

async fn require_unlock_allowed(
    conn: &mut PgConnection,
    account_id: &str,
    org_id: &str,
) -> ApiResult<()> {
    let config = load_config(conn, org_id).await?;
    let member = access::membership(conn, org_id, account_id).await?;
    let allowed = config.is_some_and(|c| c.settings.enabled && c.settings.allow_device_unlock)
        && member.is_some_and(|m| m.status == "accepted" || m.status == "confirmed");
    if allowed {
        Ok(())
    } else {
        Err(sso_error(
            "sso_device_unlock_not_allowed",
            "your organization does not allow unlocking with single sign-on",
        ))
    }
}

/// Checks an upload against the account's published key and the device key.
async fn check_upload(
    conn: &mut PgConnection,
    account_id: &str,
    device_id: &str,
    public_key: &[u8],
    upload: &TrustedDeviceUpload,
) -> ApiResult<()> {
    let me = signed::own_bundle(conn, account_id).await?;
    let grant =
        signed::parse::<TrustedDeviceGrant>("grant", &upload.grant, &upload.grant_signature, &me)?;
    let sealed = validate::base64("sealedKey", &upload.sealed_key, validate::MAX_SMALL_LEN)?;
    let g = &grant.value;
    if upload.device_id != device_id
        || g.account_id != account_id
        || g.device_id != device_id
        || g.device_key_hash != device_key_hash(public_key)
        || g.sealed_hash != sealed_hash(&sealed)
        || encoding::decode(&upload.public_key).ok().as_deref() != Some(public_key)
    {
        return Err(ApiError::bad_request(
            "the trusted device grant does not match",
        ));
    }
    Ok(())
}

async fn insert_device(
    conn: &mut PgConnection,
    account_id: &str,
    name: &str,
    upload: &TrustedDeviceUpload,
    approved_by: &str,
) -> ApiResult<()> {
    let count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"count!\" FROM trusted_devices WHERE account_id = $1",
        account_id,
    )
    .fetch_one(&mut *conn)
    .await?;
    if count >= MAX_TRUSTED_DEVICES {
        return Err(ApiError::bad_request(
            "remove a trusted device first (at most 20)",
        ));
    }
    let now = now_ms();
    let inserted = sqlx::query!(
        "INSERT INTO trusted_devices (id, account_id, name, public_key, sealed_key, grant_data, grant_signature, \
         approved_by, created_at, last_used_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT DO NOTHING",
        &upload.device_id,
        account_id,
        name,
        &upload.public_key,
        &upload.sealed_key,
        &upload.grant,
        &upload.grant_signature,
        approved_by,
        now,
        now,
    )
    .execute(&mut *conn)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::conflict(
            "this device is already trusted",
            serde_json::Value::Null,
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollRequest {
    #[serde(flatten)]
    upload: TrustedDeviceUpload,
    #[serde(default)]
    name: String,
}

/// `POST /account/trusted-devices`: this unlocked device becomes trusted.
pub async fn enroll(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Json(req): Json<EnrollRequest>,
) -> ApiResult<(StatusCode, Json<TrustedDeviceInfo>)> {
    require_recent_login(&session)?;
    validate::id("deviceId", &req.upload.device_id)?;
    let public_key =
        validate::base64("publicKey", &req.upload.public_key, validate::MAX_SMALL_LEN)?;
    if public_key.len() != identity::ENC_PK_LEN {
        return Err(ApiError::bad_request("invalid publicKey"));
    }
    let name = clean_device_name(if req.name.is_empty() {
        &session.device_name
    } else {
        &req.name
    });
    let mut tx = state.db.as_account(&session.account_id).await?;
    let org_id = unlock_org(&mut tx, &session.account_id)
        .await?
        .ok_or_else(|| {
            sso_error(
                "sso_device_unlock_not_allowed",
                "your organization does not allow unlocking with single sign-on",
            )
        })?;
    require_unlock_allowed(&mut tx, &session.account_id, &org_id).await?;
    check_upload(
        &mut tx,
        &session.account_id,
        &req.upload.device_id,
        &public_key,
        &req.upload,
    )
    .await?;
    insert_device(&mut tx, &session.account_id, &name, &req.upload, "").await?;
    tx.commit().await?;
    record_event(
        &state,
        &session.account_id,
        "trusted_device_added",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    let now = now_ms();
    Ok((
        StatusCode::CREATED,
        Json(TrustedDeviceInfo {
            id: req.upload.device_id,
            name,
            approved_by: String::new(),
            created_at: now,
            last_used_at: now,
        }),
    ))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedDeviceInfo {
    id: String,
    name: String,
    /// The device that approved it (empty: it trusted itself).
    approved_by: String,
    created_at: i64,
    last_used_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRequestInfo {
    id: String,
    device_name: String,
    client_kind: String,
    ip: String,
    /// The new device's public key; compute the approval code from it.
    public_key: String,
    created_at: i64,
    expires_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedDevicesResponse {
    /// The account may unlock with SSO (an organization allows it).
    allowed: bool,
    org_id: Option<String>,
    devices: Vec<TrustedDeviceInfo>,
    requests: Vec<DeviceRequestInfo>,
}

/// `GET /account/trusted-devices`: trusted devices and pending requests.
pub async fn list(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<Json<TrustedDevicesResponse>> {
    let mut conn = state.db.as_account(&session.account_id).await?;
    let org_id = unlock_org(&mut conn, &session.account_id).await?;
    let devices: Vec<(String, String, String, i64, i64)> = sqlx::query!(
        "SELECT id, name, approved_by, created_at, last_used_at FROM trusted_devices WHERE account_id = $1 \
         ORDER BY created_at",
        &session.account_id,
    ).map(|row| (row.id, row.name, row.approved_by, row.created_at, row.last_used_at))
    .fetch_all(&mut *conn)
    .await?;
    let requests: Vec<(String, String, String, String, String, i64, i64)> = sqlx::query!(
        "SELECT id, device_name, client_kind, ip, public_key, created_at, expires_at FROM trusted_device_requests \
         WHERE account_id = $1 AND status = 'pending' AND expires_at > $2 ORDER BY created_at DESC",
        &session.account_id,
        now_ms(),
    ).map(|row| (row.id, row.device_name, row.client_kind, row.ip, row.public_key, row.created_at, row.expires_at))
    .fetch_all(&mut *conn)
    .await?;
    Ok(Json(TrustedDevicesResponse {
        allowed: org_id.is_some(),
        org_id,
        devices: devices
            .into_iter()
            .map(
                |(id, name, approved_by, created_at, last_used_at)| TrustedDeviceInfo {
                    id,
                    name,
                    approved_by,
                    created_at,
                    last_used_at,
                },
            )
            .collect(),
        requests: requests
            .into_iter()
            .map(
                |(id, device_name, client_kind, ip, public_key, created_at, expires_at)| {
                    DeviceRequestInfo {
                        id,
                        device_name,
                        client_kind,
                        ip,
                        public_key,
                        created_at,
                        expires_at,
                    }
                },
            )
            .collect(),
    }))
}

/// `DELETE /account/trusted-devices/{id}`: the device must use the master
/// password again (it keeps nothing that opens the account key).
pub async fn remove(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    validate::id("device id", &id)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    let deleted = sqlx::query!(
        "DELETE FROM trusted_devices WHERE id = $1 AND account_id = $2",
        &id,
        &session.account_id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    if deleted.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    record_event(
        &state,
        &session.account_id,
        "trusted_device_removed",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- A new device asks for approval -----------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRequestBody {
    proof: String,
    public_key: String,
    #[serde(default)]
    device_name: String,
    #[serde(default)]
    client_kind: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRequestCreated {
    /// Also the device ID once approved.
    request_id: String,
    /// Keep it on the device to poll the status (single use once approved).
    request_token: String,
    expires_at: i64,
    /// The code to compare on the approving device.
    approval_code: String,
}

/// `POST /sso/device-requests`: after an SSO sign-in, a device that is not
/// trusted yet asks a trusted device of the account to approve it.
pub async fn create_request(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<DeviceRequestBody>,
) -> ApiResult<(StatusCode, Json<DeviceRequestCreated>)> {
    auth::limit_ip(&state, &ip)?;
    let public_key = validate::base64("publicKey", &req.public_key, validate::MAX_SMALL_LEN)?;
    if public_key.len() != identity::ENC_PK_LEN {
        return Err(ApiError::bad_request("invalid publicKey"));
    }
    // The SSO proof identifies the account: the request runs as it.
    let (account_id, org_id) = take_proof(&state, &req.proof).await?;
    let mut tx = state.db.as_account(&account_id).await?;
    require_unlock_allowed(&mut tx, &account_id, &org_id).await?;
    let now = now_ms();
    let open: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"count!\" FROM trusted_device_requests WHERE account_id = $1 AND status = 'pending' AND expires_at > $2",
        &account_id,
        now,
    )
    .fetch_one(&mut *tx)
    .await?;
    if open >= MAX_OPEN_REQUESTS {
        return Err(ApiError::RateLimited(std::time::Duration::from_secs(60)));
    }
    sqlx::query!(
        "DELETE FROM trusted_device_requests WHERE account_id = $1 AND expires_at < $2",
        &account_id,
        now,
    )
    .execute(&mut *tx)
    .await?;
    let request_id = login::new_id()?;
    let request_token = encoding::encode(
        &passbox_core::random::bytes::<32>().map_err(|e| ApiError::Internal(e.into()))?,
    );
    let expires_at = now + REQUEST_TTL_MS;
    sqlx::query!(
        "INSERT INTO trusted_device_requests (id, account_id, org_id, public_key, device_name, client_kind, ip, \
         token_hash, status, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', $9, $10)",
        &request_id,
        &account_id,
        &org_id,
        encoding::encode(&public_key),
        clean_device_name(&req.device_name),
        client_kind(&req.client_kind),
        &ip,
        hash(&request_token),
        now,
        expires_at,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    record_event(
        &state,
        &account_id,
        "trusted_device_requested",
        &clean_device_name(&req.device_name),
        &client_kind(&req.client_kind),
        &ip,
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(DeviceRequestCreated {
            request_id,
            request_token,
            expires_at,
            approval_code: approval_code(&public_key),
        }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApproveRequest {
    #[serde(flatten)]
    upload: TrustedDeviceUpload,
}

/// `POST /account/trusted-devices/requests/{id}/approve`: an unlocked
/// device of the account (login in the last 10 minutes) approves a new
/// device, after the user compared the approval codes.
pub async fn approve(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(id): Path<String>,
    Json(req): Json<ApproveRequest>,
) -> ApiResult<StatusCode> {
    require_recent_login(&session)?;
    validate::id("request id", &id)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    let row: Option<(String, String, String, i64)> = sqlx::query!(
        "SELECT org_id, public_key, device_name, expires_at FROM trusted_device_requests \
         WHERE id = $1 AND account_id = $2 AND status = 'pending'",
        &id,
        &session.account_id,
    )
    .map(|row| (row.org_id, row.public_key, row.device_name, row.expires_at))
    .fetch_optional(&mut *tx)
    .await?;
    let Some((org_id, public_key, device_name, expires_at)) = row else {
        return Err(ApiError::NotFound);
    };
    if expires_at < now_ms() {
        return Err(ApiError::NotFound);
    }
    require_unlock_allowed(&mut tx, &session.account_id, &org_id).await?;
    let public_key = encoding::decode(&public_key).map_err(|e| ApiError::Internal(e.into()))?;
    check_upload(&mut tx, &session.account_id, &id, &public_key, &req.upload).await?;
    let grant = Signed::<TrustedDeviceGrant>::parse(&req.upload.grant, &req.upload.grant_signature)
        .map_err(|_| ApiError::bad_request("invalid grant"))?;
    insert_device(
        &mut tx,
        &session.account_id,
        &device_name,
        &req.upload,
        &grant.value.approved_by,
    )
    .await?;
    sqlx::query!(
        "UPDATE trusted_device_requests SET status = 'approved' WHERE id = $1",
        &id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    record_event(
        &state,
        &session.account_id,
        "trusted_device_approved",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /account/trusted-devices/requests/{id}/deny`.
pub async fn deny(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    validate::id("request id", &id)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    let updated = sqlx::query!(
        "UPDATE trusted_device_requests SET status = 'denied' WHERE id = $1 AND account_id = $2 AND status = 'pending'",
        &id,
        &session.account_id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    record_event(
        &state,
        &session.account_id,
        "trusted_device_denied",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Unlocking ---------------------------------------------------------------------------

/// A session and the sealed account key of the trusted device.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockResponse {
    session: SessionResponse,
    unlock: TrustedDeviceUnlock,
    email: String,
}

async fn unlock_response(
    state: &AppState,
    account_id: &str,
    org_id: &str,
    device_id: &str,
    device_name: &str,
    client_kind: &str,
    ip: &str,
) -> ApiResult<UnlockResponse> {
    let mut conn = state.db.as_account(account_id).await?;
    crate::instance::ensure_active(&mut conn, account_id).await?;
    require_unlock_allowed(&mut conn, account_id, org_id).await?;
    let device: Option<(String, String, String)> = sqlx::query!(
        "SELECT sealed_key, grant_data, grant_signature FROM trusted_devices WHERE id = $1 AND account_id = $2",
        device_id,
        account_id,
    ).map(|row| (row.sealed_key, row.grant_data, row.grant_signature))
    .fetch_optional(&mut *conn)
    .await?;
    let Some((sealed_key, grant, grant_signature)) = device else {
        return Err(sso_error(
            "sso_device_not_trusted",
            "this device is not trusted; approve it from a trusted device or unlock with your master password",
        ));
    };
    let keys: (String, String, Vec<u8>) = sqlx::query!(
        "SELECT bundle, bundle_signature, encrypted_private FROM account_keys WHERE account_id = $1 \
         ORDER BY key_version DESC LIMIT 1",
        account_id,
    ).map(|row| (row.bundle, row.bundle_signature, row.encrypted_private))
    .fetch_one(&mut *conn)
    .await?;
    let email: String =
        sqlx::query_scalar!("SELECT email FROM accounts WHERE id = $1", account_id,)
            .fetch_one(&mut *conn)
            .await?;
    sqlx::query!(
        "UPDATE trusted_devices SET last_used_at = $1 WHERE id = $2",
        now_ms(),
        device_id,
    )
    .execute(&mut *conn)
    .await?;
    let hours: i64 =
        sqlx::query_scalar!("SELECT reauth_hours FROM org_sso WHERE org_id = $1", org_id,)
            .fetch_one(&mut *conn)
            .await?;
    conn.commit().await?;
    let session = auth::start_session(
        state,
        account_id,
        NewSession {
            device_token_hash: None,
            device_name,
            client_kind,
            ip,
            event: "login_sso_device",
            remember_until: 0,
        },
    )
    .await?;
    let until = now_ms() + hours * 60 * 60 * 1000;
    remember(state, account_id, session.device_token(), until).await?;
    Ok(UnlockResponse {
        session,
        email,
        unlock: TrustedDeviceUnlock {
            account_id: account_id.to_owned(),
            device_id: device_id.to_owned(),
            sealed_key,
            grant,
            grant_signature,
            bundle: keys.0,
            bundle_signature: keys.1,
            encrypted_private: encoding::encode(&keys.2),
        },
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockRequest {
    proof: String,
    device_id: String,
    #[serde(default)]
    device_name: String,
    #[serde(default)]
    client_kind: String,
}

/// `POST /sso/unlock`: a trusted device unlocks after an SSO sign-in.
pub async fn unlock(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<UnlockRequest>,
) -> ApiResult<Json<UnlockResponse>> {
    auth::limit_ip(&state, &ip)?;
    validate::id("deviceId", &req.device_id)?;
    let (account_id, org_id) = take_proof(&state, &req.proof).await?;
    Ok(Json(
        unlock_response(
            &state,
            &account_id,
            &org_id,
            &req.device_id,
            &clean_device_name(&req.device_name),
            &client_kind(&req.client_kind),
            &ip,
        )
        .await?,
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusRequest {
    request_token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusResponse {
    /// `pending`, `approved` or `denied`.
    status: String,
    /// Once approved (returned once): the session and the sealed key.
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<UnlockResponse>,
}

/// `POST /sso/device-requests/status`: the waiting device polls. The first
/// poll after the approval returns a session and the sealed key and ends
/// the request.
pub async fn request_status(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<StatusRequest>,
) -> ApiResult<Json<StatusResponse>> {
    if let Some(wait) = state.limiter.hit(
        &format!("device-request-poll:{ip}"),
        120,
        std::time::Duration::from_secs(60),
    ) {
        return Err(ApiError::RateLimited(wait));
    }
    if req.request_token.is_empty() || req.request_token.len() > 128 {
        return Err(ApiError::NotFound);
    }
    let row: Option<(String, String, String, String, String, String, i64)> = sqlx::query!(
        "SELECT id, account_id, org_id, status, device_name, client_kind, expires_at FROM trusted_device_requests \
         WHERE token_hash = $1",
        hash(&req.request_token),
    ).map(|row| (row.id, row.account_id, row.org_id, row.status, row.device_name, row.client_kind, row.expires_at))
    .fetch_optional(&mut *state.db.public(Public::Auth).await?)
    .await?;
    let Some((id, account_id, org_id, status, device_name, client_kind, expires_at)) = row else {
        return Err(ApiError::NotFound);
    };
    if status == "pending" && expires_at < now_ms() {
        return Err(sso_error(
            "sso_request_expired",
            "the approval request has expired; start again",
        ));
    }
    if status != "approved" {
        return Ok(Json(StatusResponse {
            status,
            result: None,
        }));
    }
    // Single use: the first successful poll ends the request. The holder of
    // the request token of an approved request acts for the account.
    let mut tx = state.db.as_account(&account_id).await?;
    let taken = sqlx::query!(
        "DELETE FROM trusted_device_requests WHERE id = $1 AND status = 'approved'",
        &id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    if taken.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    let result = unlock_response(
        &state,
        &account_id,
        &org_id,
        &id,
        &device_name,
        &client_kind,
        &ip,
    )
    .await?;
    Ok(Json(StatusResponse {
        status,
        result: Some(result),
    }))
}
