//! Account security: activity log and master password changes.

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use passbox_core::kdf::KdfParams;
use passbox_core::{encoding, opaque};
use serde::{Deserialize, Serialize};

use super::auth::{Session, record_event};
use super::validate;
use crate::db::now_ms;
use crate::error::{ApiError, ApiResult};
use crate::security::ClientIp;
use crate::state::AppState;

/// Sensitive changes need a session created by a login within this window.
const REAUTH_WINDOW_MS: i64 = 10 * 60 * 1000;

#[derive(Deserialize)]
pub struct EventsQuery {
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountEvent {
    id: String,
    kind: String,
    device_name: String,
    client_kind: String,
    ip: String,
    created_at: i64,
}

/// The account's recent security-relevant activity, newest first.
pub async fn events(
    State(state): State<AppState>,
    session: Session,
    Query(query): Query<EventsQuery>,
) -> ApiResult<Json<Vec<AccountEvent>>> {
    let limit = query.limit.clamp(1, 200);
    let rows: Vec<(String, String, String, String, String, i64)> = sqlx::query_as(
        "SELECT id, kind, device_name, client_kind, ip, created_at FROM account_events \
         WHERE account_id = $1 ORDER BY created_at DESC LIMIT $2",
    )
    .bind(&session.account_id)
    .bind(limit)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(
                |(id, kind, device_name, client_kind, ip, created_at)| AccountEvent {
                    id,
                    kind,
                    device_name,
                    client_kind,
                    ip,
                    created_at,
                },
            )
            .collect(),
    ))
}

fn require_recent_login(session: &Session) -> ApiResult<()> {
    if now_ms() - session.created_at > REAUTH_WINDOW_MS {
        return Err(ApiError::ReauthenticationRequired);
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordStartRequest {
    registration_request: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordStartResponse {
    registration_response: String,
}

/// Starts registering new OPAQUE credentials for a changed master password.
pub async fn password_start(
    State(state): State<AppState>,
    session: Session,
    Json(req): Json<PasswordStartRequest>,
) -> ApiResult<Json<PasswordStartResponse>> {
    require_recent_login(&session)?;
    let request = validate::base64(
        "registrationRequest",
        &req.registration_request,
        validate::MAX_SMALL_LEN,
    )?;
    let response = state
        .opaque
        .registration_response(&request, session.account_id.as_bytes())
        .map_err(|_| ApiError::bad_request("invalid registrationRequest"))?;
    Ok(Json(PasswordStartResponse {
        registration_response: encoding::encode(&response),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordFinishRequest {
    registration_upload: String,
    kdf_salt: String,
    kdf_params: KdfParams,
    /// The unchanged account key, encrypted with the new Account Unlock Key.
    encrypted_account_key: String,
}

/// Replaces the login credentials and the wrapped account key, and signs
/// out every other device (deleting their device tokens as well).
pub async fn password_finish(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Json(req): Json<PasswordFinishRequest>,
) -> ApiResult<StatusCode> {
    require_recent_login(&session)?;
    validate::kdf(&req.kdf_salt, &req.kdf_params)?;
    validate::base64(
        "encryptedAccountKey",
        &req.encrypted_account_key,
        validate::MAX_SMALL_LEN,
    )?;
    let upload = validate::base64(
        "registrationUpload",
        &req.registration_upload,
        validate::MAX_SMALL_LEN,
    )?;
    let record = opaque::registration_record(&upload)
        .map_err(|_| ApiError::bad_request("invalid registrationUpload"))?;

    let mut tx = crate::db::begin_write(&state.db).await?;
    sqlx::query(
        "UPDATE accounts SET opaque_record = $1, kdf_salt = $2, kdf_memory_kib = $3, kdf_iterations = $4, \
         kdf_parallelism = $5, encrypted_account_key = $6 WHERE id = $7",
    )
    .bind(encoding::encode(&record))
    .bind(&req.kdf_salt)
    .bind(i64::from(req.kdf_params.memory_kib))
    .bind(i64::from(req.kdf_params.iterations))
    .bind(i64::from(req.kdf_params.parallelism))
    .bind(&req.encrypted_account_key)
    .bind(&session.account_id)
    .execute(&mut *tx)
    .await?;
    // Other devices must enter the new password anyway, so they lose their
    // exemption from the per-email lockout too. This device keeps the device
    // token issued with its session.
    sqlx::query(
        "DELETE FROM device_tokens WHERE account_id = $1 AND token_hash NOT IN \
         (SELECT device_token_hash FROM sessions WHERE token_hash = $2)",
    )
    .bind(&session.account_id)
    .bind(session.token_hash())
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM sessions WHERE account_id = $1 AND token_hash <> $2")
        .bind(&session.account_id)
        .bind(session.token_hash())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    record_event(
        &state,
        &session.account_id,
        "password_changed",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    super::notify::password_changed(&state, &session.account_id, &session.device_name, &ip).await;
    Ok(StatusCode::NO_CONTENT)
}
