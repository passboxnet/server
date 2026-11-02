//! Signing in a device without a session (`pbx login`) from a signed-in
//! browser.
//!
//! 1. The requesting device picks an ID and a secret, creates an ephemeral
//!    X-Wing key pair and registers the ID, the public key, its name and a
//!    MAC under the secret (`POST /cli-logins`, no session). It gets a poll
//!    token; the server keeps only its hash. The secret travels only in the
//!    fragment of the link the user opens (`#/cli-login/{id}#{secret}`), so
//!    the server never sees it.
//! 2. The user opens the link in the web vault, signed in. The browser
//!    fetches the request (`GET /cli-logins/{id}`), checks the MAC and asks
//!    "Was that you?". Approving uploads the account's email, ID and Secret
//!    Key sealed to the ephemeral key (`POST /cli-logins/{id}/approve`);
//!    denying tells the device (`POST /cli-logins/{id}/deny`).
//! 3. The device polls with its token (`POST /cli-logins/poll`) and receives
//!    the answer once (the row is deleted), then asks for the master
//!    password. `POST /cli-logins/cancel` withdraws the request.
//!
//! Requests expire after 10 minutes. Creating is rate limited per IP and
//! globally, with at most a few open requests per IP.

use std::time::Duration;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use passbox_core::{encoding, random};
use serde::{Deserialize, Serialize};

use super::auth::{Session, clean_device_name, hash_token, limit_ip, record_event};
use super::validate;
use crate::db::{Public, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::security::ClientIp;
use crate::state::AppState;

pub(crate) const REQUEST_TTL_MS: i64 = 10 * 60 * 1000;
/// Open requests per IP.
const MAX_OPEN_PER_IP: i64 = 3;
/// New requests per IP and hour.
const MAX_CREATED_PER_IP: u32 = 10;
/// New requests on this server per minute.
const MAX_CREATED_GLOBAL: u32 = 300;
/// Polls per IP and minute (a device polls every two seconds).
const MAX_POLLS_PER_IP: u32 = 120;

fn internal(err: impl Into<anyhow::Error>) -> ApiError {
    ApiError::Internal(err.into())
}

fn gone() -> ApiError {
    ApiError::forbidden(
        "cli_login_expired",
        "the sign-in request expired or was already answered; start it again",
    )
}

fn rate_limited(state: &AppState, key: &str, max: u32, window: Duration) -> ApiResult<()> {
    match state.limiter.hit(key, max, window) {
        Some(wait) => Err(ApiError::RateLimited(wait)),
        None => Ok(()),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRequest {
    id: String,
    ephemeral_key: String,
    mac: String,
    #[serde(default)]
    device_name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateResponse {
    poll_token: String,
    expires_at: i64,
}

/// `POST /cli-logins` (no session): registers a sign-in request.
pub async fn create(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<CreateRequest>,
) -> ApiResult<(StatusCode, Json<CreateResponse>)> {
    limit_ip(&state, &ip)?;
    rate_limited(
        &state,
        "cli-login-global",
        MAX_CREATED_GLOBAL,
        Duration::from_secs(60),
    )?;
    rate_limited(
        &state,
        &format!("cli-login-ip:{ip}"),
        MAX_CREATED_PER_IP,
        Duration::from_secs(3600),
    )?;
    validate::id("id", &req.id)?;
    let ephemeral = validate::base64("ephemeralKey", &req.ephemeral_key, validate::MAX_SMALL_LEN)?;
    if ephemeral.len() != passbox_core::identity::ENC_PK_LEN {
        return Err(ApiError::bad_request("ephemeralKey has the wrong length"));
    }
    if validate::base64("mac", &req.mac, 128)?.len() != 32 {
        return Err(ApiError::bad_request("mac must be 32 bytes"));
    }
    let device_name = clean_device_name(&req.device_name);
    if device_name != req.device_name {
        // The MAC covers the name; the client sends it already cleaned.
        return Err(ApiError::bad_request(
            "deviceName must be at most 80 characters without control characters",
        ));
    }
    let now = now_ms();
    let token = encoding::encode(&random::bytes::<32>().map_err(internal)?);
    let expires_at = now + REQUEST_TTL_MS;
    let mut tx = state.db.public(Public::Auth).await?;
    sqlx::query!("DELETE FROM cli_logins WHERE expires_at <= $1", now)
        .execute(&mut *tx)
        .await?;
    let open: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"count!\" FROM cli_logins WHERE created_ip = $1 AND status = 'pending'",
        &ip,
    )
    .fetch_one(&mut *tx)
    .await?;
    if open >= MAX_OPEN_PER_IP {
        return Err(ApiError::RateLimited(Duration::from_secs(60)));
    }
    let inserted = sqlx::query!(
        "INSERT INTO cli_logins (id, status, ephemeral_key, mac, poll_token_hash, device_name, created_ip, \
         created_at, expires_at) VALUES ($1, 'pending', $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (id) DO NOTHING",
        &req.id,
        &req.ephemeral_key,
        &req.mac,
        hash_token(&token),
        &device_name,
        &ip,
        now,
        expires_at,
    )
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::conflict(
            "a sign-in request with this ID exists",
            serde_json::Value::Null,
        ));
    }
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(CreateResponse {
            poll_token: token,
            expires_at,
        }),
    ))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestView {
    id: String,
    device_name: String,
    ip: String,
    created_at: i64,
    expires_at: i64,
    ephemeral_key: String,
    mac: String,
}

/// `GET /cli-logins/{id}`: a pending request, for the signed-in account
/// that opened its link.
pub async fn get(
    State(state): State<AppState>,
    session: Session,
    Path(request_id): Path<String>,
) -> ApiResult<Json<RequestView>> {
    validate::id("request id", &request_id)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    let row = sqlx::query!(
        r#"SELECT id AS "id!", device_name AS "device_name!", created_ip AS "created_ip!",
           created_at AS "created_at!", expires_at AS "expires_at!",
           ephemeral_key AS "ephemeral_key!", mac AS "mac!"
           FROM passbox.pending_cli_login($1, $2)"#,
        &request_id,
        now_ms(),
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(gone)?;
    tx.commit().await?;
    Ok(Json(RequestView {
        id: row.id,
        device_name: row.device_name,
        ip: row.created_ip,
        created_at: row.created_at,
        expires_at: row.expires_at,
        ephemeral_key: row.ephemeral_key,
        mac: row.mac,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApproveRequest {
    sealed_payload: String,
}

async fn decide(
    state: &AppState,
    session: &Session,
    ip: &str,
    request_id: &str,
    decision: &str,
    sealed: &str,
) -> ApiResult<StatusCode> {
    let mut tx = state.db.as_account(&session.account_id).await?;
    let decided = sqlx::query_scalar!(
        r#"SELECT passbox.decide_cli_login($1, $2, $3, $4, $5) AS "decided!""#,
        request_id,
        decision,
        sealed,
        clean_device_name(&session.device_name),
        now_ms(),
    )
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    if !decided {
        return Err(gone());
    }
    let kind = if decision == "approved" {
        "cli_login_approved"
    } else {
        "cli_login_denied"
    };
    record_event(
        state,
        &session.account_id,
        kind,
        &session.device_name,
        &session.client_kind,
        ip,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /cli-logins/{id}/approve`: the account details, sealed to the
/// requesting device's key.
pub async fn approve(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(request_id): Path<String>,
    Json(req): Json<ApproveRequest>,
) -> ApiResult<StatusCode> {
    validate::id("request id", &request_id)?;
    validate::base64(
        "sealedPayload",
        &req.sealed_payload,
        validate::MAX_SMALL_LEN,
    )?;
    decide(
        &state,
        &session,
        &ip,
        &request_id,
        "approved",
        &req.sealed_payload,
    )
    .await
}

/// `POST /cli-logins/{id}/deny`: the requesting device is told.
pub async fn deny(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(request_id): Path<String>,
) -> ApiResult<StatusCode> {
    validate::id("request id", &request_id)?;
    decide(&state, &session, &ip, &request_id, "denied", "").await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenRequest {
    poll_token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PollResponse {
    /// `pending`, `approved`, `denied` or `expired` (also for unknown,
    /// cancelled or already answered requests).
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    sealed_payload: Option<String>,
    /// The name of the device that approved.
    #[serde(skip_serializing_if = "Option::is_none")]
    approved_by: Option<String>,
}

impl PollResponse {
    fn status(status: &'static str) -> Self {
        Self {
            status,
            sealed_payload: None,
            approved_by: None,
        }
    }
}

fn token_hash(token: &str) -> Option<String> {
    (!token.is_empty() && token.len() <= 128).then(|| hash_token(token))
}

/// `POST /cli-logins/poll` (no session): the requesting device waits. The
/// answer is delivered once; then the request is deleted.
pub async fn poll(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<TokenRequest>,
) -> ApiResult<Json<PollResponse>> {
    rate_limited(
        &state,
        &format!("cli-login-poll-ip:{ip}"),
        MAX_POLLS_PER_IP,
        Duration::from_secs(60),
    )?;
    let Some(hash) = token_hash(&req.poll_token) else {
        return Ok(Json(PollResponse::status("expired")));
    };
    let now = now_ms();
    let mut tx = state.db.public(Public::Auth).await?;
    let Some(row) = sqlx::query!(
        "SELECT status, sealed_payload, approver_device_name, expires_at FROM cli_logins \
         WHERE poll_token_hash = $1",
        &hash,
    )
    .fetch_optional(&mut *tx)
    .await?
    else {
        return Ok(Json(PollResponse::status("expired")));
    };
    let response = match row.status.as_str() {
        _ if row.expires_at <= now => PollResponse::status("expired"),
        "pending" => return Ok(Json(PollResponse::status("pending"))),
        "approved" => PollResponse {
            status: "approved",
            sealed_payload: Some(row.sealed_payload),
            approved_by: Some(row.approver_device_name),
        },
        _ => PollResponse::status("denied"),
    };
    sqlx::query!("DELETE FROM cli_logins WHERE poll_token_hash = $1", &hash)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(response))
}

/// `POST /cli-logins/cancel` (no session): withdraws a request.
pub async fn cancel(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<TokenRequest>,
) -> ApiResult<StatusCode> {
    limit_ip(&state, &ip)?;
    if let Some(hash) = token_hash(&req.poll_token) {
        let mut tx = state.db.public(Public::Auth).await?;
        sqlx::query!("DELETE FROM cli_logins WHERE poll_token_hash = $1", &hash)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    }
    Ok(StatusCode::NO_CONTENT)
}
