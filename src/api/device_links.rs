//! Adding a device with a code (wave C4).
//!
//! 1. A signed-in device opens a link (`POST /device-links`) and shows the
//!    server's 4-character short ID plus a secret the server never sees.
//! 2. The new device claims the link with its ephemeral public key and a
//!    MAC under that secret (`POST /device-links/claim`, no session) and
//!    gets a claim token.
//! 3. The signed-in device polls the link, checks the MAC, shows the new
//!    device's name and, once the user approves, uploads the account's
//!    email, ID and Secret Key sealed to the ephemeral key.
//! 4. The new device polls with its claim token, receives the sealed
//!    payload once (the link is deleted) and asks for the master password.
//!
//! Links expire after 10 minutes.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use passbox_core::device_link::{self, is_short_id};
use passbox_core::{encoding, id, random};
use serde::{Deserialize, Serialize};

use super::auth::{Session, clean_device_name, hash_token, limit_ip, record_event};
use super::validate;
use crate::db::{self, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::security::ClientIp;
use crate::state::AppState;

const LINK_TTL_MS: i64 = 10 * 60 * 1000;
const MAX_OPEN_LINKS: i64 = 5;
/// Claims per IP and minute (a claim needs the code, which has a 60-bit secret).
const MAX_CLAIMS_PER_IP: u32 = 10;

fn internal(err: impl Into<anyhow::Error>) -> ApiError {
    ApiError::Internal(err.into())
}

fn gone() -> ApiError {
    ApiError::forbidden(
        "device_link_expired",
        "the code expired or was already used; show a new code on your other device",
    )
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateResponse {
    id: String,
    short_id: String,
    expires_at: i64,
}

/// `POST /device-links`: opens a link on the signed-in device.
pub async fn create(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
) -> ApiResult<(StatusCode, Json<CreateResponse>)> {
    let now = now_ms();
    let mut tx = db::begin_write(&state.db).await?;
    sqlx::query("DELETE FROM device_links WHERE expires_at < $1")
        .bind(now)
        .execute(&mut *tx)
        .await?;
    let open: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_links WHERE account_id = $1")
        .bind(&session.account_id)
        .fetch_one(&mut *tx)
        .await?;
    if open >= MAX_OPEN_LINKS {
        return Err(ApiError::bad_request(
            "too many open codes; wait a few minutes",
        ));
    }
    let mut short_id = String::new();
    for _ in 0..20 {
        let candidate = device_link::new_short_id().map_err(internal)?;
        let taken: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM device_links WHERE short_id = $1")
                .bind(&candidate)
                .fetch_optional(&mut *tx)
                .await?;
        if taken.is_none() {
            short_id = candidate;
            break;
        }
    }
    if short_id.is_empty() {
        return Err(internal(anyhow::anyhow!("no free short ID")));
    }
    let link_id = id::new_id().map_err(internal)?;
    let expires_at = now + LINK_TTL_MS;
    sqlx::query(
        "INSERT INTO device_links (id, account_id, short_id, status, ephemeral_key, mac, claim_token_hash, \
         claim_device_name, claim_ip, claimed_at, sealed_payload, created_at, expires_at) \
         VALUES ($1, $2, $3, 'open', '', '', '', '', '', 0, '', $4, $5)",
    )
    .bind(&link_id)
    .bind(&session.account_id)
    .bind(&short_id)
    .bind(now)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    record_event(
        &state,
        &session.account_id,
        "device_link_created",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(CreateResponse {
            id: link_id,
            short_id,
            expires_at,
        }),
    ))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkView {
    /// `open`, `claimed` or `approved`.
    status: String,
    expires_at: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    ephemeral_key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    mac: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    ip: String,
    claimed_at: i64,
}

/// `GET /device-links/{id}`: the signed-in device polls its link.
pub async fn get(
    State(state): State<AppState>,
    session: Session,
    Path(link_id): Path<String>,
) -> ApiResult<Json<LinkView>> {
    validate::id("link id", &link_id)?;
    let row: Option<(String, i64, String, String, String, String, i64)> = sqlx::query_as(
        "SELECT status, expires_at, ephemeral_key, mac, claim_device_name, claim_ip, claimed_at \
         FROM device_links WHERE id = $1 AND account_id = $2 AND expires_at > $3",
    )
    .bind(&link_id)
    .bind(&session.account_id)
    .bind(now_ms())
    .fetch_optional(&state.db)
    .await?;
    let (status, expires_at, ephemeral_key, mac, device_name, ip, claimed_at) =
        row.ok_or_else(gone)?;
    Ok(Json(LinkView {
        status,
        expires_at,
        ephemeral_key,
        mac,
        device_name,
        ip,
        claimed_at,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApproveRequest {
    sealed_payload: String,
}

/// `POST /device-links/{id}/approve`: the sealed account details.
pub async fn approve(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(link_id): Path<String>,
    Json(req): Json<ApproveRequest>,
) -> ApiResult<StatusCode> {
    validate::id("link id", &link_id)?;
    validate::base64(
        "sealedPayload",
        &req.sealed_payload,
        validate::MAX_SMALL_LEN,
    )?;
    let updated = sqlx::query(
        "UPDATE device_links SET status = 'approved', sealed_payload = $1 WHERE id = $2 AND account_id = $3 \
         AND status = 'claimed' AND expires_at > $4",
    )
    .bind(&req.sealed_payload)
    .bind(&link_id)
    .bind(&session.account_id)
    .bind(now_ms())
    .execute(&state.db)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(gone());
    }
    record_event(
        &state,
        &session.account_id,
        "device_link_approved",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /device-links/{id}`: cancels a link.
pub async fn delete(
    State(state): State<AppState>,
    session: Session,
    Path(link_id): Path<String>,
) -> ApiResult<StatusCode> {
    validate::id("link id", &link_id)?;
    sqlx::query("DELETE FROM device_links WHERE id = $1 AND account_id = $2")
        .bind(&link_id)
        .bind(&session.account_id)
        .execute(&state.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimRequest {
    short_id: String,
    ephemeral_key: String,
    mac: String,
    #[serde(default)]
    device_name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimResponse {
    claim_token: String,
    expires_at: i64,
}

/// `POST /device-links/claim` (no session): the new device answers the code.
pub async fn claim(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<ClaimRequest>,
) -> ApiResult<Json<ClaimResponse>> {
    limit_ip(&state, &ip)?;
    if let Some(wait) = state.limiter.hit(
        &format!("device-claim-ip:{ip}"),
        MAX_CLAIMS_PER_IP,
        std::time::Duration::from_secs(60),
    ) {
        return Err(ApiError::RateLimited(wait));
    }
    let short_id = req.short_id.to_ascii_uppercase();
    if !is_short_id(&short_id) {
        return Err(gone());
    }
    let ephemeral = validate::base64("ephemeralKey", &req.ephemeral_key, validate::MAX_SMALL_LEN)?;
    if ephemeral.len() != passbox_core::identity::ENC_PK_LEN {
        return Err(ApiError::bad_request("ephemeralKey has the wrong length"));
    }
    if validate::base64("mac", &req.mac, 128)?.len() != 32 {
        return Err(ApiError::bad_request("mac must be 32 bytes"));
    }
    let token = encoding::encode(&random::bytes::<32>().map_err(internal)?);
    let now = now_ms();
    // The first claim wins; a second device (or a guess) gets "expired".
    let updated = sqlx::query(
        "UPDATE device_links SET status = 'claimed', ephemeral_key = $1, mac = $2, claim_token_hash = $3, \
         claim_device_name = $4, claim_ip = $5, claimed_at = $6 WHERE short_id = $7 AND status = 'open' \
         AND expires_at > $8",
    )
    .bind(&req.ephemeral_key)
    .bind(&req.mac)
    .bind(hash_token(&token))
    .bind(clean_device_name(&req.device_name))
    .bind(&ip)
    .bind(now)
    .bind(&short_id)
    .bind(now)
    .execute(&state.db)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(gone());
    }
    let expires_at: i64 =
        sqlx::query_scalar("SELECT expires_at FROM device_links WHERE claim_token_hash = $1")
            .bind(hash_token(&token))
            .fetch_one(&state.db)
            .await?;
    Ok(Json(ClaimResponse {
        claim_token: token,
        expires_at,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PollRequest {
    claim_token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PollResponse {
    /// `claimed` (waiting for approval) or `approved`.
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sealed_payload: Option<String>,
}

/// `POST /device-links/poll` (no session): the new device waits for the
/// approval. The sealed payload is delivered once.
pub async fn poll(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<PollRequest>,
) -> ApiResult<Json<PollResponse>> {
    limit_ip(&state, &ip)?;
    if req.claim_token.is_empty() || req.claim_token.len() > 128 {
        return Err(gone());
    }
    let token_hash = hash_token(&req.claim_token);
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT status, sealed_payload FROM device_links WHERE claim_token_hash = $1 AND expires_at > $2",
    )
    .bind(&token_hash)
    .bind(now_ms())
    .fetch_optional(&state.db)
    .await?;
    let (status, sealed) = row.ok_or_else(gone)?;
    if status != "approved" {
        return Ok(Json(PollResponse {
            status,
            sealed_payload: None,
        }));
    }
    sqlx::query("DELETE FROM device_links WHERE claim_token_hash = $1")
        .bind(&token_hash)
        .execute(&state.db)
        .await?;
    Ok(Json(PollResponse {
        status,
        sealed_payload: Some(sealed),
    }))
}
