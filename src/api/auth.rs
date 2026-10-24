//! Registration, login (OPAQUE) and sessions.

use axum::Json;
use axum::extract::{FromRequestParts, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use data_encoding::HEXLOWER;
use hmac::{Hmac, KeyInit, Mac};
use passbox_core::kdf::{KdfParams, SALT_LEN};
use passbox_core::{encoding, id, opaque, random};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::validate;
use crate::db::{self, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Sessions expire after 30 days.
const SESSION_TTL_MS: i64 = 30 * 24 * 60 * 60 * 1000;
/// A login must be finished within 5 minutes of starting it.
const LOGIN_TTL_MS: i64 = 5 * 60 * 1000;

// --- Prelogin ---------------------------------------------------------------

#[derive(Deserialize)]
pub struct PreloginRequest {
    email: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreloginResponse {
    account_id: String,
    kdf_salt: String,
    kdf_params: KdfParams,
}

/// Returns what a client needs to derive its keys. Unknown emails get stable
/// fake values, so the endpoint does not reveal which accounts exist.
pub async fn prelogin(
    State(state): State<AppState>,
    Json(req): Json<PreloginRequest>,
) -> ApiResult<Json<PreloginResponse>> {
    let email = validate::email(&req.email)?;
    let row: Option<(String, String, i64, i64, i64)> = sqlx::query_as(
        "SELECT id, kdf_salt, kdf_memory_kib, kdf_iterations, kdf_parallelism FROM accounts WHERE email = $1",
    )
    .bind(&email)
    .fetch_optional(&state.db)
    .await?;

    let response = match row {
        Some((account_id, kdf_salt, memory, iterations, parallelism)) => PreloginResponse {
            account_id,
            kdf_salt,
            kdf_params: KdfParams {
                memory_kib: to_u32(memory)?,
                iterations: to_u32(iterations)?,
                parallelism: to_u32(parallelism)?,
            },
        },
        None => PreloginResponse {
            account_id: fake_account_id(&state, &email),
            kdf_salt: encoding::encode(&fake_bytes(&state, "salt", &email)[..SALT_LEN]),
            kdf_params: KdfParams::DEFAULT,
        },
    };
    Ok(Json(response))
}

fn to_u32(value: i64) -> ApiResult<u32> {
    u32::try_from(value)
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("stored KDF parameter out of range")))
}

fn fake_bytes(state: &AppState, purpose: &str, email: &str) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(state.prelogin_key.as_slice())
        .expect("HMAC accepts any key length");
    mac.update(purpose.as_bytes());
    mac.update(b"|");
    mac.update(email.as_bytes());
    mac.finalize().into_bytes().into()
}

fn fake_account_id(state: &AppState, email: &str) -> String {
    let bytes = fake_bytes(state, "account-id", email);
    let mut id_bytes = [0u8; 16];
    id_bytes.copy_from_slice(&bytes[..16]);
    id::from_bytes(id_bytes)
}

// --- Registration -------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterStartRequest {
    account_id: String,
    email: String,
    registration_request: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterStartResponse {
    registration_response: String,
}

pub async fn register_start(
    State(state): State<AppState>,
    Json(req): Json<RegisterStartRequest>,
) -> ApiResult<Json<RegisterStartResponse>> {
    validate::id("accountId", &req.account_id)?;
    let email = validate::email(&req.email)?;
    ensure_account_is_new(&state, &req.account_id, &email).await?;
    let request = validate::base64(
        "registrationRequest",
        &req.registration_request,
        validate::MAX_SMALL_LEN,
    )?;
    let response = state
        .opaque
        .registration_response(&request, req.account_id.as_bytes())
        .map_err(|_| ApiError::bad_request("invalid registrationRequest"))?;
    Ok(Json(RegisterStartResponse {
        registration_response: encoding::encode(&response),
    }))
}

async fn ensure_account_is_new(state: &AppState, account_id: &str, email: &str) -> ApiResult<()> {
    let exists: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM accounts WHERE id = $1 OR email = $2")
            .bind(account_id)
            .bind(email)
            .fetch_optional(&state.db)
            .await?;
    match exists {
        Some(_) => Err(ApiError::conflict(
            "an account with this email already exists",
            serde_json::Value::Null,
        )),
        None => Ok(()),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewVaultRequest {
    pub id: String,
    pub encrypted_key: String,
    pub encrypted_meta: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterFinishRequest {
    account_id: String,
    email: String,
    registration_upload: String,
    kdf_salt: String,
    kdf_params: KdfParams,
    encrypted_account_key: String,
    /// The account's first (personal) vault.
    vault: NewVaultRequest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterFinishResponse {
    account_id: String,
}

pub async fn register_finish(
    State(state): State<AppState>,
    Json(req): Json<RegisterFinishRequest>,
) -> ApiResult<(StatusCode, Json<RegisterFinishResponse>)> {
    validate::id("accountId", &req.account_id)?;
    let email = validate::email(&req.email)?;
    validate::kdf(&req.kdf_salt, &req.kdf_params)?;
    validate::base64(
        "encryptedAccountKey",
        &req.encrypted_account_key,
        validate::MAX_SMALL_LEN,
    )?;
    super::vaults::validate_new_vault(&req.vault)?;
    let upload = validate::base64(
        "registrationUpload",
        &req.registration_upload,
        validate::MAX_SMALL_LEN,
    )?;
    let record = opaque::registration_record(&upload)
        .map_err(|_| ApiError::bad_request("invalid registrationUpload"))?;

    let now = now_ms();
    let mut tx = state.db.begin().await?;
    let inserted = sqlx::query(
        "INSERT INTO accounts (id, email, opaque_record, kdf_salt, kdf_memory_kib, kdf_iterations, \
         kdf_parallelism, encrypted_account_key, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT DO NOTHING",
    )
    .bind(&req.account_id)
    .bind(&email)
    .bind(encoding::encode(&record))
    .bind(&req.kdf_salt)
    .bind(i64::from(req.kdf_params.memory_kib))
    .bind(i64::from(req.kdf_params.iterations))
    .bind(i64::from(req.kdf_params.parallelism))
    .bind(&req.encrypted_account_key)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::conflict(
            "an account with this email already exists",
            serde_json::Value::Null,
        ));
    }
    super::vaults::insert_vault(&mut tx, &req.account_id, &req.vault, now).await?;
    tx.commit().await?;

    tracing::info!(account_id = %req.account_id, "account registered");
    Ok((
        StatusCode::CREATED,
        Json(RegisterFinishResponse {
            account_id: req.account_id,
        }),
    ))
}

// --- Login ----------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginStartRequest {
    email: String,
    credential_request: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginStartResponse {
    login_id: String,
    credential_response: String,
}

pub async fn login_start(
    State(state): State<AppState>,
    Json(req): Json<LoginStartRequest>,
) -> ApiResult<Json<LoginStartResponse>> {
    let email = validate::email(&req.email)?;
    let request = validate::base64(
        "credentialRequest",
        &req.credential_request,
        validate::MAX_SMALL_LEN,
    )?;
    let account: Option<(String, String)> =
        sqlx::query_as("SELECT id, opaque_record FROM accounts WHERE email = $1")
            .bind(&email)
            .fetch_optional(&state.db)
            .await?;

    let (account_id, record, credential_id) = match account {
        Some((id, record)) => {
            let record = encoding::decode(&record).map_err(|e| ApiError::Internal(e.into()))?;
            (Some(id.clone()), Some(record), id)
        }
        // Unknown emails run the protocol against a fake identity, so the
        // response looks like a real one.
        None => (None, None, fake_account_id(&state, &email)),
    };
    let (login_state, response) = state
        .opaque
        .start_login(record.as_deref(), &request, credential_id.as_bytes())
        .map_err(|_| ApiError::bad_request("invalid credentialRequest"))?;

    let login_id = id::new_id().map_err(|e| ApiError::Internal(e.into()))?;
    let now = now_ms();
    sqlx::query("DELETE FROM login_attempts WHERE expires_at < $1")
        .bind(now)
        .execute(&state.db)
        .await?;
    sqlx::query(
        "INSERT INTO login_attempts (id, account_id, state, expires_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(&login_id)
    .bind(account_id)
    .bind(encoding::encode(&login_state))
    .bind(now + LOGIN_TTL_MS)
    .execute(&state.db)
    .await?;

    Ok(Json(LoginStartResponse {
        login_id,
        credential_response: encoding::encode(&response),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginFinishRequest {
    login_id: String,
    credential_finalization: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginFinishResponse {
    token: String,
    account_id: String,
    expires_at: i64,
}

pub async fn login_finish(
    State(state): State<AppState>,
    Json(req): Json<LoginFinishRequest>,
) -> ApiResult<Json<LoginFinishResponse>> {
    validate::id("loginId", &req.login_id)?;
    let finalization = validate::base64(
        "credentialFinalization",
        &req.credential_finalization,
        validate::MAX_SMALL_LEN,
    )?;

    // Each attempt can be finished once, successful or not.
    let attempt: Option<(Option<String>, String, i64)> = sqlx::query_as(
        "DELETE FROM login_attempts WHERE id = $1 RETURNING account_id, state, expires_at",
    )
    .bind(&req.login_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((account_id, login_state, expires_at)) = attempt else {
        return Err(ApiError::InvalidCredentials);
    };
    let now = now_ms();
    let login_state = encoding::decode(&login_state).map_err(|e| ApiError::Internal(e.into()))?;
    let verified = opaque::finish_login(&login_state, &finalization).is_ok();
    let account_id = match account_id {
        Some(id) if verified && expires_at >= now => id,
        _ => {
            tracing::info!("failed login");
            return Err(ApiError::InvalidCredentials);
        }
    };

    let token = encoding::encode(&random::bytes::<32>().map_err(|e| ApiError::Internal(e.into()))?);
    let expires_at = now + SESSION_TTL_MS;
    sqlx::query("INSERT INTO sessions (token_hash, account_id, created_at, expires_at) VALUES ($1, $2, $3, $4)")
        .bind(hash_token(&token))
        .bind(&account_id)
        .bind(now)
        .bind(expires_at)
        .execute(&state.db)
        .await?;
    tracing::info!(account_id = %account_id, "login");

    Ok(Json(LoginFinishResponse {
        token,
        account_id,
        expires_at,
    }))
}

pub async fn logout(State(state): State<AppState>, session: Session) -> ApiResult<StatusCode> {
    sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
        .bind(&session.token_hash)
        .execute(&state.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Account ----------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountResponse {
    account_id: String,
    email: String,
    kdf_salt: String,
    kdf_params: KdfParams,
    encrypted_account_key: String,
}

pub async fn account(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<Json<AccountResponse>> {
    let (email, kdf_salt, memory, iterations, parallelism, encrypted_account_key): (
        String,
        String,
        i64,
        i64,
        i64,
        String,
    ) = sqlx::query_as(
        "SELECT email, kdf_salt, kdf_memory_kib, kdf_iterations, kdf_parallelism, encrypted_account_key \
         FROM accounts WHERE id = $1",
    )
    .bind(&session.account_id)
    .fetch_one(&state.db)
    .await?;
    Ok(Json(AccountResponse {
        account_id: session.account_id,
        email,
        kdf_salt,
        kdf_params: KdfParams {
            memory_kib: to_u32(memory)?,
            iterations: to_u32(iterations)?,
            parallelism: to_u32(parallelism)?,
        },
        encrypted_account_key,
    }))
}

// --- Session extractor ----------------------------------------------------------

/// An authenticated request. Extracting it fails with 401 unless the request
/// carries a valid `Authorization: Bearer <token>` header.
pub struct Session {
    pub account_id: String,
    token_hash: String,
}

fn hash_token(token: &str) -> String {
    HEXLOWER.encode(&Sha256::digest(token.as_bytes()))
}

impl FromRequestParts<AppState> for Session {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(ApiError::Unauthorized)?;
        let token = header
            .strip_prefix("Bearer ")
            .ok_or(ApiError::Unauthorized)?;
        if token.is_empty() || token.len() > 128 {
            return Err(ApiError::Unauthorized);
        }
        let token_hash = hash_token(token);
        let account_id: Option<String> = sqlx::query_scalar(
            "SELECT account_id FROM sessions WHERE token_hash = $1 AND expires_at > $2",
        )
        .bind(&token_hash)
        .bind(db::now_ms())
        .fetch_optional(&state.db)
        .await?;
        account_id
            .map(|account_id| Session {
                account_id,
                token_hash,
            })
            .ok_or(ApiError::Unauthorized)
    }
}
