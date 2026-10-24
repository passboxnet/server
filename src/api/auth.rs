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
use crate::security::ClientIp;
use crate::state::AppState;

/// Requests to authentication endpoints per client IP and minute.
const AUTH_REQUESTS_PER_MINUTE: u32 = 60;
/// Failed logins within the lockout window per (email, IP) pair for unknown
/// devices, and per device token for known devices.
const MAX_FAILED_LOGINS: u32 = 10;
/// Failed logins per email from unknown devices within the lockout window, a
/// backstop against guessing from many addresses. Devices with a valid
/// device token are exempt, so reaching it does not lock out the user.
const MAX_FAILED_LOGINS_PER_EMAIL: u32 = 50;
/// Failed logins per IP within the lockout window. Higher, because many
/// people can share one address (offices, mobile carriers).
const MAX_FAILED_LOGINS_PER_IP: u32 = 100;
const LOCKOUT_WINDOW: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// Device tokens are valid for a year after they were issued. Each
/// successful login replaces the presented token with a new one.
const DEVICE_TOKEN_TTL_MS: i64 = 365 * 24 * 60 * 60 * 1000;
/// Device tokens beyond this many per account are deleted, oldest first.
const MAX_DEVICE_TOKENS_PER_ACCOUNT: i64 = 50;

/// Throttles authentication requests from one IP address.
fn limit_ip(state: &AppState, ip: &str) -> ApiResult<()> {
    match state.limiter.hit(
        &format!("auth-ip:{ip}"),
        AUTH_REQUESTS_PER_MINUTE,
        std::time::Duration::from_secs(60),
    ) {
        Some(wait) => Err(ApiError::RateLimited(wait)),
        None => Ok(()),
    }
}

/// The failure counters that apply to a login, with their limits.
///
/// A login with a valid device token (`device_token_hash`) counts against
/// that token and the IP only. Without one it counts against the
/// (email, IP) pair, the email as a whole (backstop) and the IP. So an
/// attacker who knows an email locks out only their own address and, once
/// the backstop is reached, new devices; devices that signed in before keep
/// working.
fn failure_limits(email: &str, ip: &str, device_token_hash: Option<&str>) -> Vec<(String, u32)> {
    let mut limits = match device_token_hash {
        Some(hash) => vec![(format!("fail-device:{hash}"), MAX_FAILED_LOGINS)],
        None => vec![
            (format!("fail-email-ip:{email} {ip}"), MAX_FAILED_LOGINS),
            (format!("fail-email:{email}"), MAX_FAILED_LOGINS_PER_EMAIL),
        ],
    };
    limits.push((format!("fail-ip:{ip}"), MAX_FAILED_LOGINS_PER_IP));
    limits
}

/// Fails while any of the login's failure counters is exhausted. The error
/// carries the longest remaining wait of the current windows, so clients
/// know when to retry.
fn check_lockout(state: &AppState, limits: &[(String, u32)]) -> ApiResult<()> {
    let wait = limits
        .iter()
        .filter_map(|(key, max)| state.limiter.blocked(key, *max, LOCKOUT_WINDOW))
        .max();
    match wait {
        Some(wait) => Err(ApiError::RateLimited(wait)),
        None => Ok(()),
    }
}

fn record_failure(state: &AppState, limits: &[(String, u32)]) {
    for (key, max) in limits {
        state.limiter.hit(key, *max, LOCKOUT_WINDOW);
    }
}

// --- Device tokens -------------------------------------------------------------
//
// A device token is an opaque random value the server hands out on every
// successful login. It proves that a device signed in successfully before
// and only exempts that device from the per-email lockout; it grants no
// access by itself. The server stores SHA-256 hashes only.
//
// - Each successful login replaces the token it was started with (rotation),
//   so a device holds exactly one current token.
// - Logging out, locking or revoking a session keeps the token: the device
//   still is a device that knew the password.
// - A master password change deletes every token of the account except the
//   one issued with the session that made the change.
// - Tokens expire a year after they were issued; at most
//   `MAX_DEVICE_TOKENS_PER_ACCOUNT` are kept per account.

/// Returns the hash of `token` if it is a valid device token of the account
/// with `email`. Unknown, expired or foreign tokens are ignored (the login
/// counts as coming from an unknown device), never an error.
async fn valid_device_token(
    state: &AppState,
    email: &str,
    token: Option<&str>,
) -> ApiResult<Option<String>> {
    let Some(token) = token.filter(|t| !t.is_empty() && t.len() <= 128) else {
        return Ok(None);
    };
    let token_hash = hash_token(token);
    let found: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM device_tokens d JOIN accounts a ON a.id = d.account_id \
         WHERE d.token_hash = $1 AND a.email = $2 AND d.expires_at > $3",
    )
    .bind(&token_hash)
    .bind(email)
    .bind(now_ms())
    .fetch_optional(&state.db)
    .await?;
    Ok(found.map(|_| token_hash))
}

/// Issues a new device token after a successful login and returns it with
/// its hash. The token the login was started with is deleted. If the
/// response gets lost, the device counts as unknown until its next
/// successful login.
async fn issue_device_token(
    state: &AppState,
    account_id: &str,
    previous_hash: Option<&str>,
    now: i64,
) -> ApiResult<(String, String)> {
    let token = encoding::encode(&random::bytes::<32>().map_err(|e| ApiError::Internal(e.into()))?);
    let token_hash = hash_token(&token);
    let mut tx = crate::db::begin_write(&state.db).await?;
    sqlx::query(
        "DELETE FROM device_tokens WHERE account_id = $1 AND (expires_at <= $2 OR token_hash = $3)",
    )
    .bind(account_id)
    .bind(now)
    .bind(previous_hash.unwrap_or(""))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO device_tokens (token_hash, account_id, created_at, expires_at) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(&token_hash)
    .bind(account_id)
    .bind(now)
    .bind(now + DEVICE_TOKEN_TTL_MS)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "DELETE FROM device_tokens WHERE account_id = $1 AND token_hash NOT IN \
         (SELECT token_hash FROM device_tokens WHERE account_id = $2 \
         ORDER BY created_at DESC, token_hash LIMIT $3)",
    )
    .bind(account_id)
    .bind(account_id)
    .bind(MAX_DEVICE_TOKENS_PER_ACCOUNT)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((token, token_hash))
}

/// Records an entry in the account's activity log.
pub async fn record_event(
    state: &AppState,
    account_id: &str,
    kind: &str,
    device_name: &str,
    client_kind: &str,
    ip: &str,
) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO account_events (id, account_id, kind, device_name, client_kind, ip, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id::new_id().map_err(|e| ApiError::Internal(e.into()))?)
    .bind(account_id)
    .bind(kind)
    .bind(device_name)
    .bind(client_kind)
    .bind(ip)
    .bind(now_ms())
    .execute(&state.db)
    .await?;
    Ok(())
}

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
    ClientIp(ip): ClientIp,
    Json(req): Json<PreloginRequest>,
) -> ApiResult<Json<PreloginResponse>> {
    limit_ip(&state, &ip)?;
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
    ClientIp(ip): ClientIp,
    Json(req): Json<RegisterStartRequest>,
) -> ApiResult<Json<RegisterStartResponse>> {
    limit_ip(&state, &ip)?;
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
    ClientIp(ip): ClientIp,
    Json(req): Json<RegisterFinishRequest>,
) -> ApiResult<(StatusCode, Json<RegisterFinishResponse>)> {
    limit_ip(&state, &ip)?;
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
    let mut tx = crate::db::begin_write(&state.db).await?;
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
    record_event(&state, &req.account_id, "account_created", "", "", &ip).await?;
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
    /// The device token from this device's last successful login, if any.
    #[serde(default)]
    device_token: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginStartResponse {
    login_id: String,
    credential_response: String,
}

pub async fn login_start(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<LoginStartRequest>,
) -> ApiResult<Json<LoginStartResponse>> {
    limit_ip(&state, &ip)?;
    let email = validate::email(&req.email)?;
    let device_token_hash = valid_device_token(&state, &email, req.device_token.as_deref()).await?;
    check_lockout(
        &state,
        &failure_limits(&email, &ip, device_token_hash.as_deref()),
    )?;
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
        "INSERT INTO login_attempts (id, account_id, state, expires_at, ip, email, device_token_hash) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&login_id)
    .bind(account_id)
    .bind(encoding::encode(&login_state))
    .bind(now + LOGIN_TTL_MS)
    .bind(&ip)
    .bind(&email)
    .bind(device_token_hash.unwrap_or_default())
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
    /// Shown in the user's device list, for example "Chrome on macOS".
    #[serde(default)]
    device_name: String,
    /// web, extension, desktop, ios, android or cli.
    #[serde(default)]
    client_kind: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginFinishResponse {
    token: String,
    account_id: String,
    session_id: String,
    expires_at: i64,
    /// Store it on the device and send it with the next `login/start`. It
    /// replaces the device token the login was started with.
    device_token: String,
}

const CLIENT_KINDS: [&str; 6] = ["web", "extension", "desktop", "ios", "android", "cli"];

fn clean_device_name(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_control())
        .take(80)
        .collect::<String>()
        .trim()
        .to_owned()
}

pub async fn login_finish(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<LoginFinishRequest>,
) -> ApiResult<Json<LoginFinishResponse>> {
    validate::id("loginId", &req.login_id)?;
    let finalization = validate::base64(
        "credentialFinalization",
        &req.credential_finalization,
        validate::MAX_SMALL_LEN,
    )?;
    let device_name = clean_device_name(&req.device_name);
    let client_kind = if CLIENT_KINDS.contains(&req.client_kind.as_str()) {
        req.client_kind.clone()
    } else {
        String::new()
    };

    // Each attempt can be finished once, successful or not.
    let attempt: Option<(Option<String>, String, i64, String, String)> = sqlx::query_as(
        "DELETE FROM login_attempts WHERE id = $1 \
         RETURNING account_id, state, expires_at, email, device_token_hash",
    )
    .bind(&req.login_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((account_id, login_state, expires_at, email, device_token_hash)) = attempt else {
        return Err(ApiError::InvalidCredentials);
    };
    let device_token_hash = Some(device_token_hash.as_str()).filter(|h| !h.is_empty());
    let now = now_ms();
    let login_state = encoding::decode(&login_state).map_err(|e| ApiError::Internal(e.into()))?;
    let verified = opaque::finish_login(&login_state, &finalization).is_ok();
    let account_id = match account_id {
        Some(id) if verified && expires_at >= now => id,
        known => {
            tracing::info!("failed login");
            record_failure(&state, &failure_limits(&email, &ip, device_token_hash));
            if let Some(account_id) = known {
                record_event(
                    &state,
                    &account_id,
                    "login_failed",
                    &device_name,
                    &client_kind,
                    &ip,
                )
                .await?;
            }
            return Err(ApiError::InvalidCredentials);
        }
    };

    let token = encoding::encode(&random::bytes::<32>().map_err(|e| ApiError::Internal(e.into()))?);
    let session_id = id::new_id().map_err(|e| ApiError::Internal(e.into()))?;
    let expires_at = now + SESSION_TTL_MS;
    let (device_token, new_device_token_hash) =
        issue_device_token(&state, &account_id, device_token_hash, now).await?;
    sqlx::query(
        "INSERT INTO sessions (token_hash, account_id, created_at, expires_at, id, device_name, client_kind, ip, \
         last_used_at, device_token_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(hash_token(&token))
    .bind(&account_id)
    .bind(now)
    .bind(expires_at)
    .bind(&session_id)
    .bind(&device_name)
    .bind(&client_kind)
    .bind(&ip)
    .bind(now)
    .bind(&new_device_token_hash)
    .execute(&state.db)
    .await?;
    record_event(
        &state,
        &account_id,
        "login",
        &device_name,
        &client_kind,
        &ip,
    )
    .await?;
    tracing::info!(account_id = %account_id, "login");

    Ok(Json(LoginFinishResponse {
        token,
        account_id,
        session_id,
        expires_at,
        device_token,
    }))
}

pub async fn logout(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
) -> ApiResult<StatusCode> {
    sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
        .bind(&session.token_hash)
        .execute(&state.db)
        .await?;
    record_event(
        &state,
        &session.account_id,
        "logout",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
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
    /// Public ID of the session, shown in the device list.
    pub id: String,
    pub device_name: String,
    pub client_kind: String,
    /// When the session was created by a full login (Unix ms).
    pub created_at: i64,
    token_hash: String,
}

impl Session {
    pub(crate) fn token_hash(&self) -> &str {
        &self.token_hash
    }
}

/// `last_used_at` is updated at most this often per session.
const LAST_USED_RESOLUTION_MS: i64 = 60_000;

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
        let now = db::now_ms();
        let row: Option<(String, String, String, String, i64, i64)> = sqlx::query_as(
            "SELECT account_id, id, device_name, client_kind, created_at, last_used_at FROM sessions \
             WHERE token_hash = $1 AND expires_at > $2",
        )
        .bind(&token_hash)
        .bind(now)
        .fetch_optional(&state.db)
        .await?;
        let (account_id, id, device_name, client_kind, created_at, last_used_at) =
            row.ok_or(ApiError::Unauthorized)?;
        if now - last_used_at > LAST_USED_RESOLUTION_MS {
            sqlx::query("UPDATE sessions SET last_used_at = $1 WHERE token_hash = $2")
                .bind(now)
                .bind(&token_hash)
                .execute(&state.db)
                .await?;
        }
        Ok(Session {
            account_id,
            id,
            device_name,
            client_kind,
            created_at,
            token_hash,
        })
    }
}
