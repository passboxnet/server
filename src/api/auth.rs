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
use crate::db::{self, Conn, Public, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::security::ClientIp;
use crate::state::AppState;

/// Requests to authentication endpoints per client IP and minute.
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
pub(crate) const LOCKOUT_WINDOW: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// Device tokens are valid for a year after they were issued. Each
/// successful login replaces the presented token with a new one.
const DEVICE_TOKEN_TTL_MS: i64 = 365 * 24 * 60 * 60 * 1000;
/// Device tokens beyond this many per account are deleted, oldest first.
const MAX_DEVICE_TOKENS_PER_ACCOUNT: i64 = 50;

/// Throttles authentication requests from one IP address.
pub(crate) fn limit_ip(state: &AppState, ip: &str) -> ApiResult<()> {
    match state.limiter.hit(
        &format!("auth-ip:{ip}"),
        state.auth_rate_limit,
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
pub(crate) fn check_lockout(state: &AppState, limits: &[(String, u32)]) -> ApiResult<()> {
    let wait = limits
        .iter()
        .filter_map(|(key, max)| state.limiter.blocked(key, *max, LOCKOUT_WINDOW))
        .max();
    match wait {
        Some(wait) => Err(ApiError::RateLimited(wait)),
        None => Ok(()),
    }
}

pub(crate) fn record_failure(state: &AppState, limits: &[(String, u32)]) {
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
    conn: &mut Conn,
    email: &str,
    token: Option<&str>,
) -> ApiResult<Option<String>> {
    let Some(token) = token.filter(|t| !t.is_empty() && t.len() <= 128) else {
        return Ok(None);
    };
    let token_hash = hash_token(token);
    let found = sqlx::query_scalar!(
        r#"SELECT 1 AS "found!" FROM device_tokens d JOIN accounts a ON a.id = d.account_id
           WHERE d.token_hash = $1 AND a.email = $2 AND d.expires_at > $3"#,
        token_hash,
        email,
        now_ms(),
    )
    .fetch_optional(conn)
    .await?;
    Ok(found.map(|_| token_hash))
}

/// Issues a new device token after a successful login and returns it with
/// its hash. The token the login was started with is deleted; whether the
/// device is remembered for two-factor authentication carries over to the
/// new token, and `remember_until` extends it. If the response gets lost,
/// the device counts as unknown until its next successful login.
async fn issue_device_token(
    state: &AppState,
    account_id: &str,
    previous_hash: Option<&str>,
    remember_until: i64,
    now: i64,
) -> ApiResult<(String, String)> {
    let token = encoding::encode(&random::bytes::<32>().map_err(|e| ApiError::Internal(e.into()))?);
    let token_hash = hash_token(&token);
    let previous_hash = previous_hash.unwrap_or("");
    let mut tx = state.db.as_account(account_id).await?;
    let carried = sqlx::query!(
        "SELECT two_factor_until, sso_until FROM device_tokens WHERE token_hash = $1 AND account_id = $2 \
         AND expires_at > $3",
        previous_hash,
        account_id,
        now,
    )
    .fetch_optional(&mut *tx)
    .await?;
    let (carried_two_factor, sso_until) = carried
        .map(|row| (row.two_factor_until, row.sso_until))
        .unwrap_or((0, 0));
    let two_factor_until = carried_two_factor.max(remember_until);
    sqlx::query!(
        "DELETE FROM device_tokens WHERE account_id = $1 AND (expires_at <= $2 OR token_hash = $3)",
        account_id,
        now,
        previous_hash,
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!(
        "INSERT INTO device_tokens (token_hash, account_id, created_at, expires_at, two_factor_until, sso_until) \
         VALUES ($1, $2, $3, $4, $5, $6)",
        token_hash,
        account_id,
        now,
        now + DEVICE_TOKEN_TTL_MS,
        two_factor_until,
        sso_until,
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!(
        "DELETE FROM device_tokens WHERE account_id = $1 AND token_hash NOT IN \
         (SELECT token_hash FROM device_tokens WHERE account_id = $1 \
         ORDER BY created_at DESC, token_hash LIMIT $2)",
        account_id,
        MAX_DEVICE_TOKENS_PER_ACCOUNT,
    )
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
    // The log belongs to the account, also for failed sign-ins of others.
    let mut tx = state.db.as_account(account_id).await?;
    sqlx::query!(
        "INSERT INTO account_events (id, account_id, kind, device_name, client_kind, ip, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
        id::new_id().map_err(|e| ApiError::Internal(e.into()))?,
        account_id,
        kind,
        device_name,
        client_kind,
        ip,
        now_ms(),
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    // Organizations log their members' sign-ins and security changes in
    // their audit log.
    super::org_audit::mirror_account_event(state, account_id, kind, device_name, client_kind, ip)
        .await;
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
    let mut tx = state.db.public(Public::Auth).await?;
    let row = sqlx::query!(
        "SELECT id, kdf_salt, kdf_memory_kib, kdf_iterations, kdf_parallelism FROM accounts WHERE email = $1",
        email
    )
    .fetch_optional(&mut *tx)
    .await?;

    let response = match row {
        Some(row) => PreloginResponse {
            account_id: row.id,
            kdf_salt: encoding::encode(&row.kdf_salt),
            kdf_params: KdfParams {
                memory_kib: to_u32(row.kdf_memory_kib)?,
                iterations: to_u32(row.kdf_iterations)?,
                parallelism: to_u32(row.kdf_parallelism)?,
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

pub(crate) fn fake_account_id(state: &AppState, email: &str) -> String {
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
    /// Token from an invitation link; needed when registration is not open.
    #[serde(default)]
    invite_token: Option<String>,
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
    let mut tx = state.db.public(Public::Auth).await?;
    ensure_account_is_new(&mut tx, &req.account_id, &email).await?;
    crate::instance::check_registration(&state, &mut tx, &email, req.invite_token.as_deref())
        .await?;
    drop(tx);
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

async fn ensure_account_is_new(conn: &mut Conn, account_id: &str, email: &str) -> ApiResult<()> {
    let exists = sqlx::query_scalar!(
        r#"SELECT 1 AS "exists!" FROM accounts WHERE id = $1 OR email = $2"#,
        account_id,
        email,
    )
    .fetch_optional(conn)
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
    #[serde(default)]
    invite_token: Option<String>,
    /// Language for mails (`en`, `de`); defaults to `Accept-Language`.
    #[serde(default)]
    locale: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterFinishResponse {
    account_id: String,
}

pub async fn register_finish(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: axum::http::HeaderMap,
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
    let locale = crate::mail::request_locale(req.locale.as_deref(), &headers);

    let now = now_ms();
    let mut tx = state.db.public(Public::Auth).await?;
    let grant =
        crate::instance::check_registration(&state, &mut tx, &email, req.invite_token.as_deref())
            .await?;
    let kdf_salt = encoding::decode(&req.kdf_salt).map_err(|e| ApiError::Internal(e.into()))?;
    let encrypted_account_key =
        encoding::decode(&req.encrypted_account_key).map_err(|e| ApiError::Internal(e.into()))?;
    let inserted = sqlx::query!(
        "INSERT INTO accounts (id, email, opaque_record, kdf_salt, kdf_memory_kib, kdf_iterations, \
         kdf_parallelism, encrypted_account_key, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT DO NOTHING",
        req.account_id,
        email,
        record,
        kdf_salt,
        i64::from(req.kdf_params.memory_kib),
        i64::from(req.kdf_params.iterations),
        i64::from(req.kdf_params.parallelism),
        encrypted_account_key,
        now,
    )
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::conflict(
            "an account with this email already exists",
            serde_json::Value::Null,
        ));
    }
    // From here on the transaction runs as the new account.
    let first_admin =
        crate::instance::on_account_created(&mut tx, &req.account_id, &grant, locale, now).await?;
    super::vaults::insert_vault(&mut tx, &req.account_id, &req.vault, now).await?;
    tx.commit().await?;

    tracing::info!(account_id = %req.account_id, "account registered");
    record_event(&state, &req.account_id, "account_created", "", "", &ip).await?;
    super::admin::account_registered(&state, &req.account_id, &email, &grant, first_admin, &ip)
        .await?;
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
    let mut tx = state.db.public(Public::Auth).await?;
    let device_token_hash =
        valid_device_token(&mut tx, &email, req.device_token.as_deref()).await?;
    check_lockout(
        &state,
        &failure_limits(&email, &ip, device_token_hash.as_deref()),
    )?;
    let request = validate::base64(
        "credentialRequest",
        &req.credential_request,
        validate::MAX_SMALL_LEN,
    )?;
    let account = sqlx::query!(
        "SELECT id, opaque_record FROM accounts WHERE email = $1",
        email
    )
    .fetch_optional(&mut *tx)
    .await?;

    let (account_id, record, credential_id) = match account {
        Some(row) => (Some(row.id.clone()), Some(row.opaque_record), row.id),
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
    sqlx::query!("DELETE FROM login_attempts WHERE expires_at < $1", now)
        .execute(&mut *tx)
        .await?;
    sqlx::query!(
        "INSERT INTO login_attempts (id, account_id, state, expires_at, ip, email, device_token_hash) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
        login_id,
        account_id,
        login_state.as_slice(),
        now + LOGIN_TTL_MS,
        ip,
        email,
        device_token_hash.unwrap_or_default(),
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

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
    /// The web origin of the client (`location.origin`), so the server can
    /// offer the security keys registered for it. Optional.
    #[serde(default)]
    origin: String,
    /// Proof of an SSO sign-in (`/sso/redeem`), for organizations that
    /// require single sign-on.
    #[serde(default)]
    sso_proof: Option<String>,
}

/// A new session.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionResponse {
    token: String,
    account_id: String,
    session_id: String,
    expires_at: i64,
    /// Store it on the device and send it with the next `login/start`. It
    /// replaces the device token the login was started with.
    device_token: String,
    /// Unused recovery codes left, after signing in with one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recovery_codes_remaining: Option<i64>,
}

impl SessionResponse {
    pub(crate) fn device_token(&self) -> &str {
        &self.device_token
    }
}

/// The answer to `login/finish`: a session, or the request for a second
/// factor when the account has two-factor authentication turned on.
#[derive(Serialize)]
#[serde(untagged)]
pub enum LoginFinishResponse {
    Session(SessionResponse),
    TwoFactor(super::two_factor::LoginChallenge),
}

pub(crate) const CLIENT_KINDS: [&str; 6] = ["web", "extension", "desktop", "ios", "android", "cli"];

pub(crate) fn clean_device_name(name: &str) -> String {
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
    if req.origin.len() > 256 {
        return Err(ApiError::bad_request("origin is too long"));
    }
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
    let mut tx = state.db.public(Public::Auth).await?;
    let attempt = sqlx::query!(
        "DELETE FROM login_attempts WHERE id = $1 \
         RETURNING account_id, state, expires_at, email, device_token_hash",
        req.login_id
    )
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    let Some(attempt) = attempt else {
        return Err(ApiError::InvalidCredentials);
    };
    let (account_id, login_state, expires_at, email, device_token_hash) = (
        attempt.account_id,
        attempt.state,
        attempt.expires_at,
        attempt.email,
        attempt.device_token_hash,
    );
    let device_token_hash = Some(device_token_hash.as_str()).filter(|h| !h.is_empty());
    let now = now_ms();
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
    {
        let mut tx = state.db.as_account(&account_id).await?;
        crate::instance::ensure_active(&mut tx, &account_id).await?;
    }
    // Organizations can require single sign-on; a fresh or remembered SSO
    // sign-in also stands in for the second factor.
    let sso = super::sso::login::login_gate(
        &state,
        &account_id,
        req.sso_proof.as_deref(),
        device_token_hash,
    )
    .await?;

    // The password was right. With two-factor authentication on, a device
    // that is not remembered gets a challenge instead of a session.
    if !sso.satisfied
        && let Some(challenge) = super::two_factor::login_challenge(
            &state,
            &account_id,
            super::two_factor::PendingLogin {
                device_token_hash,
                device_name: &device_name,
                client_kind: &client_kind,
                ip: &ip,
                origin: &req.origin,
            },
        )
        .await?
    {
        tracing::info!(account_id = %account_id, "login needs a second factor");
        return Ok(Json(LoginFinishResponse::TwoFactor(challenge)));
    }

    let session = start_session(
        &state,
        &account_id,
        NewSession {
            device_token_hash,
            device_name: &device_name,
            client_kind: &client_kind,
            ip: &ip,
            event: if sso.satisfied { "login_sso" } else { "login" },
            remember_until: 0,
        },
    )
    .await?;
    super::sso::login::remember(
        &state,
        &account_id,
        session.device_token(),
        sso.remember_until,
    )
    .await?;
    Ok(Json(LoginFinishResponse::Session(session)))
}

/// How a session comes about.
pub(crate) struct NewSession<'a> {
    /// The valid device token the login was started with.
    pub device_token_hash: Option<&'a str>,
    pub device_name: &'a str,
    pub client_kind: &'a str,
    pub ip: &'a str,
    /// The activity log entry: `login`, `login_two_factor` or
    /// `login_recovered` (right after an account recovery).
    pub event: &'a str,
    /// Remember the device for two-factor authentication until then (Unix
    /// ms; 0 keeps what the device token had).
    pub remember_until: i64,
}

/// Creates a session after a complete login and issues a new device token.
pub(crate) async fn start_session(
    state: &AppState,
    account_id: &str,
    new: NewSession<'_>,
) -> ApiResult<SessionResponse> {
    let now = now_ms();
    let token = encoding::encode(&random::bytes::<32>().map_err(|e| ApiError::Internal(e.into()))?);
    let session_id = id::new_id().map_err(|e| ApiError::Internal(e.into()))?;
    let expires_at = now + SESSION_TTL_MS;
    let (device_token, new_device_token_hash) = issue_device_token(
        state,
        account_id,
        new.device_token_hash,
        new.remember_until,
        now,
    )
    .await?;
    let mut tx = state.db.as_account(account_id).await?;
    sqlx::query!(
        "INSERT INTO sessions (token_hash, account_id, created_at, expires_at, id, device_name, client_kind, ip, \
         last_used_at, device_token_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $3, $9)",
        hash_token(&token),
        account_id,
        now,
        expires_at,
        session_id,
        new.device_name,
        new.client_kind,
        new.ip,
        new_device_token_hash,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    // The device that just recovered the account gets the recovery mail
    // instead of a new-device mail.
    if new.event != "login_recovered" {
        super::notify::signed_in(
            state,
            account_id,
            new.device_token_hash.is_some(),
            new.device_name,
            new.ip,
            now,
        )
        .await;
    }
    record_event(
        state,
        account_id,
        new.event,
        new.device_name,
        new.client_kind,
        new.ip,
    )
    .await?;
    tracing::info!(account_id = %account_id, "login");

    Ok(SessionResponse {
        token,
        account_id: account_id.to_owned(),
        session_id,
        expires_at,
        device_token,
        recovery_codes_remaining: None,
    })
}

pub async fn logout(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
) -> ApiResult<StatusCode> {
    let mut tx = state.db.as_account(&session.account_id).await?;
    sqlx::query!(
        "DELETE FROM sessions WHERE token_hash = $1",
        session.token_hash
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
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
    /// Whether the account may use the instance administration.
    instance_admin: bool,
}

pub async fn account(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<Json<AccountResponse>> {
    let mut tx = state.db.as_account(&session.account_id).await?;
    let row = sqlx::query!(
        "SELECT email, kdf_salt, kdf_memory_kib, kdf_iterations, kdf_parallelism, encrypted_account_key \
         FROM accounts WHERE id = $1",
        session.account_id
    )
    .fetch_one(&mut *tx)
    .await?;
    let (email, memory, iterations, parallelism) = (
        row.email,
        row.kdf_memory_kib,
        row.kdf_iterations,
        row.kdf_parallelism,
    );
    let kdf_salt = encoding::encode(&row.kdf_salt);
    let encrypted_account_key = encoding::encode(&row.encrypted_account_key);
    let instance_admin = crate::instance::is_admin(&state, &mut tx, &session.account_id).await?;
    Ok(Json(AccountResponse {
        instance_admin,
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

pub(crate) fn hash_token(token: &str) -> String {
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
        // Sessions of disabled accounts are deleted when the account is
        // disabled; the function's join also covers a login finishing at
        // that moment. Signed-out requests cannot read sessions: the
        // function resolves one token hash only.
        let mut tx = state.db.public(Public::Auth).await?;
        let row = sqlx::query!(
            r#"SELECT account_id AS "account_id!", id AS "id!", device_name AS "device_name!",
                      client_kind AS "client_kind!", created_at AS "created_at!",
                      last_used_at AS "last_used_at!"
               FROM passbox.session_by_token($1, $2)"#,
            token_hash,
            now,
        )
        .fetch_optional(&mut *tx)
        .await?;
        drop(tx);
        let row = row.ok_or(ApiError::Unauthorized)?;
        let (account_id, id, device_name, client_kind, created_at, last_used_at) = (
            row.account_id,
            row.id,
            row.device_name,
            row.client_kind,
            row.created_at,
            row.last_used_at,
        );
        if now - last_used_at > LAST_USED_RESOLUTION_MS {
            let mut tx = state.db.as_account(&account_id).await?;
            sqlx::query!(
                "UPDATE sessions SET last_used_at = $1 WHERE token_hash = $2",
                now,
                token_hash,
            )
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
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
