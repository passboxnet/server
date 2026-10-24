//! Account recovery (wave C): the personal recovery code (C2), the device
//! side of organization recovery (C1) and setting new credentials after
//! either.
//!
//! - A recovery code is the password of a second OPAQUE record
//!   (credential identifier `recovery|{account_id}`). The wrapped copy of
//!   the account key is only returned after that login succeeded (and, when
//!   the account uses two-factor sign-in, after a second factor), so the
//!   server never hands it to someone who only knows the email.
//! - An organization recovery request carries the device's ephemeral public
//!   key. Admins approve it in the organization (`api::org_recovery`); the
//!   device then fetches the sealed account key with its request token.
//! - Either way the device gets a single-use recovery token (15 minutes)
//!   and sets a new master password, a new Secret Key (new KDF salt and
//!   OPAQUE record) and, for codes, a new recovery code. Every session and
//!   device token is revoked.
//!
//! Unknown emails, accounts without a recovery code and accounts without an
//! escrow get answers that look like real ones. See
//! `docs/architecture/recovery.md`.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use passbox_core::kdf::KdfParams;
use passbox_core::keyring::AccountKeysUpload;
use passbox_core::{encoding, id, opaque, random};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::account::require_recent_login;
use super::auth::{
    CLIENT_KINDS, Session, check_lockout, clean_device_name, fake_account_id, hash_token, limit_ip,
    record_event, record_failure,
};
use super::validate;
use crate::db::{self, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::mail::Template;
use crate::security::ClientIp;
use crate::state::AppState;

/// A recovery-code login must be finished within this time.
const ATTEMPT_TTL_MS: i64 = 5 * 60 * 1000;
/// A proven recovery must set new credentials within this time.
const SESSION_TTL_MS: i64 = 15 * 60 * 1000;
/// Organization recovery requests expire after two days.
pub(crate) const REQUEST_TTL_MS: i64 = 48 * 60 * 60 * 1000;
const MAX_FAILURES_PER_EMAIL_IP: u32 = 10;
const MAX_FAILURES_PER_EMAIL: u32 = 20;
const MAX_FAILURES_PER_IP: u32 = 100;
/// Organization recovery requests per IP and per email within an hour.
const MAX_REQUESTS_PER_IP: u32 = 10;
const MAX_REQUESTS_PER_EMAIL: u32 = 3;

fn internal(err: impl Into<anyhow::Error>) -> ApiError {
    ApiError::Internal(err.into())
}

fn credential_id(account_id: &str) -> String {
    format!("recovery|{account_id}")
}

fn expired() -> ApiError {
    ApiError::forbidden(
        "recovery_expired",
        "the recovery expired or was already used; start again",
    )
}

fn failure_limits(email: &str, ip: &str) -> Vec<(String, u32)> {
    vec![
        (
            format!("fail-recovery-email-ip:{email} {ip}"),
            MAX_FAILURES_PER_EMAIL_IP,
        ),
        (
            format!("fail-recovery-email:{email}"),
            MAX_FAILURES_PER_EMAIL,
        ),
        (format!("fail-recovery-ip:{ip}"), MAX_FAILURES_PER_IP),
    ]
}

fn random_token() -> ApiResult<String> {
    Ok(encoding::encode(&random::bytes::<32>().map_err(internal)?))
}

fn client_kind(kind: &str) -> String {
    if CLIENT_KINDS.contains(&kind) {
        kind.to_owned()
    } else {
        String::new()
    }
}

// --- Status and setup (signed in) ----------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryCodeStatus {
    created_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EscrowStatus {
    org_id: String,
    key_version: i64,
    created_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryStatus {
    /// `null` without a recovery code.
    recovery_code: Option<RecoveryCodeStatus>,
    /// Organizations this account escrowed its key with.
    org_escrows: Vec<EscrowStatus>,
}

/// What recovery options the account has set up.
pub async fn status(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<Json<RecoveryStatus>> {
    let created: Option<i64> =
        sqlx::query_scalar("SELECT created_at FROM account_recovery WHERE account_id = $1")
            .bind(&session.account_id)
            .fetch_optional(&state.db)
            .await?;
    let escrows: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT org_id, key_version, created_at FROM org_recovery_escrows WHERE account_id = $1 \
         ORDER BY created_at",
    )
    .bind(&session.account_id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(RecoveryStatus {
        recovery_code: created.map(|created_at| RecoveryCodeStatus { created_at }),
        org_escrows: escrows
            .into_iter()
            .map(|(org_id, key_version, created_at)| EscrowStatus {
                org_id,
                key_version,
                created_at,
            })
            .collect(),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeStartRequest {
    registration_request: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeStartResponse {
    registration_response: String,
}

/// Starts registering the OPAQUE record of a new recovery code.
pub async fn code_start(
    State(state): State<AppState>,
    session: Session,
    Json(req): Json<CodeStartRequest>,
) -> ApiResult<Json<CodeStartResponse>> {
    require_recent_login(&session)?;
    let request = validate::base64(
        "registrationRequest",
        &req.registration_request,
        validate::MAX_SMALL_LEN,
    )?;
    let response = state
        .opaque
        .registration_response(&request, credential_id(&session.account_id).as_bytes())
        .map_err(|_| ApiError::bad_request("invalid registrationRequest"))?;
    Ok(Json(CodeStartResponse {
        registration_response: encoding::encode(&response),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeFinishRequest {
    registration_upload: String,
    /// The account key wrapped with the code's wrapping key.
    wrapped_account_key: String,
}

/// Stores a new recovery code (replacing an earlier one).
pub async fn code_finish(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Json(req): Json<CodeFinishRequest>,
) -> ApiResult<StatusCode> {
    require_recent_login(&session)?;
    let record = registration_record(&req.registration_upload)?;
    validate::base64(
        "wrappedAccountKey",
        &req.wrapped_account_key,
        validate::MAX_SMALL_LEN,
    )?;
    let mut tx = db::begin_write(&state.db).await?;
    store_recovery_code(
        &mut tx,
        &session.account_id,
        &record,
        &req.wrapped_account_key,
    )
    .await?;
    tx.commit().await?;
    record_event(
        &state,
        &session.account_id,
        "account_recovery_code_created",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    let params = json!({ "device": session.device_name, "ip": ip, "time": now_ms() });
    notify(
        &state,
        &session.account_id,
        Template::RecoveryCodeCreated,
        params,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Deletes the recovery code.
pub async fn code_delete(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
) -> ApiResult<StatusCode> {
    require_recent_login(&session)?;
    let deleted = sqlx::query("DELETE FROM account_recovery WHERE account_id = $1")
        .bind(&session.account_id)
        .execute(&state.db)
        .await?;
    if deleted.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    record_event(
        &state,
        &session.account_id,
        "account_recovery_code_removed",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn registration_record(upload: &str) -> ApiResult<String> {
    let upload = validate::base64("registrationUpload", upload, validate::MAX_SMALL_LEN)?;
    let record = opaque::registration_record(&upload)
        .map_err(|_| ApiError::bad_request("invalid registrationUpload"))?;
    Ok(encoding::encode(&record))
}

async fn store_recovery_code(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    account_id: &str,
    record: &str,
    wrapped: &str,
) -> ApiResult<()> {
    sqlx::query("DELETE FROM account_recovery WHERE account_id = $1")
        .bind(account_id)
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "INSERT INTO account_recovery (account_id, opaque_record, wrapped_account_key, created_at) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(account_id)
    .bind(record)
    .bind(wrapped)
    .bind(now_ms())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn notify(state: &AppState, account_id: &str, template: Template, params: serde_json::Value) {
    if let Err(err) = state
        .mailer
        .enqueue_for_account(account_id, template, params)
        .await
    {
        tracing::warn!(error = ?err, "could not queue a recovery mail");
    }
}

// --- Recovery by code (signed out) -----------------------------------------------------

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

/// First round of the recovery-code login.
pub async fn login_start(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<LoginStartRequest>,
) -> ApiResult<Json<LoginStartResponse>> {
    limit_ip(&state, &ip)?;
    let email = validate::email(&req.email)?;
    check_lockout(&state, &failure_limits(&email, &ip))?;
    let request = validate::base64(
        "credentialRequest",
        &req.credential_request,
        validate::MAX_SMALL_LEN,
    )?;
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT a.id, r.opaque_record FROM accounts a JOIN account_recovery r ON r.account_id = a.id \
         WHERE a.email = $1",
    )
    .bind(&email)
    .fetch_optional(&state.db)
    .await?;
    let (account_id, record, credential) = match row {
        Some((id, record)) => {
            let record = encoding::decode(&record).map_err(internal)?;
            (Some(id.clone()), Some(record), credential_id(&id))
        }
        // No account or no recovery code: a fake identity, so the response
        // looks like a real one.
        None => (None, None, credential_id(&fake_account_id(&state, &email))),
    };
    let (login_state, response) = state
        .opaque
        .start_login(record.as_deref(), &request, credential.as_bytes())
        .map_err(|_| ApiError::bad_request("invalid credentialRequest"))?;
    let login_id = id::new_id().map_err(internal)?;
    let now = now_ms();
    sqlx::query("DELETE FROM recovery_attempts WHERE expires_at < $1")
        .bind(now)
        .execute(&state.db)
        .await?;
    sqlx::query(
        "INSERT INTO recovery_attempts (id, account_id, state, email, ip, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&login_id)
    .bind(account_id)
    .bind(encoding::encode(&login_state))
    .bind(&email)
    .bind(&ip)
    .bind(now + ATTEMPT_TTL_MS)
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
    #[serde(default)]
    device_name: String,
    #[serde(default)]
    client_kind: String,
}

/// A proven recovery: the token for setting new credentials and what the
/// device needs to verify and re-wrap the account key.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryGrant {
    recovery_token: String,
    account_id: String,
    email: String,
    expires_at: i64,
    /// `code` or `org`.
    method: &'static str,
    /// Set while a recovery by code still needs the account's second
    /// factor (`totp`, `recovery`); finish with `recovery/two-factor`.
    #[serde(skip_serializing_if = "Option::is_none")]
    two_factor_methods: Option<Vec<&'static str>>,
    /// The account key wrapped with the recovery code (recovery by code,
    /// after the second factor).
    #[serde(skip_serializing_if = "Option::is_none")]
    wrapped_account_key: Option<String>,
    /// The account's key pairs: the recovered account key must open them.
    #[serde(skip_serializing_if = "Option::is_none")]
    account_keys: Option<AccountKeysUpload>,
}

async fn account_keys(state: &AppState, account_id: &str) -> ApiResult<Option<AccountKeysUpload>> {
    let row: Option<(i64, String, String, String)> = sqlx::query_as(
        "SELECT key_version, bundle, bundle_signature, encrypted_private FROM account_keys \
         WHERE account_id = $1 ORDER BY key_version DESC LIMIT 1",
    )
    .bind(account_id)
    .fetch_optional(&state.db)
    .await?;
    row.map(
        |(key_version, bundle, bundle_signature, encrypted_private)| {
            Ok(AccountKeysUpload {
                key_version: u32::try_from(key_version).map_err(internal)?,
                bundle,
                bundle_signature,
                encrypted_private,
            })
        },
    )
    .transpose()
}

struct NewRecoverySession<'a> {
    account_id: &'a str,
    method: &'a str,
    source_id: &'a str,
    two_factor_pending: bool,
    device_name: &'a str,
    client_kind: &'a str,
    ip: &'a str,
}

async fn create_session(state: &AppState, new: NewRecoverySession<'_>) -> ApiResult<(String, i64)> {
    let token = random_token()?;
    let now = now_ms();
    let expires_at = now + SESSION_TTL_MS;
    sqlx::query("DELETE FROM recovery_sessions WHERE expires_at < $1")
        .bind(now)
        .execute(&state.db)
        .await?;
    sqlx::query(
        "INSERT INTO recovery_sessions (token_hash, account_id, method, source_id, two_factor_pending, \
         device_name, client_kind, ip, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(hash_token(&token))
    .bind(new.account_id)
    .bind(new.method)
    .bind(new.source_id)
    .bind(i64::from(new.two_factor_pending))
    .bind(new.device_name)
    .bind(new.client_kind)
    .bind(new.ip)
    .bind(now)
    .bind(expires_at)
    .execute(&state.db)
    .await?;
    Ok((token, expires_at))
}

async fn account_email(state: &AppState, account_id: &str) -> ApiResult<String> {
    Ok(
        sqlx::query_scalar("SELECT email FROM accounts WHERE id = $1")
            .bind(account_id)
            .fetch_one(&state.db)
            .await?,
    )
}

async fn wrapped_key(state: &AppState, account_id: &str) -> ApiResult<String> {
    sqlx::query_scalar("SELECT wrapped_account_key FROM account_recovery WHERE account_id = $1")
        .bind(account_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(expired)
}

/// Second round of the recovery-code login. Wrong codes are usually
/// detected by the client itself (OPAQUE), like wrong master passwords.
pub async fn login_finish(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<LoginFinishRequest>,
) -> ApiResult<Json<RecoveryGrant>> {
    limit_ip(&state, &ip)?;
    validate::id("loginId", &req.login_id)?;
    let finalization = validate::base64(
        "credentialFinalization",
        &req.credential_finalization,
        validate::MAX_SMALL_LEN,
    )?;
    let device_name = clean_device_name(&req.device_name);
    let client_kind = client_kind(&req.client_kind);
    let attempt: Option<(Option<String>, String, String, i64)> = sqlx::query_as(
        "DELETE FROM recovery_attempts WHERE id = $1 RETURNING account_id, state, email, expires_at",
    )
    .bind(&req.login_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((account_id, login_state, email, expires_at)) = attempt else {
        return Err(ApiError::InvalidCredentials);
    };
    let login_state = encoding::decode(&login_state).map_err(internal)?;
    let verified = opaque::finish_login(&login_state, &finalization).is_ok();
    let account_id = match account_id {
        Some(id) if verified && expires_at >= now_ms() => id,
        known => {
            record_failure(&state, &failure_limits(&email, &ip));
            if let Some(account_id) = known {
                record_event(
                    &state,
                    &account_id,
                    "account_recovery_failed",
                    &device_name,
                    &client_kind,
                    &ip,
                )
                .await?;
            }
            return Err(ApiError::InvalidCredentials);
        }
    };
    crate::instance::ensure_active(&state, &account_id).await?;
    let methods = super::two_factor::recovery_methods(&state, &account_id).await?;
    if methods.as_ref().is_some_and(Vec::is_empty) {
        return Err(ApiError::forbidden(
            "recovery_needs_security_key",
            "this account's only second factor is a security key; recover it through your organization or ask the server's administrators",
        ));
    }
    let (token, expires_at) = create_session(
        &state,
        NewRecoverySession {
            account_id: &account_id,
            method: "code",
            source_id: "",
            two_factor_pending: methods.is_some(),
            device_name: &device_name,
            client_kind: &client_kind,
            ip: &ip,
        },
    )
    .await?;
    let released = methods.is_none();
    Ok(Json(RecoveryGrant {
        recovery_token: token,
        email: account_email(&state, &account_id).await?,
        expires_at,
        method: "code",
        two_factor_methods: methods,
        wrapped_account_key: if released {
            Some(wrapped_key(&state, &account_id).await?)
        } else {
            None
        },
        account_keys: if released {
            account_keys(&state, &account_id).await?
        } else {
            None
        },
        account_id,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoFactorRequest {
    recovery_token: String,
    /// `totp` or `recovery`.
    method: String,
    code: String,
}

/// The second factor of a recovery by code.
pub async fn two_factor(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<TwoFactorRequest>,
) -> ApiResult<Json<RecoveryGrant>> {
    limit_ip(&state, &ip)?;
    let session = find_session(&state, &req.recovery_token).await?;
    if session.method != "code" {
        return Err(ApiError::bad_request("no second factor is needed"));
    }
    if req.code.len() > 64 {
        return Err(ApiError::InvalidTwoFactorCode);
    }
    super::two_factor::verify_recovery_factor(
        &state,
        &session.account_id,
        &ip,
        &req.method,
        &req.code,
    )
    .await?;
    sqlx::query("UPDATE recovery_sessions SET two_factor_pending = 0 WHERE token_hash = $1")
        .bind(&session.token_hash)
        .execute(&state.db)
        .await?;
    Ok(Json(RecoveryGrant {
        recovery_token: req.recovery_token,
        email: account_email(&state, &session.account_id).await?,
        expires_at: session.expires_at,
        method: "code",
        two_factor_methods: None,
        wrapped_account_key: Some(wrapped_key(&state, &session.account_id).await?),
        account_keys: account_keys(&state, &session.account_id).await?,
        account_id: session.account_id,
    }))
}

struct RecoverySession {
    token_hash: String,
    account_id: String,
    method: String,
    two_factor_pending: bool,
    expires_at: i64,
}

async fn find_session(state: &AppState, token: &str) -> ApiResult<RecoverySession> {
    if token.is_empty() || token.len() > 128 {
        return Err(expired());
    }
    let token_hash = hash_token(token);
    let row: Option<(String, String, i64, i64)> = sqlx::query_as(
        "SELECT account_id, method, two_factor_pending, expires_at FROM recovery_sessions \
         WHERE token_hash = $1 AND expires_at > $2",
    )
    .bind(&token_hash)
    .bind(now_ms())
    .fetch_optional(&state.db)
    .await?;
    let (account_id, method, pending, expires_at) = row.ok_or_else(expired)?;
    Ok(RecoverySession {
        token_hash,
        account_id,
        method,
        two_factor_pending: pending != 0,
        expires_at,
    })
}

// --- Setting new credentials -------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompleteStartRequest {
    recovery_token: String,
    /// OPAQUE registration for the new master password and Secret Key.
    registration_request: String,
    /// OPAQUE registration for a new recovery code (optional).
    #[serde(default)]
    recovery_registration_request: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompleteStartResponse {
    registration_response: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_registration_response: Option<String>,
}

pub async fn complete_start(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<CompleteStartRequest>,
) -> ApiResult<Json<CompleteStartResponse>> {
    limit_ip(&state, &ip)?;
    let session = find_session(&state, &req.recovery_token).await?;
    if session.two_factor_pending {
        return Err(ApiError::forbidden(
            "two_factor_required",
            "enter the second factor first",
        ));
    }
    let respond = |request: &str, credential: &str| -> ApiResult<String> {
        let request = validate::base64("registrationRequest", request, validate::MAX_SMALL_LEN)?;
        state
            .opaque
            .registration_response(&request, credential.as_bytes())
            .map(|r| encoding::encode(&r))
            .map_err(|_| ApiError::bad_request("invalid registrationRequest"))
    };
    Ok(Json(CompleteStartResponse {
        registration_response: respond(&req.registration_request, &session.account_id)?,
        recovery_registration_response: req
            .recovery_registration_request
            .as_deref()
            .map(|r| respond(r, &credential_id(&session.account_id)))
            .transpose()?,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewRecoveryCode {
    registration_upload: String,
    wrapped_account_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompleteFinishRequest {
    recovery_token: String,
    registration_upload: String,
    kdf_salt: String,
    kdf_params: KdfParams,
    /// The (unchanged) account key wrapped with the new Account Unlock Key.
    encrypted_account_key: String,
    #[serde(default)]
    recovery_code: Option<NewRecoveryCode>,
}

/// Sets the new credentials and signs out every device.
pub async fn complete_finish(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<CompleteFinishRequest>,
) -> ApiResult<StatusCode> {
    limit_ip(&state, &ip)?;
    validate::kdf(&req.kdf_salt, &req.kdf_params)?;
    validate::base64(
        "encryptedAccountKey",
        &req.encrypted_account_key,
        validate::MAX_SMALL_LEN,
    )?;
    let record = registration_record(&req.registration_upload)?;
    let new_code = req
        .recovery_code
        .as_ref()
        .map(|code| {
            validate::base64(
                "wrappedAccountKey",
                &code.wrapped_account_key,
                validate::MAX_SMALL_LEN,
            )?;
            Ok::<_, ApiError>((
                registration_record(&code.registration_upload)?,
                code.wrapped_account_key.clone(),
            ))
        })
        .transpose()?;
    if req.recovery_token.is_empty() || req.recovery_token.len() > 128 {
        return Err(expired());
    }

    let mut tx = db::begin_write(&state.db).await?;
    // Single use: the session is deleted with the change.
    let row: Option<(String, String, String, i64, String, String)> = sqlx::query_as(
        "DELETE FROM recovery_sessions WHERE token_hash = $1 AND expires_at > $2 \
         RETURNING account_id, method, source_id, two_factor_pending, device_name, client_kind",
    )
    .bind(hash_token(&req.recovery_token))
    .bind(now_ms())
    .fetch_optional(&mut *tx)
    .await?;
    let (account_id, method, source_id, pending, device_name, client_kind) =
        row.ok_or_else(expired)?;
    if pending != 0 {
        return Err(ApiError::forbidden(
            "two_factor_required",
            "enter the second factor first",
        ));
    }
    sqlx::query(
        "UPDATE accounts SET opaque_record = $1, kdf_salt = $2, kdf_memory_kib = $3, kdf_iterations = $4, \
         kdf_parallelism = $5, encrypted_account_key = $6 WHERE id = $7",
    )
    .bind(&record)
    .bind(&req.kdf_salt)
    .bind(i64::from(req.kdf_params.memory_kib))
    .bind(i64::from(req.kdf_params.iterations))
    .bind(i64::from(req.kdf_params.parallelism))
    .bind(&req.encrypted_account_key)
    .bind(&account_id)
    .execute(&mut *tx)
    .await?;
    // Every device has to sign in again with the new credentials; a used
    // recovery code is replaced (or removed).
    for statement in [
        "DELETE FROM sessions WHERE account_id = $1",
        "DELETE FROM device_tokens WHERE account_id = $1",
        "DELETE FROM recovery_sessions WHERE account_id = $1",
        "DELETE FROM device_links WHERE account_id = $1",
        "DELETE FROM account_recovery WHERE account_id = $1",
    ] {
        sqlx::query(statement)
            .bind(&account_id)
            .execute(&mut *tx)
            .await?;
    }
    if let Some((record, wrapped)) = &new_code {
        store_recovery_code(&mut tx, &account_id, record, wrapped).await?;
    }
    let mut approver = String::new();
    let mut org_id = String::new();
    if method == "org" {
        let row: Option<(String, String)> = sqlx::query_as(
            "UPDATE org_recovery_requests SET status = 'completed' WHERE id = $1 AND account_id = $2 \
             RETURNING org_id, decided_by",
        )
        .bind(&source_id)
        .bind(&account_id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((org, by)) = row {
            org_id = org;
            approver = by;
        }
    }
    tx.commit().await?;

    tracing::info!(account_id = %account_id, method = %method, "account recovered");
    let kind = if method == "org" {
        "account_recovered_org"
    } else {
        "account_recovered_code"
    };
    record_event(&state, &account_id, kind, &device_name, &client_kind, &ip).await?;
    let now = now_ms();
    let approver_email = if approver.is_empty() {
        String::new()
    } else {
        account_email(&state, &approver).await.unwrap_or_default()
    };
    let member = account_email(&state, &account_id).await?;
    let params = json!({
        "method": method, "device": device_name, "ip": ip, "time": now,
        "approver": approver_email, "member": member,
    });
    notify(&state, &account_id, Template::RecoveryUsed, params.clone()).await;
    if method == "org" && !org_id.is_empty() {
        let admins = super::org_recovery::recovery_admins(&state, &org_id).await?;
        for admin in admins {
            record_event(&state, &admin, "org_member_recovered", "", "", &ip).await?;
            notify(&state, &admin, Template::RecoveryUsed, params.clone()).await;
        }
    }
    if new_code.is_some() {
        record_event(
            &state,
            &account_id,
            "account_recovery_code_created",
            &device_name,
            &client_kind,
            &ip,
        )
        .await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

// --- Organization recovery: the requesting device ----------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgRequest {
    email: String,
    /// The organization to ask; the first one the account escrowed its key
    /// with when omitted.
    #[serde(default)]
    org_id: Option<String>,
    /// The device's ephemeral X-Wing public key (Base64url).
    ephemeral_key: String,
    #[serde(default)]
    device_name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgRequestResponse {
    request_id: String,
    /// Keep it on the device; it proves the request is yours.
    request_token: String,
    expires_at: i64,
}

/// Asks the organization's admins to recover the account. The answer looks
/// the same whether or not the account exists and escrowed its key.
pub async fn org_request(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<OrgRequest>,
) -> ApiResult<(StatusCode, Json<OrgRequestResponse>)> {
    limit_ip(&state, &ip)?;
    let email = validate::email(&req.email)?;
    let hour = std::time::Duration::from_secs(60 * 60);
    for (key, max) in [
        (format!("recovery-request-ip:{ip}"), MAX_REQUESTS_PER_IP),
        (
            format!("recovery-request-email:{email}"),
            MAX_REQUESTS_PER_EMAIL,
        ),
    ] {
        if let Some(wait) = state.limiter.hit(&key, max, hour) {
            return Err(ApiError::RateLimited(wait));
        }
    }
    let ephemeral = validate::base64("ephemeralKey", &req.ephemeral_key, validate::MAX_SMALL_LEN)?;
    if ephemeral.len() != passbox_core::identity::ENC_PK_LEN {
        return Err(ApiError::bad_request("ephemeralKey has the wrong length"));
    }
    if let Some(org_id) = &req.org_id {
        validate::id("orgId", org_id)?;
    }
    let device_name = clean_device_name(&req.device_name);
    let request_id = id::new_id().map_err(internal)?;
    let token = random_token()?;
    let now = now_ms();
    let expires_at = now + REQUEST_TTL_MS;

    let escrow: Option<(String, String)> = sqlx::query_as(
        "SELECT e.org_id, a.id FROM org_recovery_escrows e JOIN accounts a ON a.id = e.account_id \
         JOIN org_members m ON m.org_id = e.org_id AND m.account_id = e.account_id \
         JOIN org_recovery_keys k ON k.org_id = e.org_id AND k.key_version = e.key_version \
         WHERE a.email = $1 AND a.disabled_at = 0 AND m.status = 'confirmed' \
         AND (e.org_id = $2 OR $3 = '') ORDER BY e.created_at LIMIT 1",
    )
    .bind(&email)
    .bind(req.org_id.clone().unwrap_or_default())
    .bind(req.org_id.clone().unwrap_or_default())
    .fetch_optional(&state.db)
    .await?;
    if let Some((org_id, account_id)) = escrow {
        let mut tx = db::begin_write(&state.db).await?;
        // A new request replaces an open one of the same account.
        sqlx::query(
            "UPDATE org_recovery_requests SET status = 'cancelled' WHERE account_id = $1 \
             AND status IN ('pending', 'approved')",
        )
        .bind(&account_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO org_recovery_requests (id, org_id, account_id, token_hash, ephemeral_key, status, \
             approval, approval_signature, sealed_key, request_code, decided_by, decided_at, device_name, ip, \
             created_at, expires_at) VALUES ($1, $2, $3, $4, $5, 'pending', '', '', '', '', '', 0, $6, $7, $8, $9)",
        )
        .bind(&request_id)
        .bind(&org_id)
        .bind(&account_id)
        .bind(hash_token(&token))
        .bind(&req.ephemeral_key)
        .bind(&device_name)
        .bind(&ip)
        .bind(now)
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        record_event(
            &state,
            &account_id,
            "org_recovery_requested",
            &device_name,
            "",
            &ip,
        )
        .await?;
        let link = state
            .mailer
            .public_url()
            .map(|url| format!("{url}/#/recovery-requests"))
            .unwrap_or_default();
        let params =
            json!({ "device": device_name, "ip": ip, "time": now, "member": email, "link": link });
        notify(&state, &account_id, Template::Recovery, params.clone()).await;
        for admin in super::org_recovery::recovery_admins(&state, &org_id).await? {
            notify(&state, &admin, Template::RecoveryRequested, params.clone()).await;
        }
    } else {
        tracing::info!("recovery request without escrow");
    }
    Ok((
        StatusCode::CREATED,
        Json(OrgRequestResponse {
            request_id,
            request_token: token,
            expires_at,
        }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgRequestRef {
    request_id: String,
    request_token: String,
    #[serde(default)]
    client_kind: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovedRequest {
    request_id: String,
    account_id: String,
    approval: String,
    approval_signature: String,
    sealed_key: String,
    approver_bundle: String,
    approver_bundle_signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgStatusResponse {
    /// `pending`, `approved`, `denied`, `completed`, `cancelled` or `expired`.
    status: String,
    expires_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    approved: Option<ApprovedRequest>,
    /// Set with `approved`: the token for `recovery/complete/*`.
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery: Option<RecoveryGrant>,
}

/// The device's view of its request. Once approved, every call issues a new
/// recovery token (replacing the previous one).
#[allow(clippy::type_complexity)]
pub async fn org_status(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<OrgRequestRef>,
) -> ApiResult<Json<OrgStatusResponse>> {
    limit_ip(&state, &ip)?;
    validate::id("requestId", &req.request_id)?;
    let row: Option<(String, String, String, String, String, String, String, String, i64, String)> =
        sqlx::query_as(
            "SELECT account_id, token_hash, status, approval, approval_signature, sealed_key, decided_by, \
             device_name, expires_at, org_id FROM org_recovery_requests WHERE id = $1",
        )
        .bind(&req.request_id)
        .fetch_optional(&state.db)
        .await?;
    let Some((
        account_id,
        _token_hash,
        status,
        approval,
        approval_signature,
        sealed_key,
        decided_by,
        device_name,
        expires_at,
        _org_id,
    )) = row.filter(|r| r.1 == hash_token(&req.request_token))
    else {
        // Unknown requests (including the fake ones) stay pending.
        return Ok(Json(OrgStatusResponse {
            status: "pending".into(),
            expires_at: now_ms() + REQUEST_TTL_MS,
            approved: None,
            recovery: None,
        }));
    };
    let now = now_ms();
    let status = if expires_at < now && (status == "pending" || status == "approved") {
        "expired".to_owned()
    } else {
        status
    };
    if status != "approved" {
        return Ok(Json(OrgStatusResponse {
            status,
            expires_at,
            approved: None,
            recovery: None,
        }));
    }
    let mut conn = state.db.acquire().await?;
    let approver = super::signed::bundle(&mut conn, &decided_by)
        .await?
        .ok_or_else(|| internal(anyhow::anyhow!("approver without keys")))?;
    drop(conn);
    sqlx::query(
        "DELETE FROM recovery_sessions WHERE account_id = $1 AND method = 'org' AND source_id = $2",
    )
    .bind(&account_id)
    .bind(&req.request_id)
    .execute(&state.db)
    .await?;
    let client_kind = client_kind(&req.client_kind);
    let (token, token_expires) = create_session(
        &state,
        NewRecoverySession {
            account_id: &account_id,
            method: "org",
            source_id: &req.request_id,
            two_factor_pending: false,
            device_name: &device_name,
            client_kind: &client_kind,
            ip: &ip,
        },
    )
    .await?;
    Ok(Json(OrgStatusResponse {
        status,
        expires_at,
        approved: Some(ApprovedRequest {
            request_id: req.request_id.clone(),
            account_id: account_id.clone(),
            approval,
            approval_signature,
            sealed_key,
            approver_bundle: approver.encoded(),
            approver_bundle_signature: approver.encoded_signature(),
        }),
        recovery: Some(RecoveryGrant {
            recovery_token: token,
            email: account_email(&state, &account_id).await?,
            expires_at: token_expires,
            method: "org",
            two_factor_methods: None,
            wrapped_account_key: None,
            account_keys: account_keys(&state, &account_id).await?,
            account_id,
        }),
    }))
}

/// Withdraws a request from the requesting device.
pub async fn org_cancel(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<OrgRequestRef>,
) -> ApiResult<StatusCode> {
    limit_ip(&state, &ip)?;
    validate::id("requestId", &req.request_id)?;
    sqlx::query(
        "UPDATE org_recovery_requests SET status = 'cancelled' WHERE id = $1 AND token_hash = $2 \
         AND status IN ('pending', 'approved')",
    )
    .bind(&req.request_id)
    .bind(hash_token(&req.request_token))
    .execute(&state.db)
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
