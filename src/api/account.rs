//! Account security: activity log, master password and email address changes.

use std::time::Duration;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use data_encoding::HEXLOWER;
use passbox_core::kdf::KdfParams;
use passbox_core::{encoding, opaque, random};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use super::auth::{Session, record_event};
use super::validate;
use crate::db::now_ms;
use crate::error::{ApiError, ApiResult};
use crate::mail::{Template, request_locale};
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
    let mut tx = state.db.as_account(&session.account_id).await?;
    let rows = sqlx::query!(
        "SELECT id, kind, device_name, client_kind, ip, created_at FROM account_events \
         WHERE account_id = $1 ORDER BY created_at DESC LIMIT $2",
        session.account_id,
        limit,
    )
    .fetch_all(&mut *tx)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| AccountEvent {
                id: row.id,
                kind: row.kind,
                device_name: row.device_name,
                client_kind: row.client_kind,
                ip: row.ip,
                created_at: row.created_at,
            })
            .collect(),
    ))
}

pub(crate) fn require_recent_login(session: &Session) -> ApiResult<()> {
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

    let kdf_salt = super::vaults::decode(&req.kdf_salt)?;
    let encrypted_account_key = super::vaults::decode(&req.encrypted_account_key)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    sqlx::query!(
        "UPDATE accounts SET opaque_record = $1, kdf_salt = $2, kdf_memory_kib = $3, kdf_iterations = $4, \
         kdf_parallelism = $5, encrypted_account_key = $6 WHERE id = $7",
        record,
        kdf_salt,
        i64::from(req.kdf_params.memory_kib),
        i64::from(req.kdf_params.iterations),
        i64::from(req.kdf_params.parallelism),
        encrypted_account_key,
        session.account_id,
    )
    .execute(&mut *tx)
    .await?;
    // Other devices must enter the new password anyway, so they lose their
    // exemption from the per-email lockout too. This device keeps the device
    // token issued with its session.
    sqlx::query!(
        "DELETE FROM device_tokens WHERE account_id = $1 AND token_hash NOT IN \
         (SELECT device_token_hash FROM sessions WHERE token_hash = $2)",
        session.account_id,
        session.token_hash(),
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!(
        "DELETE FROM sessions WHERE account_id = $1 AND token_hash <> $2",
        session.account_id,
        session.token_hash(),
    )
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

// --- Email address ---------------------------------------------------------------

/// How long a confirmation code for a new address is valid.
const EMAIL_CODE_TTL_MS: i64 = 30 * 60 * 1000;
/// A new code is mailed at most once a minute.
const EMAIL_CODE_RESEND_MS: i64 = 60 * 1000;
const EMAIL_CODE_MAX_ATTEMPTS: i64 = 5;

fn hash_email_code(account_id: &str, email: &str, code: &str) -> String {
    HEXLOWER.encode(&Sha256::digest(
        format!("{account_id}:{email}:{code}").as_bytes(),
    ))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingEmailChange {
    new_email: String,
    expires_at: i64,
}

/// `GET /api/v1/account/email`: the change waiting for its code, if any.
pub async fn email_pending(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<Json<Option<PendingEmailChange>>> {
    let mut tx = state.db.as_account(&session.account_id).await?;
    let row = sqlx::query!(
        "SELECT new_email, code_expires_at FROM email_changes WHERE account_id = $1 AND code_expires_at > $2",
        session.account_id,
        now_ms(),
    )
    .fetch_optional(&mut *tx)
    .await?;
    Ok(Json(row.map(|row| PendingEmailChange {
        new_email: row.new_email,
        expires_at: row.code_expires_at,
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailStartRequest {
    email: String,
    /// Language of the confirmation mail (`en`, `de`); defaults to the request's.
    #[serde(default)]
    locale: Option<String>,
}

/// `POST /api/v1/account/email`: mails a confirmation code to the new
/// address. Whether the address is taken is only told once the code is
/// entered, so the endpoint does not reveal who has an account.
pub async fn email_start(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Json(req): Json<EmailStartRequest>,
) -> ApiResult<(StatusCode, Json<PendingEmailChange>)> {
    require_recent_login(&session)?;
    let email = req.email.trim().to_lowercase();
    if !super::breach::valid_email(&email) {
        return Err(ApiError::bad_request("enter a valid email address"));
    }
    if let Some(wait) = state.limiter.hit(
        &format!("email-change:{}", session.account_id),
        10,
        Duration::from_secs(60 * 60),
    ) {
        return Err(ApiError::RateLimited(wait));
    }
    let mut tx = state.db.as_account(&session.account_id).await?;
    let current = sqlx::query_scalar!(
        "SELECT email FROM accounts WHERE id = $1",
        session.account_id
    )
    .fetch_one(&mut *tx)
    .await?;
    if current == email {
        return Err(ApiError::bad_request(
            "this is already the address of your account",
        ));
    }
    // Addresses of single sign-on accounts belong to the organization's
    // identity provider.
    let managed = sqlx::query_scalar!(
        r#"SELECT EXISTS (SELECT 1 FROM sso_identities WHERE account_id = $1)
              OR EXISTS (SELECT 1 FROM scim_users WHERE account_id = $1 AND active) AS "managed!""#,
        session.account_id
    )
    .fetch_one(&mut *tx)
    .await?;
    if managed {
        return Err(ApiError::forbidden(
            "email_managed",
            "your organization manages the address of this account",
        ));
    }
    let sent_at = sqlx::query_scalar!(
        "SELECT created_at FROM email_changes WHERE account_id = $1 AND new_email = $2",
        session.account_id,
        email,
    )
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(sent_at) = sent_at
        && now_ms() - sent_at < EMAIL_CODE_RESEND_MS
    {
        return Err(ApiError::RateLimited(Duration::from_millis(
            (EMAIL_CODE_RESEND_MS - (now_ms() - sent_at)).max(1000) as u64,
        )));
    }
    let locale = match request_locale(req.locale.as_deref(), &headers) {
        Some(locale) => locale,
        None => {
            crate::instance::load_settings(&mut tx)
                .await?
                .default_locale
        }
    };
    let bytes = random::bytes::<8>().map_err(|e| ApiError::Internal(e.into()))?;
    let code = format!("{:06}", u64::from_be_bytes(bytes) % 1_000_000);
    let now = now_ms();
    let expires_at = now + EMAIL_CODE_TTL_MS;
    sqlx::query!(
        "INSERT INTO email_changes (account_id, new_email, code_hash, code_expires_at, code_attempts, created_at) \
         VALUES ($1, $2, $3, $4, 0, $5) ON CONFLICT (account_id) DO UPDATE SET new_email = excluded.new_email, \
         code_hash = excluded.code_hash, code_expires_at = excluded.code_expires_at, code_attempts = 0, \
         created_at = excluded.created_at",
        session.account_id,
        email,
        hash_email_code(&session.account_id, &email, &code),
        expires_at,
        now,
    )
    .execute(&mut *tx)
    .await?;
    crate::mail::Mailer::enqueue_in(
        &mut tx,
        &email,
        Template::EmailChangeCode,
        locale,
        &json!({ "email": email, "code": code, "minutes": EMAIL_CODE_TTL_MS / 60_000 }),
    )
    .await?;
    tx.commit().await?;
    state.mailer.wake();
    Ok((
        StatusCode::ACCEPTED,
        Json(PendingEmailChange {
            new_email: email,
            expires_at,
        }),
    ))
}

#[derive(Deserialize)]
pub struct EmailConfirmRequest {
    code: String,
}

#[derive(Serialize)]
pub struct EmailConfirmResponse {
    email: String,
}

/// `POST /api/v1/account/email/confirm`: replaces the address with the
/// pending one and tells the old address about it.
pub async fn email_confirm(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Json(req): Json<EmailConfirmRequest>,
) -> ApiResult<Json<EmailConfirmResponse>> {
    let mut tx = state.db.as_account(&session.account_id).await?;
    let pending = sqlx::query!(
        "SELECT new_email, code_hash, code_expires_at, code_attempts FROM email_changes WHERE account_id = $1",
        session.account_id,
    )
    .fetch_optional(&mut *tx)
    .await?;
    let Some(pending) = pending.filter(|row| {
        row.code_expires_at > now_ms() && row.code_attempts < EMAIL_CODE_MAX_ATTEMPTS
    }) else {
        return Err(ApiError::forbidden(
            "code_expired",
            "the code expired or was entered wrong too often; request a new one",
        ));
    };
    let code: String = req.code.chars().filter(char::is_ascii_digit).collect();
    if hash_email_code(&session.account_id, &pending.new_email, &code) != pending.code_hash {
        sqlx::query!(
            "UPDATE email_changes SET code_attempts = code_attempts + 1 WHERE account_id = $1",
            session.account_id,
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Err(ApiError::InvalidTwoFactorCode);
    }
    let old_email = sqlx::query_scalar!(
        "SELECT email FROM accounts WHERE id = $1",
        session.account_id
    )
    .fetch_one(&mut *tx)
    .await?;
    let changed = sqlx::query!(
        "UPDATE accounts SET email = $1 WHERE id = $2",
        pending.new_email,
        session.account_id,
    )
    .execute(&mut *tx)
    .await;
    if let Err(err) = changed {
        if err
            .as_database_error()
            .is_some_and(|err| err.is_unique_violation())
        {
            return Err(ApiError::forbidden(
                "email_taken",
                "another account already uses this address",
            ));
        }
        return Err(err.into());
    }
    sqlx::query!(
        "DELETE FROM email_changes WHERE account_id = $1",
        session.account_id
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    record_event(
        &state,
        &session.account_id,
        "email_changed",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    super::notify::email_changed(
        &state,
        &session.account_id,
        &old_email,
        &pending.new_email,
        &session.device_name,
        &ip,
    )
    .await;
    Ok(Json(EmailConfirmResponse {
        email: pending.new_email,
    }))
}

/// `DELETE /api/v1/account/email`: drops the pending change.
pub async fn email_cancel(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<StatusCode> {
    let mut tx = state.db.as_account(&session.account_id).await?;
    sqlx::query!(
        "DELETE FROM email_changes WHERE account_id = $1",
        session.account_id
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
