//! Login two-factor authentication: the second step after the OPAQUE login.
//!
//! Factors are a TOTP authenticator app, WebAuthn security keys or passkeys,
//! and one-time recovery codes. All verification logic lives in
//! `passbox_core::{totp, two_factor, webauthn}`; this module stores the
//! factors and runs the flows:
//!
//! - `login/finish` answers with a challenge instead of a session when the
//!   account has a second factor and the device is not remembered
//!   ([`login_challenge`]); `login/two-factor` completes it
//!   ([`login_two_factor`]). The challenge only appears after the password
//!   was verified, so it reveals nothing about unknown accounts.
//! - Adding factors needs a session from a login in the last 10 minutes,
//!   like a master password change. Turning two-factor authentication off
//!   needs a valid second factor or recovery code.
//! - TOTP secrets are encrypted at rest with the server's two-factor key.
//!   Recovery codes are stored as SHA-256 hashes and deleted when used.
//! - Wrong codes count against the account and the client IP (in memory,
//!   15-minute windows, like failed logins) and each login challenge allows
//!   five attempts.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use passbox_core::aead::SymmetricKey;
use passbox_core::{encoding, id, random, two_factor, webauthn};
use serde::{Deserialize, Serialize};

use super::account::require_recent_login;
use super::auth::{
    NewSession, Session, SessionResponse, check_lockout, clean_device_name, hash_token, limit_ip,
    record_event, record_failure, start_session,
};
use super::validate;
use crate::db::{Db, Public, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::security::ClientIp;
use crate::state::AppState;

/// Login challenges, WebAuthn registrations and checks expire after this.
const CHALLENGE_TTL_MS: i64 = 5 * 60 * 1000;
/// Wrong second factors per login challenge before it is discarded.
const MAX_ATTEMPTS_PER_CHALLENGE: i64 = 5;
/// Wrong second factors per account within the lockout window.
const MAX_FAILURES_PER_ACCOUNT: u32 = 10;
/// Wrong second factors per client IP within the lockout window.
const MAX_FAILURES_PER_IP: u32 = 100;
/// "Remember this device" lasts 30 days.
pub const REMEMBER_DEVICE_MS: i64 = 30 * 24 * 60 * 60 * 1000;
/// Security keys per account.
const MAX_SECURITY_KEYS: i64 = 10;
/// How long browsers wait for the user to touch the security key.
const WEBAUTHN_TIMEOUT_MS: i64 = 2 * 60 * 1000;
/// Shown in authenticator apps and as the WebAuthn RP name.
const ISSUER: &str = "Passbox";

const PURPOSE_LOGIN: &str = "login";
const PURPOSE_REGISTER: &str = "webauthn_register";
const PURPOSE_VERIFY: &str = "verify";

fn internal(err: impl Into<anyhow::Error>) -> ApiError {
    ApiError::Internal(err.into())
}

fn failure_limits(account_id: &str, ip: &str) -> Vec<(String, u32)> {
    vec![
        (
            format!("fail-2fa-account:{account_id}"),
            MAX_FAILURES_PER_ACCOUNT,
        ),
        (format!("fail-2fa-ip:{ip}"), MAX_FAILURES_PER_IP),
    ]
}

// --- Stored factors -------------------------------------------------------------

struct Credential {
    id: String,
    credential_id: String,
    name: String,
    rp_id: String,
    created_at: i64,
    last_used_at: i64,
}

struct Factors {
    totp: bool,
    credentials: Vec<Credential>,
    recovery_codes: i64,
}

impl Factors {
    fn enabled(&self) -> bool {
        self.totp || !self.credentials.is_empty()
    }

    fn methods(&self) -> Vec<&'static str> {
        let mut methods = Vec::new();
        if self.totp {
            methods.push("totp");
        }
        if !self.credentials.is_empty() {
            methods.push("webauthn");
        }
        if self.recovery_codes > 0 {
            methods.push("recovery");
        }
        methods
    }
}

/// The account's second factors (in its own context).
async fn load_factors(db: &Db, account_id: &str) -> ApiResult<Factors> {
    let mut tx = db.as_account(account_id).await?;
    let totp: Option<i64> =
        sqlx::query_scalar!(
            "SELECT 1::BIGINT AS \"one!\" FROM two_factor_totp WHERE account_id = $1 AND confirmed = true",
            account_id,
        )
            .fetch_optional(&mut *tx)
            .await?;
    let rows: Vec<(String, String, String, String, i64, i64)> = sqlx::query!(
        "SELECT id, credential_id, name, rp_id, created_at, last_used_at FROM webauthn_credentials \
         WHERE account_id = $1 ORDER BY created_at DESC, id",
        account_id,
    )
    .map(|row| {
        (
            row.id,
            row.credential_id,
            row.name,
            row.rp_id,
            row.created_at,
            row.last_used_at,
        )
    })
    .fetch_all(&mut *tx)
    .await?;
    let recovery_codes: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"count!\" FROM recovery_codes WHERE account_id = $1",
        account_id,
    )
    .fetch_one(&mut *tx)
    .await?;
    Ok(Factors {
        totp: totp.is_some(),
        credentials: rows
            .into_iter()
            .map(
                |(id, credential_id, name, rp_id, created_at, last_used_at)| Credential {
                    id,
                    credential_id,
                    name,
                    rp_id,
                    created_at,
                    last_used_at,
                },
            )
            .collect(),
        recovery_codes,
    })
}

/// Replaces the account's recovery codes with new ones and returns them.
async fn replace_recovery_codes(
    tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    account_id: &str,
    now: i64,
) -> ApiResult<Vec<String>> {
    let codes = two_factor::generate_recovery_codes().map_err(internal)?;
    sqlx::query!(
        "DELETE FROM recovery_codes WHERE account_id = $1",
        account_id,
    )
    .execute(&mut **tx)
    .await?;
    for code in &codes {
        let hash = two_factor::hash_recovery_code(account_id, code)
            .ok_or_else(|| internal(anyhow::anyhow!("generated an invalid recovery code")))?;
        sqlx::query!(
            "INSERT INTO recovery_codes (code_hash, account_id, created_at) VALUES ($1, $2, $3)",
            hash,
            account_id,
            now,
        )
        .execute(&mut **tx)
        .await?;
    }
    Ok(codes)
}

/// After the first factor is added: no device is remembered yet, and the
/// account gets recovery codes. Returns the codes when new ones were made.
async fn after_factor_added(
    tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    account_id: &str,
    was_enabled: bool,
    had_recovery_codes: bool,
    now: i64,
) -> ApiResult<Option<Vec<String>>> {
    if !was_enabled {
        sqlx::query!(
            "UPDATE device_tokens SET two_factor_until = 0 WHERE account_id = $1",
            account_id,
        )
        .execute(&mut **tx)
        .await?;
    }
    if had_recovery_codes {
        return Ok(None);
    }
    replace_recovery_codes(tx, account_id, now).await.map(Some)
}

// --- Challenges -------------------------------------------------------------------

struct NewChallenge<'a> {
    purpose: &'a str,
    webauthn_challenge: &'a [u8],
    rp_id: &'a str,
    device_name: &'a str,
    client_kind: &'a str,
    ip: &'a str,
    device_token_hash: &'a str,
}

/// Stores a challenge and returns its token. Challenges live in the
/// sign-in context: the login's second step is signed out.
async fn create_challenge(
    state: &AppState,
    account_id: &str,
    challenge: NewChallenge<'_>,
) -> ApiResult<(String, i64)> {
    let now = now_ms();
    let token = encoding::encode(&random::bytes::<32>().map_err(internal)?);
    let expires_at = now + CHALLENGE_TTL_MS;
    let mut tx = state.db.public(Public::Auth).await?;
    sqlx::query!(
        "DELETE FROM two_factor_challenges WHERE expires_at < $1",
        now,
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!(
        "INSERT INTO two_factor_challenges (token_hash, account_id, purpose, webauthn_challenge, rp_id, \
         device_name, client_kind, ip, device_token_hash, attempts, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        hash_token(&token),
        account_id,
        challenge.purpose,
        encoding::encode(challenge.webauthn_challenge),
        challenge.rp_id,
        challenge.device_name,
        challenge.client_kind,
        challenge.ip,
        challenge.device_token_hash,
        0i64,
        expires_at,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((token, expires_at))
}

struct StoredChallenge {
    token_hash: String,
    account_id: String,
    webauthn_challenge: Vec<u8>,
    rp_id: String,
    device_name: String,
    client_kind: String,
    device_token_hash: String,
}

/// Finds an unexpired challenge for `purpose`.
async fn find_challenge(db: &Db, token: &str, purpose: &str) -> ApiResult<Option<StoredChallenge>> {
    if token.is_empty() || token.len() > 128 {
        return Ok(None);
    }
    let token_hash = hash_token(token);
    let row: Option<(String, String, String, String, String, String)> = sqlx::query!(
        "SELECT account_id, webauthn_challenge, rp_id, device_name, client_kind, device_token_hash \
         FROM two_factor_challenges WHERE token_hash = $1 AND purpose = $2 AND expires_at > $3",
        &token_hash,
        purpose,
        now_ms(),
    )
    .map(|row| {
        (
            row.account_id,
            row.webauthn_challenge,
            row.rp_id,
            row.device_name,
            row.client_kind,
            row.device_token_hash,
        )
    })
    .fetch_optional(&mut *db.public(Public::Auth).await?)
    .await?;
    row.map(
        |(account_id, challenge, rp_id, device_name, client_kind, device_token_hash)| {
            Ok(StoredChallenge {
                token_hash: token_hash.clone(),
                account_id,
                webauthn_challenge: encoding::decode(&challenge).map_err(internal)?,
                rp_id,
                device_name,
                client_kind,
                device_token_hash,
            })
        },
    )
    .transpose()
}

/// Deletes a challenge. Returns false if it was already used, so each one
/// completes at most once even under concurrent requests.
async fn consume_challenge(db: &Db, token_hash: &str) -> ApiResult<bool> {
    let mut tx = db.public(Public::Auth).await?;
    let result = sqlx::query!(
        "DELETE FROM two_factor_challenges WHERE token_hash = $1",
        token_hash,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(result.rows_affected() == 1)
}

// --- WebAuthn options -------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialDescriptor {
    #[serde(rename = "type")]
    kind: &'static str,
    /// Base64url credential ID.
    id: String,
}

/// `PublicKeyCredentialRequestOptions` with binary values as Base64url.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestOptions {
    challenge: String,
    rp_id: String,
    allow_credentials: Vec<CredentialDescriptor>,
    timeout: i64,
    user_verification: &'static str,
}

/// Picks the security keys a client at `origin` can use: those registered
/// for an RP ID that matches the origin, or, when the origin is unknown or
/// matches none, those of the most recently added key's RP ID.
fn request_options(
    credentials: &[Credential],
    origin: &str,
    challenge: &[u8],
) -> Option<RequestOptions> {
    let rp_id = credentials
        .iter()
        .find(|c| !origin.is_empty() && webauthn::origin_matches_rp_id(origin, &c.rp_id))
        .or_else(|| credentials.first())?
        .rp_id
        .clone();
    Some(RequestOptions {
        challenge: encoding::encode(challenge),
        allow_credentials: credentials
            .iter()
            .filter(|c| c.rp_id == rp_id)
            .map(|c| CredentialDescriptor {
                kind: "public-key",
                id: c.credential_id.clone(),
            })
            .collect(),
        rp_id,
        timeout: WEBAUTHN_TIMEOUT_MS,
        // The password is the first factor; the key only has to be present.
        user_verification: "discouraged",
    })
}

// --- Verifying a second factor ------------------------------------------------------

/// A WebAuthn assertion from `navigator.credentials.get`, binary values as
/// Base64url.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionResponse {
    credential_id: String,
    client_data_json: String,
    authenticator_data: String,
    signature: String,
}

/// A second factor as sent by clients.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FactorInput {
    /// `totp`, `recovery` or `webauthn`.
    method: String,
    /// The 6-digit code or the recovery code.
    #[serde(default)]
    code: String,
    #[serde(default)]
    webauthn: Option<AssertionResponse>,
}

enum Verified {
    Totp,
    Recovery,
    WebAuthn,
}

/// Checks a second factor. Any mismatch is `InvalidTwoFactorCode`; a used
/// TOTP step or recovery code is spent here, so it cannot be used again.
async fn verify_factor(
    state: &AppState,
    account_id: &str,
    factor: &FactorInput,
    challenge: Option<&StoredChallenge>,
) -> ApiResult<Verified> {
    match factor.method.as_str() {
        "totp" => {
            if factor.code.len() > 16 {
                return Err(ApiError::InvalidTwoFactorCode);
            }
            // The first factor is verified (or the account is signed in):
            // the check runs in the account's context.
            let mut tx = state.db.as_account(account_id).await?;
            let row: Option<Vec<u8>> = sqlx::query_scalar!(
                "SELECT sealed_secret FROM two_factor_totp WHERE account_id = $1 AND confirmed = true",
                account_id,
            )
            .fetch_optional(&mut *tx)
            .await?;
            let sealed = row.ok_or(ApiError::InvalidTwoFactorCode)?;
            let step = check_totp(&state.two_factor_key, account_id, &sealed, &factor.code)?
                .ok_or(ApiError::InvalidTwoFactorCode)?;
            // Replay protection: a step is accepted once, and never one
            // older than the last accepted step.
            let updated = sqlx::query!(
                "UPDATE two_factor_totp SET last_step = $1 WHERE account_id = $2 AND last_step < $1",
                step,
                account_id,
            )
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            if updated.rows_affected() == 1 {
                Ok(Verified::Totp)
            } else {
                Err(ApiError::InvalidTwoFactorCode)
            }
        }
        "recovery" => {
            let hash = two_factor::hash_recovery_code(account_id, &factor.code)
                .ok_or(ApiError::InvalidTwoFactorCode)?;
            let mut tx = state.db.as_account(account_id).await?;
            let deleted = sqlx::query!(
                "DELETE FROM recovery_codes WHERE code_hash = $1 AND account_id = $2",
                hash,
                account_id,
            )
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            if deleted.rows_affected() == 1 {
                Ok(Verified::Recovery)
            } else {
                Err(ApiError::InvalidTwoFactorCode)
            }
        }
        "webauthn" => {
            let (Some(assertion), Some(challenge)) = (&factor.webauthn, challenge) else {
                return Err(ApiError::InvalidTwoFactorCode);
            };
            verify_webauthn(state, account_id, assertion, challenge).await
        }
        _ => Err(ApiError::bad_request(
            "method must be totp, recovery or webauthn",
        )),
    }
}

/// Decrypts a stored TOTP and checks `code` within ±1 step. Returns the
/// matching step.
fn check_totp(
    key: &SymmetricKey,
    account_id: &str,
    sealed: &[u8],
    code: &str,
) -> ApiResult<Option<i64>> {
    let totp = two_factor::open_totp(key, account_id, sealed).map_err(internal)?;
    let now = u64::try_from(now_ms() / 1000).unwrap_or(0);
    Ok(totp
        .verify(code, now, two_factor::TOTP_WINDOW)
        .and_then(|step| i64::try_from(step).ok()))
}

async fn verify_webauthn(
    state: &AppState,
    account_id: &str,
    assertion: &AssertionResponse,
    challenge: &StoredChallenge,
) -> ApiResult<Verified> {
    let invalid = |_| ApiError::InvalidTwoFactorCode;
    let credential_id =
        validate::base64("credentialId", &assertion.credential_id, 2048).map_err(invalid)?;
    let client_data_json = validate::base64(
        "clientDataJson",
        &assertion.client_data_json,
        validate::MAX_SMALL_LEN,
    )
    .map_err(invalid)?;
    let authenticator_data = validate::base64(
        "authenticatorData",
        &assertion.authenticator_data,
        validate::MAX_SMALL_LEN,
    )
    .map_err(invalid)?;
    let signature = validate::base64("signature", &assertion.signature, 1024).map_err(invalid)?;
    let mut tx = state.db.as_account(account_id).await?;
    let row: Option<(String, String, i64)> = sqlx::query!(
        "SELECT id, public_key, sign_count FROM webauthn_credentials \
         WHERE credential_id = $1 AND account_id = $2 AND rp_id = $3",
        encoding::encode(&credential_id),
        account_id,
        &challenge.rp_id,
    )
    .map(|row| (row.id, row.public_key, row.sign_count))
    .fetch_optional(&mut *tx)
    .await?;
    let (id, public_key, stored_count) = row.ok_or(ApiError::InvalidTwoFactorCode)?;
    let public_key = encoding::decode(&public_key).map_err(internal)?;
    let new_count = webauthn::verify_assertion(&webauthn::AssertionInput {
        client_data_json: &client_data_json,
        authenticator_data: &authenticator_data,
        signature: &signature,
        challenge: &challenge.webauthn_challenge,
        rp_id: &challenge.rp_id,
        public_key: &public_key,
        stored_sign_count: u32::try_from(stored_count).unwrap_or(u32::MAX),
        require_user_verification: false,
    })
    .map_err(|e| {
        tracing::info!(error = %e, "WebAuthn assertion rejected");
        ApiError::InvalidTwoFactorCode
    })?;
    sqlx::query!(
        "UPDATE webauthn_credentials SET sign_count = $1, last_used_at = $2 WHERE id = $3",
        i64::from(new_count),
        now_ms(),
        &id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Verified::WebAuthn)
}

// --- Login --------------------------------------------------------------------------

/// What `login/finish` returns instead of a session.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginChallenge {
    /// Always true; tells clients to ask for a second factor.
    two_factor_required: bool,
    /// Send it to `login/two-factor`. Valid for 5 minutes.
    challenge_token: String,
    expires_at: i64,
    /// Available factors: `totp`, `webauthn`, `recovery`.
    methods: Vec<&'static str>,
    /// Options for `navigator.credentials.get` when the account has
    /// security keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    webauthn: Option<RequestOptions>,
}

/// The login that waits for its second factor.
pub(crate) struct PendingLogin<'a> {
    pub device_token_hash: Option<&'a str>,
    pub device_name: &'a str,
    pub client_kind: &'a str,
    pub ip: &'a str,
    pub origin: &'a str,
}

/// Called by `login/finish` after the password was verified. Returns a
/// challenge if the account needs a second factor on this device.
pub(crate) async fn login_challenge(
    state: &AppState,
    account_id: &str,
    pending: PendingLogin<'_>,
) -> ApiResult<Option<LoginChallenge>> {
    let factors = load_factors(&state.db, account_id).await?;
    if !factors.enabled() {
        return Ok(None);
    }
    let now = now_ms();
    if let Some(device_token_hash) = pending.device_token_hash {
        let until: Option<i64> = sqlx::query_scalar!(
            "SELECT two_factor_until FROM device_tokens WHERE token_hash = $1 AND account_id = $2 \
             AND expires_at > $3",
            device_token_hash,
            account_id,
            now,
        )
        .fetch_optional(&mut *state.db.as_account(account_id).await?)
        .await?;
        if until.is_some_and(|until| until > now) {
            return Ok(None);
        }
    }
    let webauthn_challenge = random::bytes::<32>().map_err(internal)?;
    let webauthn = request_options(&factors.credentials, pending.origin, &webauthn_challenge);
    let (challenge_token, expires_at) = create_challenge(
        state,
        account_id,
        NewChallenge {
            purpose: PURPOSE_LOGIN,
            webauthn_challenge: &webauthn_challenge,
            rp_id: webauthn.as_ref().map_or("", |w| w.rp_id.as_str()),
            device_name: pending.device_name,
            client_kind: pending.client_kind,
            ip: pending.ip,
            device_token_hash: pending.device_token_hash.unwrap_or(""),
        },
    )
    .await?;
    Ok(Some(LoginChallenge {
        two_factor_required: true,
        challenge_token,
        expires_at,
        methods: factors.methods(),
        webauthn,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginTwoFactorRequest {
    challenge_token: String,
    #[serde(flatten)]
    factor: FactorInput,
    /// Skip the second step on this device for 30 days.
    #[serde(default)]
    remember_device: bool,
}

/// Completes a login with its second factor and creates the session.
pub async fn login_two_factor(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<LoginTwoFactorRequest>,
) -> ApiResult<Json<SessionResponse>> {
    limit_ip(&state, &ip)?;
    let challenge = find_challenge(&state.db, &req.challenge_token, PURPOSE_LOGIN)
        .await?
        .ok_or(ApiError::TwoFactorExpired)?;
    let account_id = challenge.account_id.clone();
    let limits = failure_limits(&account_id, &ip);
    check_lockout(&state, &limits)?;
    let mut tx = state.db.public(Public::Auth).await?;
    let counted = sqlx::query!(
        "UPDATE two_factor_challenges SET attempts = attempts + 1 WHERE token_hash = $1 AND attempts < $2",
        &challenge.token_hash,
        MAX_ATTEMPTS_PER_CHALLENGE,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    if counted.rows_affected() == 0 {
        consume_challenge(&state.db, &challenge.token_hash).await?;
        return Err(ApiError::TwoFactorExpired);
    }

    let verified = match verify_factor(&state, &account_id, &req.factor, Some(&challenge)).await {
        Ok(verified) => verified,
        Err(ApiError::InvalidTwoFactorCode) => {
            tracing::info!(account_id = %account_id, "wrong second factor");
            record_failure(&state, &limits);
            record_event(
                &state,
                &account_id,
                "two_factor_failed",
                &challenge.device_name,
                &challenge.client_kind,
                &ip,
            )
            .await?;
            return Err(ApiError::InvalidTwoFactorCode);
        }
        Err(other) => return Err(other),
    };
    if !consume_challenge(&state.db, &challenge.token_hash).await? {
        return Err(ApiError::TwoFactorExpired);
    }

    // The account may have been disabled since the password step.
    crate::instance::ensure_active(&mut *state.db.as_account(&account_id).await?, &account_id)
        .await?;
    let remember_until = if req.remember_device {
        now_ms() + REMEMBER_DEVICE_MS
    } else {
        0
    };
    let device_token_hash = Some(challenge.device_token_hash.as_str()).filter(|h| !h.is_empty());
    let mut session = start_session(
        &state,
        &account_id,
        NewSession {
            device_token_hash,
            device_name: &challenge.device_name,
            client_kind: &challenge.client_kind,
            ip: &ip,
            event: "login_two_factor",
            remember_until,
        },
    )
    .await?;
    if matches!(verified, Verified::Recovery) {
        record_event(
            &state,
            &account_id,
            "recovery_code_used",
            &challenge.device_name,
            &challenge.client_kind,
            &ip,
        )
        .await?;
        session.recovery_codes_remaining =
            Some(load_factors(&state.db, &account_id).await?.recovery_codes);
    }
    Ok(Json(session))
}

// --- Status -------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityKeyInfo {
    id: String,
    name: String,
    created_at: i64,
    last_used_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusResponse {
    /// Whether sign-ins need a second factor.
    enabled: bool,
    totp: bool,
    security_keys: Vec<SecurityKeyInfo>,
    recovery_codes_remaining: i64,
}

pub async fn status(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<Json<StatusResponse>> {
    let factors = load_factors(&state.db, &session.account_id).await?;
    Ok(Json(StatusResponse {
        enabled: factors.enabled(),
        totp: factors.totp,
        security_keys: factors
            .credentials
            .into_iter()
            .map(|c| SecurityKeyInfo {
                id: c.id,
                name: c.name,
                created_at: c.created_at,
                last_used_at: c.last_used_at,
            })
            .collect(),
        recovery_codes_remaining: factors.recovery_codes,
    }))
}

/// New recovery codes, shown once.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_codes: Option<Vec<String>>,
}

// --- TOTP ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpStartResponse {
    /// Base32 secret for manual entry.
    secret: String,
    /// `otpauth://` URI for the QR code.
    uri: String,
}

/// Creates a new TOTP secret, pending until a first code confirms it.
pub async fn totp_start(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<Json<TotpStartResponse>> {
    require_recent_login(&session)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    let confirmed: Option<i64> =
        sqlx::query_scalar!(
            "SELECT 1::BIGINT AS \"one!\" FROM two_factor_totp WHERE account_id = $1 AND confirmed = true",
            &session.account_id,
        )
            .fetch_optional(&mut *tx)
            .await?;
    if confirmed.is_some() {
        return Err(ApiError::conflict(
            "an authenticator app is already set up; remove it first",
            serde_json::Value::Null,
        ));
    }
    let email: String = sqlx::query_scalar!(
        "SELECT email FROM accounts WHERE id = $1",
        &session.account_id,
    )
    .fetch_one(&mut *tx)
    .await?;
    let totp = two_factor::new_login_totp(ISSUER, &email).map_err(internal)?;
    let sealed = two_factor::seal_totp(&state.two_factor_key, &session.account_id, &totp)
        .map_err(internal)?;
    sqlx::query!(
        "DELETE FROM two_factor_totp WHERE account_id = $1 AND confirmed = false",
        &session.account_id,
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!(
        "INSERT INTO two_factor_totp (account_id, sealed_secret, confirmed, last_step, created_at) \
         VALUES ($1, $2, $3, $4, $5)",
        &session.account_id,
        sealed.as_slice(),
        false,
        0i64,
        now_ms(),
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(TotpStartResponse {
        secret: totp.secret_base32(),
        uri: totp.to_uri(),
    }))
}

#[derive(Deserialize)]
pub struct TotpConfirmRequest {
    code: String,
}

/// Turns the pending TOTP on with a first code from the app. Returns
/// recovery codes when the account had none.
pub async fn totp_confirm(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Json(req): Json<TotpConfirmRequest>,
) -> ApiResult<Json<EnrollResponse>> {
    require_recent_login(&session)?;
    let limits = failure_limits(&session.account_id, &ip);
    check_lockout(&state, &limits)?;
    let pending: Option<Vec<u8>> = sqlx::query_scalar!(
        "SELECT sealed_secret FROM two_factor_totp WHERE account_id = $1 AND confirmed = false",
        &session.account_id,
    )
    .fetch_optional(&mut *state.db.as_account(&session.account_id).await?)
    .await?;
    let sealed = pending
        .ok_or_else(|| ApiError::bad_request("start setting up the authenticator app first"))?;
    let Some(step) = (if req.code.len() <= 16 {
        check_totp(
            &state.two_factor_key,
            &session.account_id,
            &sealed,
            &req.code,
        )?
    } else {
        None
    }) else {
        record_failure(&state, &limits);
        return Err(ApiError::InvalidTwoFactorCode);
    };

    let before = load_factors(&state.db, &session.account_id).await?;
    let now = now_ms();
    let mut tx = state.db.as_account(&session.account_id).await?;
    let updated = sqlx::query!(
        "UPDATE two_factor_totp SET confirmed = true, last_step = $1 WHERE account_id = $2 AND confirmed = false",
        step,
        &session.account_id,
    )
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(ApiError::bad_request(
            "start setting up the authenticator app first",
        ));
    }
    let recovery_codes = after_factor_added(
        &mut tx,
        &session.account_id,
        before.enabled(),
        before.recovery_codes > 0,
        now,
    )
    .await?;
    tx.commit().await?;
    record_added(&state, &session, &ip, before.enabled()).await?;
    Ok(Json(EnrollResponse { recovery_codes }))
}

async fn record_added(
    state: &AppState,
    session: &Session,
    ip: &str,
    was_enabled: bool,
) -> ApiResult<()> {
    super::notify::two_factor_changed(
        state,
        &session.account_id,
        if was_enabled { "changed" } else { "enabled" },
        &session.device_name,
        ip,
    )
    .await;
    record_event(
        state,
        &session.account_id,
        if was_enabled {
            "two_factor_method_added"
        } else {
            "two_factor_enabled"
        },
        &session.device_name,
        &session.client_kind,
        ip,
    )
    .await
}

fn last_factor_conflict() -> ApiError {
    ApiError::conflict(
        "this is the last second factor; turn two-factor authentication off instead",
        serde_json::Value::Null,
    )
}

/// Removes the authenticator app while a security key remains.
pub async fn totp_remove(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
) -> ApiResult<StatusCode> {
    require_recent_login(&session)?;
    let factors = load_factors(&state.db, &session.account_id).await?;
    if !factors.totp {
        return Err(ApiError::NotFound);
    }
    if factors.credentials.is_empty() {
        return Err(last_factor_conflict());
    }
    let mut tx = state.db.as_account(&session.account_id).await?;
    sqlx::query!(
        "DELETE FROM two_factor_totp WHERE account_id = $1",
        &session.account_id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    super::notify::two_factor_changed(
        &state,
        &session.account_id,
        "changed",
        &session.device_name,
        &ip,
    )
    .await;
    record_event(
        &state,
        &session.account_id,
        "two_factor_method_removed",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Security keys ------------------------------------------------------------------

#[derive(Deserialize)]
pub struct OriginRequest {
    /// The page's `location.origin`; its host becomes the RP ID.
    #[serde(default)]
    origin: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterStartResponse {
    registration_id: String,
    /// `PublicKeyCredentialCreationOptions` with binary values as Base64url.
    public_key: serde_json::Value,
}

/// Starts registering a security key or passkey as a second factor.
pub async fn webauthn_register_start(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Json(req): Json<OriginRequest>,
) -> ApiResult<Json<RegisterStartResponse>> {
    require_recent_login(&session)?;
    let rp_id = webauthn::rp_id_from_origin(&req.origin).ok_or_else(|| {
        ApiError::bad_request("security keys need a page served over https (or from localhost)")
    })?;
    let factors = load_factors(&state.db, &session.account_id).await?;
    if factors.credentials.len() as i64 >= MAX_SECURITY_KEYS {
        return Err(ApiError::conflict(
            "too many security keys; remove one first",
            serde_json::Value::Null,
        ));
    }
    let email: String = sqlx::query_scalar!(
        "SELECT email FROM accounts WHERE id = $1",
        &session.account_id,
    )
    .fetch_one(&mut *state.db.as_account(&session.account_id).await?)
    .await?;
    let challenge = random::bytes::<32>().map_err(internal)?;
    let (registration_id, _) = create_challenge(
        &state,
        &session.account_id,
        NewChallenge {
            purpose: PURPOSE_REGISTER,
            webauthn_challenge: &challenge,
            rp_id: &rp_id,
            device_name: &session.device_name,
            client_kind: &session.client_kind,
            ip: &ip,
            device_token_hash: "",
        },
    )
    .await?;
    let exclude: Vec<CredentialDescriptor> = factors
        .credentials
        .iter()
        .filter(|c| c.rp_id == rp_id)
        .map(|c| CredentialDescriptor {
            kind: "public-key",
            id: c.credential_id.clone(),
        })
        .collect();
    let params: Vec<serde_json::Value> = webauthn::SUPPORTED_ALGORITHMS
        .iter()
        .map(|alg| serde_json::json!({ "type": "public-key", "alg": alg }))
        .collect();
    Ok(Json(RegisterStartResponse {
        registration_id,
        public_key: serde_json::json!({
            "challenge": encoding::encode(&challenge),
            "rp": { "id": rp_id, "name": ISSUER },
            "user": {
                "id": encoding::encode(session.account_id.as_bytes()),
                "name": email,
                "displayName": email,
            },
            "pubKeyCredParams": params,
            "timeout": WEBAUTHN_TIMEOUT_MS,
            "attestation": "none",
            "excludeCredentials": exclude,
            "authenticatorSelection": {
                "residentKey": "discouraged",
                "userVerification": "discouraged",
            },
        }),
    }))
}

/// A registration response from `navigator.credentials.create`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationResponse {
    client_data_json: String,
    attestation_object: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterFinishRequest {
    registration_id: String,
    /// For example "YubiKey 5C". Defaults to "Security key".
    #[serde(default)]
    name: String,
    credential: AttestationResponse,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterFinishResponse {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_codes: Option<Vec<String>>,
}

/// Verifies and stores a new security key.
pub async fn webauthn_register_finish(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Json(req): Json<RegisterFinishRequest>,
) -> ApiResult<(StatusCode, Json<RegisterFinishResponse>)> {
    require_recent_login(&session)?;
    let challenge = find_challenge(&state.db, &req.registration_id, PURPOSE_REGISTER)
        .await?
        .filter(|c| c.account_id == session.account_id)
        .ok_or(ApiError::TwoFactorExpired)?;
    if !consume_challenge(&state.db, &challenge.token_hash).await? {
        return Err(ApiError::TwoFactorExpired);
    }
    let client_data_json = validate::base64(
        "clientDataJson",
        &req.credential.client_data_json,
        validate::MAX_SMALL_LEN,
    )?;
    let attestation_object = validate::base64(
        "attestationObject",
        &req.credential.attestation_object,
        validate::MAX_SMALL_LEN,
    )?;
    let credential = webauthn::verify_registration(&webauthn::RegistrationInput {
        client_data_json: &client_data_json,
        attestation_object: &attestation_object,
        challenge: &challenge.webauthn_challenge,
        rp_id: &challenge.rp_id,
        require_user_verification: false,
    })
    .map_err(|e| ApiError::bad_request(e.to_string()))?;
    let name = Some(clean_device_name(&req.name))
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "Security key".to_owned());

    let before = load_factors(&state.db, &session.account_id).await?;
    let id = id::new_id().map_err(internal)?;
    let now = now_ms();
    let mut tx = state.db.as_account(&session.account_id).await?;
    let inserted = sqlx::query!(
        "INSERT INTO webauthn_credentials (id, account_id, credential_id, public_key, algorithm, sign_count, \
         rp_id, name, created_at, last_used_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
         ON CONFLICT DO NOTHING",
        &id,
        &session.account_id,
        encoding::encode(&credential.credential_id),
        encoding::encode(&credential.public_key),
        credential.algorithm,
        i64::from(credential.sign_count),
        &challenge.rp_id,
        &name,
        now,
        0i64,
    )
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::conflict(
            "this security key is already registered",
            serde_json::Value::Null,
        ));
    }
    let recovery_codes = after_factor_added(
        &mut tx,
        &session.account_id,
        before.enabled(),
        before.recovery_codes > 0,
        now,
    )
    .await?;
    tx.commit().await?;
    record_added(&state, &session, &ip, before.enabled()).await?;
    Ok((
        StatusCode::CREATED,
        Json(RegisterFinishResponse { id, recovery_codes }),
    ))
}

/// Removes one security key while another second factor remains.
pub async fn webauthn_remove(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    require_recent_login(&session)?;
    validate::id("security key id", &id)?;
    let factors = load_factors(&state.db, &session.account_id).await?;
    if !factors.credentials.iter().any(|c| c.id == id) {
        return Err(ApiError::NotFound);
    }
    if !factors.totp && factors.credentials.len() == 1 {
        return Err(last_factor_conflict());
    }
    let mut tx = state.db.as_account(&session.account_id).await?;
    sqlx::query!(
        "DELETE FROM webauthn_credentials WHERE id = $1 AND account_id = $2",
        &id,
        &session.account_id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    super::notify::two_factor_changed(
        &state,
        &session.account_id,
        "changed",
        &session.device_name,
        &ip,
    )
    .await;
    record_event(
        &state,
        &session.account_id,
        "two_factor_method_removed",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Recovery codes -----------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryCodesResponse {
    recovery_codes: Vec<String>,
}

/// Replaces all recovery codes with 10 new ones, shown once.
pub async fn recovery_codes_regenerate(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
) -> ApiResult<Json<RecoveryCodesResponse>> {
    require_recent_login(&session)?;
    if !load_factors(&state.db, &session.account_id)
        .await?
        .enabled()
    {
        return Err(ApiError::bad_request(
            "two-factor authentication is not turned on",
        ));
    }
    let mut tx = state.db.as_account(&session.account_id).await?;
    let recovery_codes = replace_recovery_codes(&mut tx, &session.account_id, now_ms()).await?;
    tx.commit().await?;
    super::notify::two_factor_changed(
        &state,
        &session.account_id,
        "changed",
        &session.device_name,
        &ip,
    )
    .await;
    record_event(
        &state,
        &session.account_id,
        "recovery_codes_regenerated",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    Ok(Json(RecoveryCodesResponse { recovery_codes }))
}

// --- Checking a factor while signed in, and turning 2FA off --------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyChallengeResponse {
    challenge_token: String,
    expires_at: i64,
    methods: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    webauthn: Option<RequestOptions>,
}

/// Starts a check of a second factor for the signed-in account, needed for
/// WebAuthn (it signs a server challenge) before turning 2FA off.
pub async fn verify_start(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Json(req): Json<OriginRequest>,
) -> ApiResult<Json<VerifyChallengeResponse>> {
    let factors = load_factors(&state.db, &session.account_id).await?;
    if !factors.enabled() {
        return Err(ApiError::bad_request(
            "two-factor authentication is not turned on",
        ));
    }
    let challenge = random::bytes::<32>().map_err(internal)?;
    let webauthn = request_options(&factors.credentials, &req.origin, &challenge);
    let (challenge_token, expires_at) = create_challenge(
        &state,
        &session.account_id,
        NewChallenge {
            purpose: PURPOSE_VERIFY,
            webauthn_challenge: &challenge,
            rp_id: webauthn.as_ref().map_or("", |w| w.rp_id.as_str()),
            device_name: &session.device_name,
            client_kind: &session.client_kind,
            ip: &ip,
            device_token_hash: "",
        },
    )
    .await?;
    Ok(Json(VerifyChallengeResponse {
        challenge_token,
        expires_at,
        methods: factors.methods(),
        webauthn,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisableRequest {
    #[serde(flatten)]
    factor: FactorInput,
    /// From `two-factor/challenge`; required for `webauthn`.
    #[serde(default)]
    challenge_token: String,
}

/// Turns two-factor authentication off: removes the authenticator app,
/// every security key and the recovery codes, and forgets remembered
/// devices. Needs a valid second factor or recovery code.
pub async fn disable(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Json(req): Json<DisableRequest>,
) -> ApiResult<StatusCode> {
    limit_ip(&state, &ip)?;
    let limits = failure_limits(&session.account_id, &ip);
    check_lockout(&state, &limits)?;
    if !load_factors(&state.db, &session.account_id)
        .await?
        .enabled()
    {
        return Err(ApiError::bad_request(
            "two-factor authentication is not turned on",
        ));
    }
    {
        // Organization policy: an organization can require two-factor sign-in.
        let mut conn = state.db.as_account(&session.account_id).await?;
        super::org_policy::ensure_two_factor_optional(&mut conn, &session.account_id).await?;
    }
    let challenge = if req.factor.method == "webauthn" {
        find_challenge(&state.db, &req.challenge_token, PURPOSE_VERIFY)
            .await?
            .filter(|c| c.account_id == session.account_id)
    } else {
        None
    };
    match verify_factor(&state, &session.account_id, &req.factor, challenge.as_ref()).await {
        Ok(_) => {}
        Err(ApiError::InvalidTwoFactorCode) => {
            record_failure(&state, &limits);
            record_event(
                &state,
                &session.account_id,
                "two_factor_failed",
                &session.device_name,
                &session.client_kind,
                &ip,
            )
            .await?;
            return Err(ApiError::InvalidTwoFactorCode);
        }
        Err(other) => return Err(other),
    }
    if let Some(challenge) = &challenge
        && !consume_challenge(&state.db, &challenge.token_hash).await?
    {
        return Err(ApiError::TwoFactorExpired);
    }
    let mut tx = state.db.as_account(&session.account_id).await?;
    for statement in [
        "DELETE FROM two_factor_totp WHERE account_id = $1",
        "DELETE FROM webauthn_credentials WHERE account_id = $1",
        "DELETE FROM recovery_codes WHERE account_id = $1",
        "DELETE FROM two_factor_challenges WHERE account_id = $1",
    ] {
        sqlx::query(statement)
            .bind(&session.account_id)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query!(
        "UPDATE device_tokens SET two_factor_until = 0 WHERE account_id = $1",
        &session.account_id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    super::notify::two_factor_changed(
        &state,
        &session.account_id,
        "disabled",
        &session.device_name,
        &ip,
    )
    .await;
    record_event(
        &state,
        &session.account_id,
        "two_factor_disabled",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Account recovery -----------------------------------------------------------------

/// The second factors a recovery by code can be finished with, or `None`
/// when the account has no two-factor sign-in. Security keys are not offered
/// there yet (see `docs/architecture/recovery.md`).
pub(crate) async fn recovery_methods(
    state: &AppState,
    account_id: &str,
) -> ApiResult<Option<Vec<&'static str>>> {
    let factors = load_factors(&state.db, account_id).await?;
    if !factors.enabled() {
        return Ok(None);
    }
    Ok(Some(
        factors
            .methods()
            .into_iter()
            .filter(|m| *m != "webauthn")
            .collect(),
    ))
}

/// Checks a code (`totp` or `recovery`) for a recovery by code, with the
/// same lockout and replay rules as a sign-in.
pub(crate) async fn verify_recovery_factor(
    state: &AppState,
    account_id: &str,
    ip: &str,
    method: &str,
    code: &str,
) -> ApiResult<()> {
    let limits = failure_limits(account_id, ip);
    check_lockout(state, &limits)?;
    if method != "totp" && method != "recovery" {
        return Err(ApiError::bad_request("method must be totp or recovery"));
    }
    let factor = FactorInput {
        method: method.to_owned(),
        code: code.to_owned(),
        webauthn: None,
    };
    match verify_factor(state, account_id, &factor, None).await {
        Ok(Verified::Recovery) => {
            record_event(state, account_id, "recovery_code_used", "", "", ip).await?;
            Ok(())
        }
        Ok(_) => Ok(()),
        Err(ApiError::InvalidTwoFactorCode) => {
            record_failure(state, &limits);
            record_event(state, account_id, "two_factor_failed", "", "", ip).await?;
            Err(ApiError::InvalidTwoFactorCode)
        }
        Err(other) => Err(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(id: &str, rp_id: &str) -> Credential {
        Credential {
            id: id.into(),
            credential_id: format!("cred-{id}"),
            name: String::new(),
            rp_id: rp_id.into(),
            created_at: 0,
            last_used_at: 0,
        }
    }

    #[test]
    fn request_options_prefer_keys_for_the_origin() {
        let keys = [
            credential("a", "new.example"),
            credential("b", "vault.example"),
            credential("c", "vault.example"),
        ];
        let options = request_options(&keys, "https://vault.example", &[1; 32]).unwrap();
        assert_eq!(options.rp_id, "vault.example");
        assert_eq!(options.allow_credentials.len(), 2);
        // Unknown origin: the newest key's RP ID.
        let options = request_options(&keys, "", &[1; 32]).unwrap();
        assert_eq!(options.rp_id, "new.example");
        assert_eq!(options.allow_credentials.len(), 1);
        assert!(request_options(&[], "https://vault.example", &[1; 32]).is_none());
    }

    #[test]
    fn failures_count_per_account_and_ip() {
        let limits = failure_limits("a", "1.2.3.4");
        assert_eq!(
            limits[0],
            ("fail-2fa-account:a".to_owned(), MAX_FAILURES_PER_ACCOUNT)
        );
        assert_eq!(
            limits[1],
            ("fail-2fa-ip:1.2.3.4".to_owned(), MAX_FAILURES_PER_IP)
        );
    }
}
