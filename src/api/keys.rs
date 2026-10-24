//! Account key pairs and the key directory (append-only, hash-chained log
//! of public bundles with a signed head). See `passbox_core::directory`.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use passbox_core::directory::{
    self, LogEntry, LogHead, LookupResponse, MAX_LOOKUP_ENTRIES, SignedHead,
};
use passbox_core::encoding;
use passbox_core::identity::SignedBundle;
use passbox_core::keyring::{ACCOUNT_KEY_VERSION, AccountKeysUpload};
use serde::{Deserialize, Serialize};

use super::auth::{Session, record_event};
use super::validate;
use crate::db::{self, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::security::ClientIp;
use crate::state::AppState;

/// Most log entries returned by one `GET /keys/log` request.
const MAX_LOG_PAGE: i64 = 1000;

fn to_u32(value: i64) -> ApiResult<u32> {
    u32::try_from(value).map_err(|_| ApiError::Internal(anyhow::anyhow!("value out of range")))
}

fn to_u64(value: i64) -> ApiResult<u64> {
    u64::try_from(value).map_err(|_| ApiError::Internal(anyhow::anyhow!("value out of range")))
}

/// Publishes the account's first key pairs and appends them to the log.
/// Publishing the same bundle again is accepted (retries); a different one
/// is a conflict (key rotation is not supported yet).
pub async fn publish(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Json(req): Json<AccountKeysUpload>,
) -> ApiResult<StatusCode> {
    validate::base64("bundle", &req.bundle, validate::MAX_SMALL_LEN)?;
    validate::base64("bundleSignature", &req.bundle_signature, 256)?;
    validate::base64(
        "encryptedPrivate",
        &req.encrypted_private,
        validate::MAX_SMALL_LEN,
    )?;
    let bundle = SignedBundle::parse(&req.bundle, &req.bundle_signature)
        .map_err(|e| ApiError::bad_request(format!("invalid bundle: {e}")))?;
    if bundle.bundle.account_id != session.account_id {
        return Err(ApiError::bad_request(
            "the bundle belongs to another account",
        ));
    }
    if bundle.bundle.key_version != req.key_version || req.key_version != ACCOUNT_KEY_VERSION {
        return Err(ApiError::bad_request("unsupported key version"));
    }
    let bundle_hash = encoding::encode(&bundle.hash());

    let mut tx = db::begin_write(&state.db).await?;
    let existing: Option<String> =
        sqlx::query_scalar("SELECT bundle_hash FROM account_keys WHERE account_id = $1")
            .bind(&session.account_id)
            .fetch_optional(&mut *tx)
            .await?;
    match existing {
        Some(hash) if hash == bundle_hash => return Ok(StatusCode::NO_CONTENT),
        Some(_) => {
            return Err(ApiError::conflict(
                "this account already published key pairs",
                serde_json::Value::Null,
            ));
        }
        None => {}
    }
    let now = now_ms();
    let seq = append_to_log(
        &mut tx,
        &session.account_id,
        req.key_version,
        &bundle.hash(),
        now,
    )
    .await?;
    sqlx::query(
        "INSERT INTO account_keys (account_id, key_version, bundle, bundle_signature, bundle_hash, \
         encrypted_private, log_seq, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&session.account_id)
    .bind(i64::from(req.key_version))
    .bind(&req.bundle)
    .bind(&req.bundle_signature)
    .bind(&bundle_hash)
    .bind(&req.encrypted_private)
    .bind(seq)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    record_event(
        &state,
        &session.account_id,
        "keys_published",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Appends an entry to the key log inside the caller's transaction. The
/// counter row serializes concurrent appends on PostgreSQL.
async fn append_to_log(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    account_id: &str,
    key_version: u32,
    bundle_hash: &[u8; 32],
    now: i64,
) -> ApiResult<i64> {
    let seq: i64 = sqlx::query_scalar(
        "UPDATE counters SET value = value + 1 WHERE name = 'key_log_seq' RETURNING value",
    )
    .fetch_one(&mut **tx)
    .await?;
    let prev: Option<String> = sqlx::query_scalar("SELECT entry_hash FROM key_log WHERE seq = $1")
        .bind(seq - 1)
        .fetch_optional(&mut **tx)
        .await?;
    let prev: [u8; 32] = match prev {
        Some(hash) => encoding::decode(&hash)
            .ok()
            .and_then(|h| h.try_into().ok())
            .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("corrupt key log")))?,
        None if seq == 1 => [0; 32],
        None => return Err(ApiError::Internal(anyhow::anyhow!("key log has a gap"))),
    };
    let entry = directory::entry_hash(to_u64(seq)?, account_id, key_version, bundle_hash, &prev);
    sqlx::query(
        "INSERT INTO key_log (seq, account_id, key_version, bundle_hash, prev_hash, entry_hash, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(seq)
    .bind(account_id)
    .bind(i64::from(key_version))
    .bind(encoding::encode(bundle_hash))
    .bind(encoding::encode(&prev))
    .bind(encoding::encode(&entry))
    .bind(now)
    .execute(&mut **tx)
    .await?;
    Ok(seq)
}

/// The account's own keys, including the encrypted private keys.
pub async fn own(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<Json<AccountKeysUpload>> {
    let row: Option<(i64, String, String, String)> = sqlx::query_as(
        "SELECT key_version, bundle, bundle_signature, encrypted_private FROM account_keys \
         WHERE account_id = $1 ORDER BY key_version DESC LIMIT 1",
    )
    .bind(&session.account_id)
    .fetch_optional(&state.db)
    .await?;
    let (key_version, bundle, bundle_signature, encrypted_private) =
        row.ok_or(ApiError::NotFound)?;
    Ok(Json(AccountKeysUpload {
        key_version: to_u32(key_version)?,
        bundle,
        bundle_signature,
        encrypted_private,
    }))
}

async fn current_head(state: &AppState) -> ApiResult<SignedHead> {
    let row: Option<(i64, String)> =
        sqlx::query_as("SELECT seq, entry_hash FROM key_log ORDER BY seq DESC LIMIT 1")
            .fetch_optional(&state.db)
            .await?;
    let (size, root) = match row {
        Some((seq, hash)) => (
            to_u64(seq)?,
            encoding::decode(&hash)
                .ok()
                .and_then(|h| h.try_into().ok())
                .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("corrupt key log")))?,
        ),
        None => (0, [0; 32]),
    };
    Ok(state.log_signer.sign(&LogHead {
        size,
        root,
        timestamp: now_ms(),
    }))
}

/// The signed head of the key log.
pub async fn head(State(state): State<AppState>, _session: Session) -> ApiResult<Json<SignedHead>> {
    Ok(Json(current_head(&state).await?))
}

#[derive(Deserialize)]
pub struct LogQuery {
    #[serde(default = "first_seq")]
    from: i64,
    #[serde(default = "default_page")]
    limit: i64,
}

fn first_seq() -> i64 {
    1
}

fn default_page() -> i64 {
    MAX_LOG_PAGE
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogPage {
    entries: Vec<LogEntry>,
    head: SignedHead,
}

async fn entries(state: &AppState, from: i64, to: i64) -> ApiResult<Vec<LogEntry>> {
    let rows: Vec<(i64, String, i64, String, String)> = sqlx::query_as(
        "SELECT seq, account_id, key_version, bundle_hash, prev_hash FROM key_log \
         WHERE seq >= $1 AND seq <= $2 ORDER BY seq",
    )
    .bind(from)
    .bind(to)
    .fetch_all(&state.db)
    .await?;
    rows.into_iter()
        .map(|(seq, account_id, key_version, bundle_hash, prev_hash)| {
            Ok(LogEntry {
                seq: to_u64(seq)?,
                account_id,
                key_version: to_u32(key_version)?,
                bundle_hash,
                prev_hash,
            })
        })
        .collect()
}

/// A page of log entries (for auditing the whole log).
pub async fn log(
    State(state): State<AppState>,
    _session: Session,
    Query(query): Query<LogQuery>,
) -> ApiResult<Json<LogPage>> {
    let head = current_head(&state).await?;
    let size = i64::try_from(
        head.verify()
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("{e}")))?
            .0
            .size,
    )
    .unwrap_or(i64::MAX);
    let from = query.from.max(1);
    let to = size.min(from.saturating_add(query.limit.clamp(1, MAX_LOG_PAGE) - 1));
    Ok(Json(LogPage {
        entries: entries(&state, from, to).await?,
        head,
    }))
}

#[derive(Deserialize)]
pub struct LookupQuery {
    /// Size of the head the client verified last (0 for none).
    #[serde(default)]
    since: i64,
}

/// An account's current bundle with a proof against the signed head.
pub async fn lookup(
    State(state): State<AppState>,
    _session: Session,
    Path(account_id): Path<String>,
    Query(query): Query<LookupQuery>,
) -> ApiResult<Json<LookupResponse>> {
    validate::id("account id", &account_id)?;
    if query.since < 0 {
        return Err(ApiError::bad_request("since must not be negative"));
    }
    let head = current_head(&state).await?;
    let size = i64::try_from(
        head.verify()
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("{e}")))?
            .0
            .size,
    )
    .unwrap_or(i64::MAX);
    let row: Option<(String, String, i64)> = sqlx::query_as(
        "SELECT bundle, bundle_signature, log_seq FROM account_keys WHERE account_id = $1 \
         ORDER BY key_version DESC LIMIT 1",
    )
    .bind(&account_id)
    .fetch_optional(&state.db)
    .await?;
    let (bundle, bundle_signature, seq) = row.ok_or(ApiError::NotFound)?;
    let since = query.since.min(size);
    let from = if since == 0 { seq } else { seq.min(since + 1) };
    if size - from + 1 > MAX_LOOKUP_ENTRIES as i64 {
        return Err(ApiError::bad_request(
            "the proof is too large; verify the log in pages first",
        ));
    }
    Ok(Json(LookupResponse {
        bundle,
        bundle_signature,
        seq: to_u64(seq)?,
        entries: entries(&state, from, size).await?,
        head,
    }))
}
