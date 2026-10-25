//! File attachments (G2). Clients encrypt files on the device
//! (`passbox_core::file_crypto`) and upload the blob for an item; the
//! file's key, name and type are stored in the encrypted item. The server
//! checks access through the item's vault and enforces size limits and
//! storage quotas (`PASSBOX_ATTACHMENT_MAX_MB`, `PASSBOX_ATTACHMENT_QUOTA_MB`,
//! `PASSBOX_ORG_ATTACHMENT_QUOTA_MB`; 0 means unlimited).

use std::time::Duration;

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgConnection;

use super::access;
use super::auth::Session;
use super::validate;
use crate::blobs::PutOutcome;
use crate::db::{Job, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Attachments per item.
pub const MAX_PER_ITEM: i64 = 50;
const MIB: u64 = 1024 * 1024;

/// Limits for attachments, from the configuration.
#[derive(Debug, Clone, Copy)]
pub struct AttachmentLimits {
    /// Largest encrypted blob, in bytes.
    pub max_file: u64,
    /// Storage per account for its personal vaults (0 = unlimited).
    pub account_quota: u64,
    /// Storage per organization for its shared vaults (0 = unlimited).
    pub org_quota: u64,
}

impl AttachmentLimits {
    pub fn from_mib(max_file: u64, account_quota: u64, org_quota: u64) -> Self {
        Self {
            max_file: max_file.saturating_mul(MIB),
            account_quota: account_quota.saturating_mul(MIB),
            org_quota: org_quota.saturating_mul(MIB),
        }
    }
}

impl Default for AttachmentLimits {
    fn default() -> Self {
        Self::from_mib(100, 0, 0)
    }
}

/// Who the storage of a vault counts against: `("account", id)` for a
/// personal vault, `("org", id)` for a shared one.
pub async fn owner_of(conn: &mut PgConnection, vault_id: &str) -> ApiResult<(String, String)> {
    let (account_id, org_id): (String, Option<String>) = sqlx::query!(
        "SELECT account_id, org_id FROM vaults WHERE id = $1",
        vault_id,
    )
    .map(|row| (row.account_id, row.org_id))
    .fetch_optional(&mut *conn)
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(match org_id {
        Some(org) => ("org".into(), org),
        None => ("account".into(), account_id),
    })
}

fn quota_for(state: &AppState, owner: &(String, String)) -> u64 {
    if owner.0 == "org" {
        state.attachment_limits.org_quota
    } else {
        state.attachment_limits.account_quota
    }
}

async fn used_by(conn: &mut PgConnection, owner: &(String, String)) -> ApiResult<u64> {
    let used: i64 = sqlx::query_scalar!(
        r#"SELECT CAST(COALESCE(SUM(size), 0) AS BIGINT) AS "used!" FROM attachments
           WHERE owner_type = $1 AND owner_id = $2"#,
        &owner.0,
        &owner.1,
    )
    .fetch_one(&mut *conn)
    .await?;
    Ok(u64::try_from(used).unwrap_or(0))
}

fn quota_exceeded() -> ApiError {
    ApiError::forbidden(
        "quota_exceeded",
        "the storage for attachments is full; delete attachments or ask the server's admin for more space",
    )
}

/// 403 `quota_exceeded` if `extra` more bytes do not fit the owner's quota.
pub async fn ensure_quota(
    state: &AppState,
    conn: &mut PgConnection,
    owner: &(String, String),
    extra: i64,
) -> ApiResult<()> {
    let quota = quota_for(state, owner);
    if quota == 0 {
        return Ok(());
    }
    let used = used_by(conn, owner).await?;
    if used.saturating_add(u64::try_from(extra).unwrap_or(0)) > quota {
        return Err(quota_exceeded());
    }
    Ok(())
}

/// The item's vault, if the account can write to it (404/403 otherwise).
async fn writable_item(
    conn: &mut PgConnection,
    account_id: &str,
    item_id: &str,
) -> ApiResult<String> {
    let vault_id: String = sqlx::query_scalar!(
        "SELECT vault_id FROM items WHERE id = $1 AND deleted = false",
        item_id,
    )
    .fetch_optional(&mut *conn)
    .await?
    .ok_or(ApiError::NotFound)?;
    if access::vault_access(conn, &vault_id, account_id)
        .await?
        .is_none()
    {
        return Err(ApiError::NotFound);
    }
    access::require_vault_write(conn, &vault_id, account_id).await?;
    Ok(vault_id)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadQuery {
    item_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadResponse {
    id: String,
    size: u64,
}

/// `PUT /api/v1/attachments/{id}?itemId=…`: stores the encrypted blob
/// (`application/octet-stream`). IDs come from the client (`new_id`);
/// a blob cannot be replaced.
pub async fn upload(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
    Query(query): Query<UploadQuery>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<(StatusCode, Json<UploadResponse>)> {
    validate::id("attachment id", &id)?;
    validate::id("itemId", &query.item_id)?;
    let declared: Option<u64> = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok());

    // Check access and space before reading the body.
    let max_len = {
        let mut conn = state.db.as_account(&session.account_id).await?;
        let vault_id = writable_item(&mut conn, &session.account_id, &query.item_id).await?;
        let exists: Option<String> =
            sqlx::query_scalar!("SELECT id FROM attachments WHERE id = $1", &id,)
                .fetch_optional(&mut *conn)
                .await?;
        if exists.is_some() {
            return Err(ApiError::conflict(
                "an attachment with this ID exists",
                json!({}),
            ));
        }
        let count: i64 = sqlx::query_scalar!(
            "SELECT COUNT(*) AS \"count!\" FROM attachments WHERE item_id = $1",
            &query.item_id,
        )
        .fetch_one(&mut *conn)
        .await?;
        if count >= MAX_PER_ITEM {
            return Err(ApiError::bad_request(format!(
                "an item can have at most {MAX_PER_ITEM} attachments"
            )));
        }
        let owner = owner_of(&mut conn, &vault_id).await?;
        let quota = quota_for(&state, &owner);
        let mut max_len = state.attachment_limits.max_file;
        if quota > 0 {
            let left = quota.saturating_sub(used_by(&mut conn, &owner).await?);
            if left == 0 {
                return Err(quota_exceeded());
            }
            max_len = max_len.min(left);
        }
        if declared.is_some_and(|len| len > max_len) {
            return Err(too_large(&state, max_len));
        }
        max_len
    };

    let size = match state.blobs.put(&id, body, max_len).await {
        Ok(PutOutcome::Stored(size)) => size,
        Ok(PutOutcome::TooLarge) => return Err(too_large(&state, max_len)),
        Err(e) => return Err(ApiError::Internal(e)),
    };
    if size < (passbox_core::file_crypto::HEADER_LEN + passbox_core::file_crypto::TAG_LEN) as u64 {
        let _ = state.blobs.delete(&id).await;
        return Err(ApiError::bad_request("the upload is not an encrypted file"));
    }

    let result: ApiResult<()> = async {
        let mut tx = state.db.as_account(&session.account_id).await?;
        let vault_id = writable_item(&mut tx, &session.account_id, &query.item_id).await?;
        let owner = owner_of(&mut tx, &vault_id).await?;
        ensure_quota(&state, &mut tx, &owner, i64::try_from(size).unwrap_or(i64::MAX)).await?;
        sqlx::query!(
            "INSERT INTO attachments (id, item_id, vault_id, uploaded_by, owner_type, owner_id, size, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &id,
            &query.item_id,
            &vault_id,
            &session.account_id,
            &owner.0,
            &owner.1,
            i64::try_from(size).unwrap_or(i64::MAX),
            now_ms(),
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }
    .await;
    if let Err(e) = result {
        let _ = state.blobs.delete(&id).await;
        return Err(e);
    }
    Ok((StatusCode::CREATED, Json(UploadResponse { id, size })))
}

fn too_large(state: &AppState, max_len: u64) -> ApiError {
    if max_len < state.attachment_limits.max_file {
        quota_exceeded()
    } else {
        ApiError::forbidden(
            "file_too_large",
            format!(
                "files can be at most {} MB on this server",
                state.attachment_limits.max_file / MIB
            ),
        )
    }
}

/// `GET /api/v1/attachments/{id}`: the encrypted blob, for anyone who can
/// read the item.
pub async fn download(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    validate::id("attachment id", &id)?;
    {
        let mut conn = state.db.as_account(&session.account_id).await?;
        let vault_id: String =
            sqlx::query_scalar!("SELECT vault_id FROM attachments WHERE id = $1", &id,)
                .fetch_optional(&mut *conn)
                .await?
                .ok_or(ApiError::NotFound)?;
        if access::vault_access(&mut conn, &vault_id, &session.account_id)
            .await?
            .is_none()
        {
            return Err(ApiError::NotFound);
        }
    }
    let (size, body) = state
        .blobs
        .get(&id)
        .await
        .map_err(ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
            (header::CONTENT_LENGTH, size.to_string()),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
        body,
    )
        .into_response())
}

/// `DELETE /api/v1/attachments/{id}`.
pub async fn delete(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    validate::id("attachment id", &id)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    let item_id: String =
        sqlx::query_scalar!("SELECT item_id FROM attachments WHERE id = $1", &id,)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(ApiError::NotFound)?;
    writable_item(&mut tx, &session.account_id, &item_id).await?;
    sqlx::query!("DELETE FROM attachments WHERE id = $1", &id,)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    if let Err(e) = state.blobs.delete(&id).await {
        tracing::warn!(error = ?e, "could not delete an attachment blob; cleanup will retry");
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Removes the attachments of a permanently deleted item.
pub async fn delete_for_item(state: &AppState, account_id: &str, item_id: &str) -> ApiResult<()> {
    let mut tx = state.db.as_account(account_id).await?;
    let ids: Vec<String> = sqlx::query_scalar!(
        "DELETE FROM attachments WHERE item_id = $1 RETURNING id",
        item_id,
    )
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    for id in ids {
        let _ = state.blobs.delete(&id).await;
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Usage {
    /// `account` or an organization ID.
    owner: String,
    used: u64,
    /// 0 = unlimited.
    quota: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageResponse {
    max_file_size: u64,
    /// Personal vaults first, then each organization the account is in.
    usage: Vec<Usage>,
}

/// `GET /api/v1/attachments/usage`: limits and storage used.
pub async fn usage(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<Json<UsageResponse>> {
    let mut conn = state.db.as_account(&session.account_id).await?;
    let owner = ("account".to_owned(), session.account_id.clone());
    let mut usage = vec![Usage {
        owner: "account".into(),
        used: used_by(&mut conn, &owner).await?,
        quota: state.attachment_limits.account_quota,
    }];
    let orgs: Vec<String> = sqlx::query_scalar!(
        "SELECT org_id FROM org_members WHERE account_id = $1 AND status = 'confirmed' ORDER BY org_id",
        &session.account_id,
    )
    .fetch_all(&mut *conn)
    .await?;
    for org in orgs {
        let owner = ("org".to_owned(), org.clone());
        usage.push(Usage {
            owner: org,
            used: used_by(&mut conn, &owner).await?,
            quota: state.attachment_limits.org_quota,
        });
    }
    Ok(Json(UsageResponse {
        max_file_size: state.attachment_limits.max_file,
        usage,
    }))
}

/// Deletes blobs that no attachment row refers to any more (vaults or
/// organizations deleted, interrupted uploads), once they are an hour old.
pub async fn sweep(state: &AppState) -> anyhow::Result<usize> {
    let mut removed = 0;
    for (id, age_ms) in state.blobs.list().await? {
        if age_ms < 60 * 60 * 1000 {
            continue;
        }
        // The worker context sees every attachment row, so no referenced
        // blob is ever taken for an orphan.
        let mut tx = state.db.system(Job::Attachments).await?;
        let known: Option<String> =
            sqlx::query_scalar!("SELECT id FROM attachments WHERE id = $1", &id,)
                .fetch_optional(&mut *tx)
                .await?;
        drop(tx);
        if known.is_none() {
            state.blobs.delete(&id).await?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// Runs [`sweep`] every hour.
pub fn spawn_sweeper(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60 * 60));
        loop {
            interval.tick().await;
            match sweep(&state).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(removed = n, "removed unreferenced attachment blobs"),
                Err(e) => tracing::warn!(error = ?e, "attachment cleanup failed"),
            }
        }
    });
}
