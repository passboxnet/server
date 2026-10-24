//! Items. The server stores each item as one encrypted blob plus its
//! revision. Writes use optimistic concurrency: a client sends the revision it
//! wants to create, which must be exactly one higher than the stored one.
//! Deleted items stay as tombstones so other devices learn about the deletion.

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use serde_json::json;

use super::auth::Session;
use super::validate;
use super::vaults::WriteResponse;
use crate::db::{self, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutItemRequest {
    vault_id: String,
    revision: i64,
    encrypted_data: String,
}

/// Returns the vault and revision of an item, if the caller owns it.
async fn current_item(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    account_id: &str,
    item_id: &str,
) -> ApiResult<Option<(String, i64)>> {
    let row: Option<(String, i64, String)> = sqlx::query_as(
        "SELECT items.vault_id, items.revision, vaults.account_id FROM items \
         JOIN vaults ON vaults.id = items.vault_id WHERE items.id = $1",
    )
    .bind(item_id)
    .fetch_optional(&mut **tx)
    .await?;
    match row {
        // Item IDs are random; treat foreign items like missing ones but never overwrite them.
        Some((_, _, owner)) if owner != account_id => Err(ApiError::NotFound),
        Some((vault_id, revision, _)) => Ok(Some((vault_id, revision))),
        None => Ok(None),
    }
}

fn revision_conflict(current: i64) -> ApiError {
    ApiError::conflict(
        "item was changed by another device",
        json!({ "currentRevision": current }),
    )
}

/// Creates or updates an item.
pub async fn put(
    State(state): State<AppState>,
    session: Session,
    Path(item_id): Path<String>,
    Json(req): Json<PutItemRequest>,
) -> ApiResult<Json<WriteResponse>> {
    validate::id("item id", &item_id)?;
    validate::id("vaultId", &req.vault_id)?;
    validate::revision(req.revision)?;
    validate::base64("encryptedData", &req.encrypted_data, validate::MAX_ITEM_LEN)?;

    let mut tx = crate::db::begin_write(&state.db).await?;
    let owns_vault: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM vaults WHERE id = $1 AND account_id = $2")
            .bind(&req.vault_id)
            .bind(&session.account_id)
            .fetch_optional(&mut *tx)
            .await?;
    if owns_vault.is_none() {
        return Err(ApiError::NotFound);
    }

    let now = now_ms();
    match current_item(&mut tx, &session.account_id, &item_id).await? {
        None => {
            if req.revision != 1 {
                return Err(revision_conflict(0));
            }
            let seq = db::next_seq(&mut tx).await?;
            sqlx::query(
                "INSERT INTO items (id, vault_id, encrypted_data, revision, deleted, seq, created_at, updated_at) \
                 VALUES ($1, $2, $3, 1, 0, $4, $5, $6)",
            )
            .bind(&item_id)
            .bind(&req.vault_id)
            .bind(&req.encrypted_data)
            .bind(seq)
            .bind(now)
            .bind(now)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(Json(WriteResponse { revision: 1, seq }))
        }
        Some((vault_id, current)) => {
            if vault_id != req.vault_id {
                return Err(ApiError::bad_request(
                    "moving items between vaults is not supported yet",
                ));
            }
            if req.revision != current + 1 {
                return Err(revision_conflict(current));
            }
            let seq = db::next_seq(&mut tx).await?;
            sqlx::query(
                "UPDATE items SET encrypted_data = $1, revision = $2, deleted = 0, seq = $3, updated_at = $4 \
                 WHERE id = $5",
            )
            .bind(&req.encrypted_data)
            .bind(req.revision)
            .bind(seq)
            .bind(now)
            .bind(&item_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(Json(WriteResponse {
                revision: req.revision,
                seq,
            }))
        }
    }
}

#[derive(Deserialize)]
pub struct DeleteQuery {
    /// The new revision of the tombstone; must be one higher than the stored one.
    revision: i64,
}

/// Deletes an item, keeping a tombstone without data.
pub async fn delete(
    State(state): State<AppState>,
    session: Session,
    Path(item_id): Path<String>,
    Query(query): Query<DeleteQuery>,
) -> ApiResult<Json<WriteResponse>> {
    validate::id("item id", &item_id)?;
    validate::revision(query.revision)?;

    let mut tx = crate::db::begin_write(&state.db).await?;
    let (_, current) = current_item(&mut tx, &session.account_id, &item_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if query.revision != current + 1 {
        return Err(revision_conflict(current));
    }
    let seq = db::next_seq(&mut tx).await?;
    sqlx::query(
        "UPDATE items SET encrypted_data = NULL, revision = $1, deleted = 1, seq = $2, updated_at = $3 WHERE id = $4",
    )
    .bind(query.revision)
    .bind(seq)
    .bind(now_ms())
    .bind(&item_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(WriteResponse {
        revision: query.revision,
        seq,
    }))
}
