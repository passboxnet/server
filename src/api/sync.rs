//! Incremental sync. Clients send the cursor of their last sync and receive
//! every vault and item that changed since then, plus a new cursor.

use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};

use super::auth::Session;
use crate::db;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct SyncQuery {
    /// Cursor from the previous sync; omit or pass 0 for a full sync.
    #[serde(default)]
    since: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncVault {
    id: String,
    encrypted_key: String,
    encrypted_meta: String,
    revision: i64,
    updated_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncItem {
    id: String,
    vault_id: String,
    revision: i64,
    /// `None` for deleted items.
    encrypted_data: Option<String>,
    deleted: bool,
    updated_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    cursor: i64,
    vaults: Vec<SyncVault>,
    items: Vec<SyncItem>,
}

pub async fn sync(
    State(state): State<AppState>,
    session: Session,
    Query(query): Query<SyncQuery>,
) -> ApiResult<Json<SyncResponse>> {
    if query.since < 0 {
        return Err(ApiError::bad_request("since must not be negative"));
    }
    // Read the cursor first: anything committed later has a higher sequence
    // number and will be included in the next sync.
    let cursor = db::current_seq(&state.db).await?;

    let vaults: Vec<(String, String, String, i64, i64)> = sqlx::query_as(
        "SELECT id, encrypted_key, encrypted_meta, revision, updated_at FROM vaults \
         WHERE account_id = $1 AND seq > $2 AND seq <= $3 ORDER BY seq",
    )
    .bind(&session.account_id)
    .bind(query.since)
    .bind(cursor)
    .fetch_all(&state.db)
    .await?;

    let items: Vec<(String, String, i64, Option<String>, i64, i64)> = sqlx::query_as(
        "SELECT items.id, items.vault_id, items.revision, items.encrypted_data, items.deleted, items.updated_at \
         FROM items JOIN vaults ON vaults.id = items.vault_id \
         WHERE vaults.account_id = $1 AND items.seq > $2 AND items.seq <= $3 ORDER BY items.seq",
    )
    .bind(&session.account_id)
    .bind(query.since)
    .bind(cursor)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(SyncResponse {
        cursor,
        vaults: vaults
            .into_iter()
            .map(
                |(id, encrypted_key, encrypted_meta, revision, updated_at)| SyncVault {
                    id,
                    encrypted_key,
                    encrypted_meta,
                    revision,
                    updated_at,
                },
            )
            .collect(),
        items: items
            .into_iter()
            .map(
                |(id, vault_id, revision, encrypted_data, deleted, updated_at)| SyncItem {
                    id,
                    vault_id,
                    revision,
                    encrypted_data,
                    deleted: deleted != 0,
                    updated_at,
                },
            )
            .collect(),
    }))
}
