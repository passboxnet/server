//! Items. The server stores each item as one encrypted blob plus its
//! revision. Writes use optimistic concurrency: a client sends the revision it
//! wants to create, which must be exactly one higher than the stored one.
//! Deleted items stay as tombstones so other devices learn about the deletion.

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use serde_json::json;

use super::access;
use super::auth::Session;
use super::validate;
use super::vaults::WriteResponse;
use crate::db::{self, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::security::ClientIp;
use crate::state::AppState;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutItemRequest {
    vault_id: String,
    revision: i64,
    encrypted_data: String,
    /// The vault key epoch the data is encrypted with (0 for personal vaults).
    #[serde(default)]
    key_epoch: i64,
}

/// Returns the vault and revision of an item, if the caller may see it.
async fn current_item(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    account_id: &str,
    item_id: &str,
) -> ApiResult<Option<(String, i64)>> {
    let row: Option<(String, i64)> =
        sqlx::query_as("SELECT vault_id, revision FROM items WHERE id = $1")
            .bind(item_id)
            .fetch_optional(&mut **tx)
            .await?;
    match row {
        Some((vault_id, revision)) => {
            // Item IDs are random; treat foreign items like missing ones but
            // never overwrite them.
            if access::vault_access(tx, &vault_id, account_id)
                .await?
                .is_none()
            {
                return Err(ApiError::NotFound);
            }
            Ok(Some((vault_id, revision)))
        }
        None => Ok(None),
    }
}

/// Requires write access to the vault and the vault's current key epoch.
async fn require_write(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    account_id: &str,
    vault_id: &str,
    key_epoch: i64,
) -> ApiResult<access::VaultAccess> {
    let access = access::require_vault_write(tx, vault_id, account_id).await?;
    let current = match &access {
        access::VaultAccess::Personal => 0,
        access::VaultAccess::Shared { key_epoch, .. } => *key_epoch,
    };
    if key_epoch != current {
        return Err(ApiError::conflict(
            "the vault's key was rotated; encrypt with the current key epoch",
            json!({ "currentKeyEpoch": current }),
        ));
    }
    Ok(access)
}

/// The organization of a shared vault (for the audit log).
fn shared_org(access: &access::VaultAccess) -> Option<&str> {
    match access {
        access::VaultAccess::Shared { org_id, .. } => Some(org_id),
        access::VaultAccess::Personal => None,
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
    ClientIp(ip): ClientIp,
    session: Session,
    Path(item_id): Path<String>,
    Json(req): Json<PutItemRequest>,
) -> ApiResult<Json<WriteResponse>> {
    validate::id("item id", &item_id)?;
    validate::id("vaultId", &req.vault_id)?;
    validate::revision(req.revision)?;
    validate::base64("encryptedData", &req.encrypted_data, validate::MAX_ITEM_LEN)?;

    let mut tx = crate::db::begin_write(&state.db).await?;
    let vault_access =
        require_write(&mut tx, &session.account_id, &req.vault_id, req.key_epoch).await?;
    let audit_org = shared_org(&vault_access).map(str::to_owned);
    let actor = super::org_audit::Actor::of(&session, &ip);

    let now = now_ms();
    match current_item(&mut tx, &session.account_id, &item_id).await? {
        None => {
            if req.revision != 1 {
                return Err(revision_conflict(0));
            }
            if audit_org.is_none() {
                // Policy D2: no new items in personal vaults if an
                // organization turned them off.
                super::org_policy::ensure_personal_vaults_allowed(&mut tx, &session.account_id)
                    .await?;
            }
            let seq = db::next_seq(&mut tx).await?;
            sqlx::query(
                "INSERT INTO items (id, vault_id, encrypted_data, revision, deleted, seq, created_at, updated_at, \
                 key_epoch) VALUES ($1, $2, $3, 1, 0, $4, $5, $6, $7)",
            )
            .bind(&item_id)
            .bind(&req.vault_id)
            .bind(&req.encrypted_data)
            .bind(seq)
            .bind(now)
            .bind(now)
            .bind(req.key_epoch)
            .execute(&mut *tx)
            .await?;
            if let Some(org_id) = &audit_org {
                super::org_audit::record_in(
                    &mut tx,
                    org_id,
                    &actor,
                    "item_created",
                    super::org_audit::Target::item(&item_id),
                    json!({ "vaultId": req.vault_id }),
                )
                .await?;
            }
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
                "UPDATE items SET encrypted_data = $1, revision = $2, deleted = 0, seq = $3, updated_at = $4, \
                 key_epoch = $5 WHERE id = $6",
            )
            .bind(&req.encrypted_data)
            .bind(req.revision)
            .bind(seq)
            .bind(now)
            .bind(req.key_epoch)
            .bind(&item_id)
            .execute(&mut *tx)
            .await?;
            if let Some(org_id) = &audit_org {
                super::org_audit::record_in(
                    &mut tx,
                    org_id,
                    &actor,
                    "item_updated",
                    super::org_audit::Target::item(&item_id),
                    json!({ "vaultId": req.vault_id, "revision": req.revision }),
                )
                .await?;
            }
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
    ClientIp(ip): ClientIp,
    session: Session,
    Path(item_id): Path<String>,
    Query(query): Query<DeleteQuery>,
) -> ApiResult<Json<WriteResponse>> {
    validate::id("item id", &item_id)?;
    validate::revision(query.revision)?;

    let mut tx = crate::db::begin_write(&state.db).await?;
    let (vault_id, current) = current_item(&mut tx, &session.account_id, &item_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let vault_access = access::require_vault_write(&mut tx, &vault_id, &session.account_id).await?;
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
    if let Some(org_id) = shared_org(&vault_access) {
        super::org_audit::record_in(
            &mut tx,
            org_id,
            &super::org_audit::Actor::of(&session, &ip),
            "item_deleted",
            super::org_audit::Target::item(&item_id),
            json!({ "vaultId": vault_id }),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(Json(WriteResponse {
        revision: query.revision,
        seq,
    }))
}
