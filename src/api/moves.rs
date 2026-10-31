//! Moving items between vaults.
//!
//! The client re-encrypts each item (and the versions of its history it can
//! read) with the target vault's key, bound to the target vault, and sends
//! them here. The item keeps its ID, its creation date and its attachments;
//! the history is replaced by the re-encrypted versions. A row in
//! `item_moves` tells devices that can only see the old vault that the
//! item left (sync sends them a tombstone).

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgConnection;

use super::access::{self, VaultAccess};
use super::auth::Session;
use super::org_audit::{self, Actor, Target};
use super::validate;
use crate::db::{self, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::security::ClientIp;
use crate::state::AppState;

/// Items per request; clients send larger moves in batches.
pub const MAX_ITEMS_PER_MOVE: usize = 100;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MoveRequest {
    target_vault_id: String,
    /// The target vault's current key epoch (0 for personal vaults).
    #[serde(default)]
    key_epoch: i64,
    items: Vec<MoveItem>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MoveItem {
    id: String,
    /// The new revision: one higher than the stored one.
    revision: i64,
    encrypted_data: String,
    /// Earlier versions, re-encrypted for the target vault. Versions not
    /// sent here are dropped (for example ones this device cannot read).
    #[serde(default)]
    versions: Vec<MoveVersion>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MoveVersion {
    revision: i64,
    encrypted_data: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MovedItem {
    id: String,
    revision: i64,
    seq: i64,
}

#[derive(Serialize)]
pub struct MoveResponse {
    moved: Vec<MovedItem>,
}

fn org_of(access: &VaultAccess) -> Option<&str> {
    match access {
        VaultAccess::Shared { org_id, .. } => Some(org_id),
        VaultAccess::Personal => None,
    }
}

/// 403 `policy_violation` if the source organization keeps its items inside.
async fn check_policy(
    conn: &mut PgConnection,
    account_id: &str,
    source: &VaultAccess,
    target: &VaultAccess,
) -> ApiResult<()> {
    if let Some(source_org) = org_of(source)
        && org_of(target) != Some(source_org)
        && super::org_policy::current_rules(conn, source_org)
            .await?
            .is_some_and(|rules| rules.forbid_external_sharing)
    {
        return Err(ApiError::forbidden(
            "policy_violation",
            "your organization does not allow moving its items out of its vaults",
        ));
    }
    if matches!(target, VaultAccess::Personal) && !matches!(source, VaultAccess::Personal) {
        super::org_policy::ensure_personal_vaults_allowed(conn, account_id).await?;
    }
    Ok(())
}

/// `POST /api/v1/items/move`: moves items into another vault, all or none.
pub async fn move_items(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Json(req): Json<MoveRequest>,
) -> ApiResult<Json<MoveResponse>> {
    validate::id("targetVaultId", &req.target_vault_id)?;
    if req.items.is_empty() || req.items.len() > MAX_ITEMS_PER_MOVE {
        return Err(ApiError::bad_request(format!(
            "send between 1 and {MAX_ITEMS_PER_MOVE} items"
        )));
    }
    for item in &req.items {
        validate::id("item id", &item.id)?;
        validate::revision(item.revision)?;
        validate::base64(
            "encryptedData",
            &item.encrypted_data,
            validate::MAX_ITEM_LEN,
        )?;
        if item.versions.len() > super::items::MAX_ITEM_VERSIONS as usize {
            return Err(ApiError::bad_request("too many versions"));
        }
        let mut seen = std::collections::BTreeSet::new();
        for version in &item.versions {
            validate::base64(
                "encryptedData",
                &version.encrypted_data,
                validate::MAX_ITEM_LEN,
            )?;
            if version.revision < 1 || version.revision >= item.revision {
                return Err(ApiError::bad_request(
                    "versions must be older than the new revision",
                ));
            }
            if !seen.insert(version.revision) {
                return Err(ApiError::bad_request("duplicate version"));
            }
        }
    }

    let mut tx = state.db.as_account(&session.account_id).await?;
    let target = super::items::require_write(
        &mut tx,
        &session.account_id,
        &req.target_vault_id,
        req.key_epoch,
    )
    .await?;
    let target_owner = super::attachments::owner_of(&mut tx, &req.target_vault_id).await?;
    let actor = Actor::of(&session, &ip);
    let now = now_ms();
    let mut moved = Vec::with_capacity(req.items.len());
    for item in &req.items {
        let row: Option<(String, i64, bool)> = sqlx::query!(
            "SELECT vault_id, revision, deleted FROM items WHERE id = $1",
            &item.id,
        )
        .map(|row| (row.vault_id, row.revision, row.deleted))
        .fetch_optional(&mut *tx)
        .await?;
        let Some((source_vault, current, deleted)) = row else {
            return Err(ApiError::NotFound);
        };
        if deleted {
            return Err(ApiError::NotFound);
        }
        if access::vault_access(&mut tx, &source_vault, &session.account_id)
            .await?
            .is_none()
        {
            return Err(ApiError::NotFound);
        }
        let source =
            access::require_vault_write(&mut tx, &source_vault, &session.account_id).await?;
        if source_vault == req.target_vault_id {
            return Err(ApiError::bad_request("the item is already in this vault"));
        }
        if item.revision != current + 1 {
            return Err(ApiError::conflict(
                "item was changed by another device",
                json!({ "itemId": item.id, "currentRevision": current }),
            ));
        }
        check_policy(&mut tx, &session.account_id, &source, &target).await?;

        // Attachments move with the item; the target pays for their storage.
        let attachment_bytes: i64 = sqlx::query_scalar!(
            r#"SELECT CAST(COALESCE(SUM(size), 0) AS BIGINT) AS "total!" FROM attachments WHERE item_id = $1"#,
            &item.id,
        )
        .fetch_one(&mut *tx)
        .await?;
        let source_owner = super::attachments::owner_of(&mut tx, &source_vault).await?;
        if attachment_bytes > 0 && source_owner != target_owner {
            super::attachments::ensure_quota(&state, &mut tx, &target_owner, attachment_bytes)
                .await?;
        }
        sqlx::query!(
            "UPDATE attachments SET vault_id = $1, owner_type = $2, owner_id = $3 WHERE item_id = $4",
            &req.target_vault_id,
            &target_owner.0,
            &target_owner.1,
            &item.id,
        )
        .execute(&mut *tx)
        .await?;

        // The history, re-encrypted for the target (times and devices kept).
        let old: Vec<(i64, i64, Option<String>)> = sqlx::query!(
            "SELECT revision, updated_at, updated_by FROM item_versions WHERE item_id = $1",
            &item.id,
        )
        .map(|row| (row.revision, row.updated_at, row.updated_by))
        .fetch_all(&mut *tx)
        .await?;
        let current_row: (i64, Option<String>) = sqlx::query!(
            "SELECT updated_at, updated_by FROM items WHERE id = $1",
            &item.id,
        )
        .map(|row| (row.updated_at, row.updated_by))
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query!("DELETE FROM item_versions WHERE item_id = $1", &item.id,)
            .execute(&mut *tx)
            .await?;
        for version in &item.versions {
            let (updated_at, updated_by) = if version.revision == current {
                current_row.clone()
            } else {
                old.iter()
                    .find(|(r, _, _)| *r == version.revision)
                    .map_or((now, None), |(_, at, by)| (*at, by.clone()))
            };
            sqlx::query!(
                "INSERT INTO item_versions (item_id, revision, key_epoch, encrypted_data, updated_at, updated_by) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
                &item.id,
                version.revision,
                req.key_epoch,
                super::vaults::decode(&version.encrypted_data)?,
                updated_at,
                updated_by,
            )
            .execute(&mut *tx)
            .await?;
        }

        let seq = db::next_seq(&mut tx).await?;
        sqlx::query!(
            "UPDATE items SET vault_id = $1, encrypted_data = $2, revision = $3, seq = $4, updated_at = $5, \
             key_epoch = $6, updated_by = $7 WHERE id = $8",
            &req.target_vault_id,
            super::vaults::decode(&item.encrypted_data)?,
            item.revision,
            seq,
            now,
            req.key_epoch,
            &session.id,
            &item.id,
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!(
            "INSERT INTO item_moves (item_id, from_vault_id, to_vault_id, revision, seq, moved_at) \
             VALUES ($1, $2, $3, $4, $5, $6)",
            &item.id,
            &source_vault,
            &req.target_vault_id,
            item.revision,
            seq,
            now,
        )
        .execute(&mut *tx)
        .await?;

        let details = json!({ "fromVaultId": source_vault, "toVaultId": req.target_vault_id });
        let source_org = org_of(&source).map(str::to_owned);
        let target_org = org_of(&target).map(str::to_owned);
        if let Some(org) = &source_org {
            org_audit::record_in(
                &mut tx,
                org,
                &actor,
                "item_moved",
                Target::item(&item.id),
                details.clone(),
            )
            .await?;
        }
        if let Some(org) = target_org.filter(|t| source_org.as_ref() != Some(t)) {
            org_audit::record_in(
                &mut tx,
                &org,
                &actor,
                "item_moved",
                Target::item(&item.id),
                details,
            )
            .await?;
        }
        moved.push(MovedItem {
            id: item.id.clone(),
            revision: item.revision,
            seq,
        });
    }
    tx.commit().await?;
    Ok(Json(MoveResponse { moved }))
}

/// Tombstones for items that left `vault_id` (or the account's personal
/// vaults) after `since`, for sync. They come first in the item list, so a
/// device that sees both vaults removes the old copy before adding the new.
pub async fn tombstones(
    conn: &mut PgConnection,
    vault_ids: &[String],
    since: i64,
    cursor: i64,
) -> ApiResult<Vec<(String, String, i64, i64)>> {
    let mut out = Vec::new();
    for vault_id in vault_ids {
        let rows: Vec<(String, String, i64, i64)> = sqlx::query!(
            "SELECT item_id, from_vault_id, revision, moved_at FROM item_moves \
             WHERE from_vault_id = $1 AND seq > $2 AND seq <= $3 ORDER BY seq",
            vault_id,
            since,
            cursor,
        )
        .map(|row| (row.item_id, row.from_vault_id, row.revision, row.moved_at))
        .fetch_all(&mut *conn)
        .await?;
        out.extend(rows);
    }
    Ok(out)
}
