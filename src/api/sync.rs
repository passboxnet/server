//! Incremental sync. Clients send the cursor of their last sync and receive
//! every vault and item that changed since then, plus a new cursor.
//!
//! With `sharing=1` the response also covers shared vaults (their rows and
//! items) and a `sharing` object with organizations, rosters, groups, keys
//! sealed for the account and manifest chains (see
//! `passbox_core::sharing::data`). A vault the account gained access to
//! since the cursor is sent in full. Clients without `sharing=1` see their
//! personal vaults only, exactly as before.

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::{Query, State};
use passbox_core::sharing::data::{
    BundleRecord, GroupKeyRecord, ManifestRecord, OrgKeyRecord, SharingDelta, VaultAccessRecord,
    VaultKeyRecord,
};
use serde::{Deserialize, Serialize};
use sqlx::AnyConnection;

use super::auth::Session;
use crate::db;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct SyncQuery {
    /// Cursor from the previous sync; omit or pass 0 for a full sync.
    #[serde(default)]
    since: i64,
    /// `1` to include shared vaults and the sharing state.
    #[serde(default)]
    sharing: u8,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncVault {
    id: String,
    encrypted_key: String,
    encrypted_meta: String,
    revision: i64,
    updated_at: i64,
    /// Set for shared vaults.
    #[serde(skip_serializing_if = "Option::is_none")]
    org_id: Option<String>,
    /// The key epoch of `encrypted_meta` (0 for personal vaults).
    #[serde(skip_serializing_if = "is_zero")]
    key_epoch: i64,
}

fn is_zero(value: &i64) -> bool {
    *value == 0
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
    /// The vault key epoch the item is encrypted with.
    key_epoch: i64,
    /// When the item was created (Unix ms).
    created_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    cursor: i64,
    vaults: Vec<SyncVault>,
    items: Vec<SyncItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sharing: Option<SharingDelta>,
}

type ItemRow = (String, String, i64, Option<String>, i64, i64, i64, i64);

fn item(row: ItemRow) -> SyncItem {
    let (id, vault_id, revision, encrypted_data, deleted, updated_at, key_epoch, created_at) = row;
    SyncItem {
        id,
        vault_id,
        revision,
        encrypted_data,
        deleted: deleted != 0,
        updated_at,
        key_epoch,
        created_at,
    }
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
    let mut conn = state.db.acquire().await?;

    let vaults: Vec<(String, String, String, i64, i64)> = sqlx::query_as(
        "SELECT id, encrypted_key, encrypted_meta, revision, updated_at FROM vaults \
         WHERE account_id = $1 AND org_id IS NULL AND seq > $2 AND seq <= $3 ORDER BY seq",
    )
    .bind(&session.account_id)
    .bind(query.since)
    .bind(cursor)
    .fetch_all(&mut *conn)
    .await?;

    let items: Vec<ItemRow> = sqlx::query_as(
        "SELECT items.id, items.vault_id, items.revision, items.encrypted_data, items.deleted, items.updated_at, \
         items.key_epoch, items.created_at FROM items JOIN vaults ON vaults.id = items.vault_id \
         WHERE vaults.account_id = $1 AND vaults.org_id IS NULL AND items.seq > $2 AND items.seq <= $3 \
         ORDER BY items.seq",
    )
    .bind(&session.account_id)
    .bind(query.since)
    .bind(cursor)
    .fetch_all(&mut *conn)
    .await?;

    let mut response = SyncResponse {
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
                    org_id: None,
                    key_epoch: 0,
                },
            )
            .collect(),
        items: items.into_iter().map(item).collect(),
        sharing: None,
    };
    if query.sharing == 1 {
        let sharing = sync_sharing(
            &mut conn,
            &session.account_id,
            query.since,
            cursor,
            &mut response,
        )
        .await?;
        response.sharing = Some(sharing);
    }
    Ok(Json(response))
}

/// Adds shared vaults and items to `response` and returns the sharing delta.
#[allow(clippy::type_complexity)]
async fn sync_sharing(
    conn: &mut AnyConnection,
    me: &str,
    since: i64,
    cursor: i64,
    response: &mut SyncResponse,
) -> ApiResult<SharingDelta> {
    let mut delta = SharingDelta::default();
    let orgs = super::orgs::org_records(conn, me).await?;
    for (org, org_seq) in &orgs {
        let confirmed = org.status == "confirmed";
        let (roster, roster_seq) = super::orgs::roster(conn, &org.id).await?;
        if (*org_seq).max(roster_seq) > since {
            // Guests and unconfirmed members see themselves and the admins.
            let full = confirmed && org.role != "guest";
            let mut roster = roster;
            if !full {
                roster
                    .members
                    .retain(|m| m.account_id == me || m.role == "owner" || m.role == "admin");
            }
            delta.rosters.push(roster);
        }
        if !confirmed {
            continue;
        }
        let keys: Vec<(i64, String, String, String)> = sqlx::query_as(
            "SELECT epoch, sealed_key, grant_data, grant_signature FROM org_keys \
             WHERE org_id = $1 AND account_id = $2 AND seq > $3 AND seq <= $4",
        )
        .bind(&org.id)
        .bind(me)
        .bind(since)
        .bind(cursor)
        .fetch_all(&mut *conn)
        .await?;
        delta.org_keys.extend(keys.into_iter().map(
            |(epoch, sealed_key, grant, grant_signature)| OrgKeyRecord {
                org_id: org.id.clone(),
                epoch: u32::try_from(epoch).unwrap_or_default(),
                sealed_key,
                grant,
                grant_signature,
            },
        ));
        if org.role != "guest" {
            delta
                .groups
                .extend(super::groups::group_records(conn, &org.id, me).await?);
        }
    }

    // Group keys sealed for this account (all versions; old ones open vault
    // keys of older epochs).
    let group_keys: Vec<(String, i64, String, String, String, String, String, i64)> = sqlx::query_as(
        "SELECT group_members.group_id, group_members.key_version, group_versions.bundle, \
         group_versions.bundle_signature, group_members.sealed_key, group_members.grant_data, \
         group_members.grant_signature, group_members.seq FROM group_members \
         JOIN group_versions ON group_versions.group_id = group_members.group_id \
           AND group_versions.key_version = group_members.key_version \
         JOIN org_groups ON org_groups.id = group_members.group_id \
         JOIN org_members ON org_members.org_id = org_groups.org_id AND org_members.account_id = group_members.account_id \
         WHERE group_members.account_id = $1 AND org_members.status = 'confirmed'",
    )
    .bind(me)
    .fetch_all(&mut *conn)
    .await?;
    // Current group memberships, and when they began.
    let my_groups: BTreeMap<String, i64> = sqlx::query_as::<_, (String, i64)>(
        "SELECT group_members.group_id, group_members.seq FROM group_members \
         JOIN org_groups ON org_groups.id = group_members.group_id \
           AND org_groups.key_version = group_members.key_version \
         WHERE group_members.account_id = $1",
    )
    .bind(me)
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .collect();
    for (
        group_id,
        key_version,
        bundle,
        bundle_signature,
        sealed_key,
        grant,
        grant_signature,
        seq,
    ) in group_keys
    {
        if seq > since && seq <= cursor {
            delta.group_keys.push(GroupKeyRecord {
                group_id,
                key_version: u32::try_from(key_version).unwrap_or_default(),
                bundle,
                bundle_signature,
                sealed_key,
                grant,
                grant_signature,
            });
        }
    }

    // Shared vaults this account can open.
    let mut signer_ids: Vec<String> = Vec::new();
    for (org, org_seq) in orgs.iter().filter(|(o, _)| o.status == "confirmed") {
        let vaults: Vec<(String, String, i64, i64, i64, i64, i64)> = sqlx::query_as(
            "SELECT id, encrypted_meta, revision, updated_at, key_epoch, rotation_pending, seq FROM vaults \
             WHERE org_id = $1",
        )
        .bind(&org.id)
        .fetch_all(&mut *conn)
        .await?;
        for (
            vault_id,
            encrypted_meta,
            revision,
            updated_at,
            key_epoch,
            rotation_pending,
            vault_seq,
        ) in vaults
        {
            let Some(role) = super::access::shared_role(conn, &vault_id, &org.id, me).await? else {
                continue;
            };
            // When did access begin? A newer membership means a full send.
            let memberships: Vec<(String, String, i64)> = sqlx::query_as(
                "SELECT principal_type, principal_id, seq FROM vault_members WHERE vault_id = $1",
            )
            .bind(&vault_id)
            .fetch_all(&mut *conn)
            .await?;
            let mut access_seq = *org_seq;
            for (principal_type, principal_id, seq) in &memberships {
                if principal_type == "account" && principal_id == me {
                    access_seq = access_seq.max(*seq);
                } else if principal_type == "group"
                    && let Some(joined) = my_groups.get(principal_id)
                {
                    access_seq = access_seq.max(*seq).max(*joined);
                }
            }
            let vault_since = if access_seq > since { 0 } else { since };
            delta.vault_access.push(VaultAccessRecord {
                vault_id: vault_id.clone(),
                org_id: org.id.clone(),
                role: role.as_str().to_owned(),
                key_epoch: u32::try_from(key_epoch).unwrap_or_default(),
                rotation_pending: rotation_pending != 0,
            });
            if vault_seq > vault_since && vault_seq <= cursor {
                response.vaults.push(SyncVault {
                    id: vault_id.clone(),
                    encrypted_key: String::new(),
                    encrypted_meta,
                    revision,
                    updated_at,
                    org_id: Some(org.id.clone()),
                    key_epoch,
                });
            }
            let items: Vec<ItemRow> = sqlx::query_as(
                "SELECT id, vault_id, revision, encrypted_data, deleted, updated_at, key_epoch, created_at FROM items \
                 WHERE vault_id = $1 AND seq > $2 AND seq <= $3 ORDER BY seq",
            )
            .bind(&vault_id)
            .bind(vault_since)
            .bind(cursor)
            .fetch_all(&mut *conn)
            .await?;
            response.items.extend(items.into_iter().map(item));

            let keys: Vec<(i64, String, String, String, Option<String>, String, String, i64)> = sqlx::query_as(
                "SELECT key_epoch, principal_type, principal_id, sealed_key, wrapped_key, grant_data, \
                 grant_signature, seq FROM vault_keys WHERE vault_id = $1 AND seq > $2 AND seq <= $3",
            )
            .bind(&vault_id)
            .bind(vault_since)
            .bind(cursor)
            .fetch_all(&mut *conn)
            .await?;
            for (
                epoch,
                principal_type,
                principal_id,
                sealed_key,
                wrapped_key,
                grant,
                grant_signature,
                _,
            ) in keys
            {
                let mine = (principal_type == "account" && principal_id == me)
                    || (principal_type == "group" && my_groups.contains_key(&principal_id));
                if mine {
                    delta.vault_keys.push(VaultKeyRecord {
                        vault_id: vault_id.clone(),
                        key_epoch: u32::try_from(epoch).unwrap_or_default(),
                        principal_type,
                        principal_id,
                        sealed_key,
                        wrapped_key,
                        grant,
                        grant_signature,
                    });
                }
            }

            let newest_manifest: Option<i64> = sqlx::query_scalar(
                "SELECT MAX(seq) FROM vault_manifests WHERE vault_id = $1 AND seq <= $2",
            )
            .bind(&vault_id)
            .bind(cursor)
            .fetch_one(&mut *conn)
            .await?;
            if newest_manifest.is_some_and(|seq| seq > vault_since) {
                let chain: Vec<ManifestRecord> =
                    super::shared::manifest_chain(conn, &vault_id).await?;
                let signers: Vec<String> = sqlx::query_scalar(
                    "SELECT DISTINCT signer_id FROM vault_manifests WHERE vault_id = $1",
                )
                .bind(&vault_id)
                .fetch_all(&mut *conn)
                .await?;
                signer_ids.extend(signers);
                delta.manifests.extend(chain);
            }
        }
    }
    signer_ids.sort();
    signer_ids.dedup();
    for signer in signer_ids {
        let bundles: Vec<(String, String)> = sqlx::query_as(
            "SELECT bundle, bundle_signature FROM account_keys WHERE account_id = $1",
        )
        .bind(&signer)
        .fetch_all(&mut *conn)
        .await?;
        delta.signers.extend(
            bundles
                .into_iter()
                .map(|(bundle, bundle_signature)| BundleRecord {
                    bundle,
                    bundle_signature,
                }),
        );
    }
    delta.orgs = orgs.into_iter().map(|(o, _)| o).collect();
    Ok(delta)
}
