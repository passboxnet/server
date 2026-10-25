//! Groups: principals with their own encryption key pair. The group's
//! private key is sealed for each member, so adding a member is a single
//! sealing no matter how many vaults are shared with the group.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use passbox_core::identity::{SignedBundle, sealed_hash};
use passbox_core::sharing::build::{GroupKeyUpload, NewGroup, RotateGroup};
use passbox_core::sharing::data::{GrantRecord, GroupRecord};
use passbox_core::sharing::objects::{GroupBundle, GroupKeyGrant, Signed};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgConnection;

use super::access;
use super::auth::{Session, record_event};
use super::signed::{self, bad};
use super::validate;
use super::vaults::decode;
use crate::db::{self, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::security::ClientIp;
use crate::state::AppState;

const MAX_GROUP_MEMBERS: usize = 5000;

fn check_bundle(
    req_bundle: &str,
    req_signature: &str,
    me: &SignedBundle,
    org_id: &str,
    group_id: &str,
    key_version: u32,
) -> ApiResult<Signed<GroupBundle>> {
    let bundle = signed::parse::<GroupBundle>("bundle", req_bundle, req_signature, me)?;
    let b = &bundle.value;
    if b.group_id != group_id
        || b.org_id != org_id
        || b.key_version != key_version
        || b.creator_id != me.bundle.account_id
    {
        return Err(bad("the group bundle does not match"));
    }
    Ok(bundle)
}

async fn check_member_key(
    conn: &mut PgConnection,
    upload: &GroupKeyUpload,
    bundle: &GroupBundle,
    me: &SignedBundle,
) -> ApiResult<()> {
    match access::membership(conn, &bundle.org_id, &upload.account_id).await? {
        Some(m) if m.is_confirmed() => {}
        _ => {
            return Err(bad(
                "group members must be confirmed members of the organization",
            ));
        }
    }
    let member = signed::own_bundle(conn, &upload.account_id).await?;
    let grant =
        signed::parse::<GroupKeyGrant>("grant", &upload.grant, &upload.grant_signature, me)?;
    let sealed = signed::sealed("sealedKey", &upload.sealed_key)?;
    let g = &grant.value;
    if g.group_id != bundle.group_id
        || g.org_id != bundle.org_id
        || g.key_version != bundle.key_version
        || upload.key_version != bundle.key_version
        || g.account_id != upload.account_id
        || g.account_bundle_hash != member.hash()
        || g.sealed_hash != sealed_hash(&sealed)
        || g.granter_id != me.bundle.account_id
    {
        return Err(bad("the group key grant does not match"));
    }
    Ok(())
}

async fn insert_member_key(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    group_id: &str,
    upload: &GroupKeyUpload,
    seq: i64,
    now: i64,
) -> ApiResult<()> {
    let inserted = sqlx::query!(
        "INSERT INTO group_members (group_id, key_version, account_id, sealed_key, grant_data, grant_signature, \
         seq, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING",
        group_id,
        i64::from(upload.key_version),
        &upload.account_id,
        decode(&upload.sealed_key)?,
        &upload.grant,
        &upload.grant_signature,
        seq,
        now,
    )
    .execute(&mut **tx)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::conflict(
            "already a member of the group",
            serde_json::Value::Null,
        ));
    }
    Ok(())
}

async fn org_epoch(conn: &mut PgConnection, org_id: &str) -> ApiResult<i64> {
    Ok(
        sqlx::query_scalar!("SELECT meta_epoch FROM organizations WHERE id = $1", org_id,)
            .fetch_one(&mut *conn)
            .await?,
    )
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupWrite {
    id: String,
    key_version: u32,
    seq: i64,
    /// Vaults shared with the group whose keys must now be rotated.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    vaults: Vec<String>,
}

/// Creates a group (admins). The creator is always a member.
pub async fn create(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(org_id): Path<String>,
    Json(req): Json<NewGroup>,
) -> ApiResult<(StatusCode, Json<GroupWrite>)> {
    validate::id("organization id", &org_id)?;
    validate::id("group id", &req.id)?;
    validate::base64(
        "encryptedMeta",
        &req.encrypted_meta,
        validate::MAX_SMALL_LEN,
    )?;
    if req.key_version != 1 || req.members.is_empty() || req.members.len() > MAX_GROUP_MEMBERS {
        return Err(bad(
            "a new group starts at key version 1 with at least its creator",
        ));
    }
    let mut tx = state.db.as_account(&session.account_id).await?;
    access::require_admin(&mut tx, &org_id, &session.account_id).await?;
    if i64::from(req.meta_epoch) != org_epoch(&mut tx, &org_id).await? {
        return Err(ApiError::conflict(
            "the organization key changed meanwhile",
            serde_json::Value::Null,
        ));
    }
    let me = signed::own_bundle(&mut tx, &session.account_id).await?;
    let bundle = check_bundle(&req.bundle, &req.bundle_signature, &me, &org_id, &req.id, 1)?;
    if !req
        .members
        .iter()
        .any(|m| m.account_id == session.account_id)
    {
        return Err(bad("the creator must be a member of the group"));
    }
    for member in &req.members {
        check_member_key(&mut tx, member, &bundle.value, &me).await?;
    }
    let now = now_ms();
    let seq = db::next_seq(&mut tx).await?;
    let inserted = sqlx::query!(
        "INSERT INTO org_groups (id, org_id, key_version, bundle, bundle_signature, encrypted_meta, meta_epoch, \
         seq, created_at, updated_at) VALUES ($1, $2, 1, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT DO NOTHING",
        &req.id,
        &org_id,
        &req.bundle,
        &req.bundle_signature,
        decode(&req.encrypted_meta)?,
        i64::from(req.meta_epoch),
        seq,
        now,
        now,
    )
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::conflict(
            "group already exists",
            serde_json::Value::Null,
        ));
    }
    sqlx::query!(
        "INSERT INTO group_versions (group_id, key_version, bundle, bundle_signature, created_at) \
         VALUES ($1, 1, $2, $3, $4)",
        &req.id,
        &req.bundle,
        &req.bundle_signature,
        now,
    )
    .execute(&mut *tx)
    .await?;
    for member in &req.members {
        insert_member_key(&mut tx, &req.id, member, seq, now).await?;
    }
    super::org_audit::record_in(
        &mut tx,
        &org_id,
        &super::org_audit::Actor::of(&session, &ip),
        "group_created",
        super::org_audit::Target::group(&req.id),
        serde_json::json!({ "members": req.members.iter().map(|m| m.account_id.clone()).collect::<Vec<_>>() }),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(GroupWrite {
            id: req.id,
            key_version: 1,
            seq,
            vaults: Vec::new(),
        }),
    ))
}

/// The groups of an organization, as delivered by sync. Member grants are
/// included for groups the account belongs to.
pub async fn group_records(
    conn: &mut PgConnection,
    org_id: &str,
    account_id: &str,
) -> ApiResult<Vec<GroupRecord>> {
    let groups: Vec<(String, i64, String, String, Vec<u8>, i64)> = sqlx::query!(
        "SELECT id, key_version, bundle, bundle_signature, encrypted_meta, meta_epoch FROM org_groups \
         WHERE org_id = $1 ORDER BY created_at",
        org_id,
    ).map(|row| (row.id, row.key_version, row.bundle, row.bundle_signature, row.encrypted_meta, row.meta_epoch))
    .fetch_all(&mut *conn)
    .await?;
    let mut records = Vec::with_capacity(groups.len());
    for (id, key_version, bundle, bundle_signature, encrypted_meta, meta_epoch) in groups {
        let rows: Vec<(String, String, String)> = sqlx::query!(
            "SELECT account_id, grant_data, grant_signature FROM group_members \
             WHERE group_id = $1 AND key_version = $2 ORDER BY account_id",
            id.as_str(),
            key_version,
        )
        .map(|row| (row.account_id, row.grant_data, row.grant_signature))
        .fetch_all(&mut *conn)
        .await?;
        let is_member = rows.iter().any(|(a, _, _)| a == account_id);
        records.push(GroupRecord {
            id,
            org_id: org_id.to_owned(),
            key_version: u32::try_from(key_version).unwrap_or_default(),
            bundle,
            bundle_signature,
            encrypted_meta: passbox_core::encoding::encode(&encrypted_meta),
            meta_epoch: u32::try_from(meta_epoch).unwrap_or_default(),
            members: rows.iter().map(|(a, _, _)| a.clone()).collect(),
            member_grants: if is_member {
                rows.into_iter()
                    .map(|(_, grant, grant_signature)| GrantRecord {
                        grant,
                        grant_signature,
                    })
                    .collect()
            } else {
                Vec::new()
            },
        });
    }
    Ok(records)
}

/// Groups of an organization (confirmed members).
pub async fn list(
    State(state): State<AppState>,
    session: Session,
    Path(org_id): Path<String>,
) -> ApiResult<Json<Vec<GroupRecord>>> {
    validate::id("organization id", &org_id)?;
    let mut conn = state.db.as_account(&session.account_id).await?;
    access::require_confirmed(&mut conn, &org_id, &session.account_id).await?;
    Ok(Json(
        group_records(&mut conn, &org_id, &session.account_id).await?,
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateGroupRequest {
    meta_epoch: u32,
    encrypted_meta: String,
}

async fn require_group(conn: &mut PgConnection, org_id: &str, group_id: &str) -> ApiResult<i64> {
    sqlx::query_scalar!(
        "SELECT key_version FROM org_groups WHERE id = $1 AND org_id = $2",
        group_id,
        org_id,
    )
    .fetch_optional(&mut *conn)
    .await?
    .ok_or(ApiError::NotFound)
}

/// Renames a group (admins).
pub async fn update(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path((org_id, group_id)): Path<(String, String)>,
    Json(req): Json<UpdateGroupRequest>,
) -> ApiResult<StatusCode> {
    validate::id("organization id", &org_id)?;
    validate::id("group id", &group_id)?;
    validate::base64(
        "encryptedMeta",
        &req.encrypted_meta,
        validate::MAX_SMALL_LEN,
    )?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    access::require_admin(&mut tx, &org_id, &session.account_id).await?;
    require_group(&mut tx, &org_id, &group_id).await?;
    if i64::from(req.meta_epoch) != org_epoch(&mut tx, &org_id).await? {
        return Err(ApiError::conflict(
            "the organization key changed meanwhile",
            serde_json::Value::Null,
        ));
    }
    let seq = db::next_seq(&mut tx).await?;
    sqlx::query!(
        "UPDATE org_groups SET encrypted_meta = $1, meta_epoch = $2, seq = $3, updated_at = $4 WHERE id = $5",
        decode(&req.encrypted_meta)?,
        i64::from(req.meta_epoch),
        seq,
        now_ms(),
        &group_id,
    )
        .execute(&mut *tx)
        .await?;
    super::org_audit::record_in(
        &mut tx,
        &org_id,
        &super::org_audit::Actor::of(&session, &ip),
        "group_renamed",
        super::org_audit::Target::group(&group_id),
        serde_json::json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Deletes a group (admins). Vaults must be unshared from it first.
pub async fn delete(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path((org_id, group_id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    validate::id("organization id", &org_id)?;
    validate::id("group id", &group_id)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    access::require_admin(&mut tx, &org_id, &session.account_id).await?;
    require_group(&mut tx, &org_id, &group_id).await?;
    let shared: Option<i64> = sqlx::query_scalar!(
        "SELECT 1::BIGINT AS \"one!\" FROM vault_members WHERE principal_type = 'group' AND principal_id = $1 LIMIT 1",
        &group_id,
    )
    .fetch_optional(&mut *tx)
    .await?;
    if shared.is_some() {
        return Err(ApiError::conflict(
            "unshare the group's vaults first",
            serde_json::Value::Null,
        ));
    }
    sqlx::query!("DELETE FROM org_groups WHERE id = $1", &group_id,)
        .execute(&mut *tx)
        .await?;
    db::next_seq(&mut tx).await?;
    super::org_audit::record_in(
        &mut tx,
        &org_id,
        &super::org_audit::Actor::of(&session, &ip),
        "group_deleted",
        super::org_audit::Target::group(&group_id),
        serde_json::json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Adds a member to a group (admins who are members of the group, since
/// adding means sealing the group key).
pub async fn add_member(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path((org_id, group_id)): Path<(String, String)>,
    Json(req): Json<GroupKeyUpload>,
) -> ApiResult<Json<GroupWrite>> {
    validate::id("organization id", &org_id)?;
    validate::id("group id", &group_id)?;
    validate::id("accountId", &req.account_id)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    access::require_admin(&mut tx, &org_id, &session.account_id).await?;
    let key_version = require_group(&mut tx, &org_id, &group_id).await?;
    let me = signed::own_bundle(&mut tx, &session.account_id).await?;
    let (bundle, bundle_signature): (String, String) = sqlx::query!(
        "SELECT bundle, bundle_signature FROM org_groups WHERE id = $1",
        &group_id,
    )
    .map(|row| (row.bundle, row.bundle_signature))
    .fetch_one(&mut *tx)
    .await?;
    let bundle = Signed::<GroupBundle>::parse(&bundle, &bundle_signature)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("{e}")))?;
    if i64::from(req.key_version) != key_version {
        return Err(ApiError::conflict(
            "the group key was rotated meanwhile",
            json!({ "currentKeyVersion": key_version }),
        ));
    }
    check_member_key(&mut tx, &req, &bundle.value, &me).await?;
    let now = now_ms();
    let seq = db::next_seq(&mut tx).await?;
    insert_member_key(&mut tx, &group_id, &req, seq, now).await?;
    sqlx::query!(
        "UPDATE org_groups SET seq = $1 WHERE id = $2",
        seq,
        &group_id,
    )
    .execute(&mut *tx)
    .await?;
    super::org_audit::record_in(
        &mut tx,
        &org_id,
        &super::org_audit::Actor::of(&session, &ip),
        "group_member_added",
        super::org_audit::Target::group(&group_id),
        serde_json::json!({ "accountId": req.account_id }),
    )
    .await?;
    tx.commit().await?;
    record_event(
        &state,
        &req.account_id,
        "group_joined",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    Ok(Json(GroupWrite {
        id: group_id,
        key_version: req.key_version,
        seq,
        vaults: Vec::new(),
    }))
}

/// Rotates a group's key, removing members (admins). The vaults shared with
/// the group are marked for rotation and returned.
pub async fn rotate(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path((org_id, group_id)): Path<(String, String)>,
    Json(req): Json<RotateGroup>,
) -> ApiResult<Json<GroupWrite>> {
    validate::id("organization id", &org_id)?;
    validate::id("group id", &group_id)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    access::require_admin(&mut tx, &org_id, &session.account_id).await?;
    let key_version = require_group(&mut tx, &org_id, &group_id).await?;
    if i64::from(req.key_version) != key_version + 1 {
        return Err(ApiError::conflict(
            "the group key was rotated meanwhile",
            json!({ "currentKeyVersion": key_version }),
        ));
    }
    let me = signed::own_bundle(&mut tx, &session.account_id).await?;
    let bundle = check_bundle(
        &req.bundle,
        &req.bundle_signature,
        &me,
        &org_id,
        &group_id,
        req.key_version,
    )?;
    let current: Vec<String> = sqlx::query_scalar!(
        "SELECT account_id FROM group_members WHERE group_id = $1 AND key_version = $2 ORDER BY account_id",
        &group_id,
        key_version,
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut expected: Vec<String> = current
        .into_iter()
        .filter(|a| !req.removed.contains(a))
        .collect();
    let mut uploaded: Vec<String> = req.members.iter().map(|m| m.account_id.clone()).collect();
    uploaded.sort();
    // Members that left the organization meanwhile are dropped by clients.
    let mut remaining = Vec::new();
    for account in expected.drain(..) {
        if access::membership(&mut tx, &org_id, &account)
            .await?
            .is_some_and(|m| m.is_confirmed())
        {
            remaining.push(account);
        }
    }
    if uploaded != remaining || !uploaded.contains(&session.account_id) {
        return Err(bad(
            "the new group key must be sealed for exactly the remaining members",
        ));
    }
    for member in &req.members {
        check_member_key(&mut tx, member, &bundle.value, &me).await?;
    }
    let now = now_ms();
    let seq = db::next_seq(&mut tx).await?;
    sqlx::query!(
        "UPDATE org_groups SET key_version = $1, bundle = $2, bundle_signature = $3, seq = $4, updated_at = $5 \
         WHERE id = $6",
        i64::from(req.key_version),
        &req.bundle,
        &req.bundle_signature,
        seq,
        now,
        &group_id,
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!(
        "INSERT INTO group_versions (group_id, key_version, bundle, bundle_signature, created_at) \
         VALUES ($1, $2, $3, $4, $5)",
        &group_id,
        i64::from(req.key_version),
        &req.bundle,
        &req.bundle_signature,
        now,
    )
    .execute(&mut *tx)
    .await?;
    for account in &req.removed {
        sqlx::query!(
            "DELETE FROM group_members WHERE group_id = $1 AND account_id = $2",
            &group_id,
            account,
        )
        .execute(&mut *tx)
        .await?;
    }
    for member in &req.members {
        insert_member_key(&mut tx, &group_id, member, seq, now).await?;
    }
    let vaults: Vec<String> = sqlx::query_scalar!(
        "SELECT vault_id FROM vault_members WHERE principal_type = 'group' AND principal_id = $1",
        &group_id,
    )
    .fetch_all(&mut *tx)
    .await?;
    for vault in &vaults {
        sqlx::query!(
            "UPDATE vaults SET rotation_pending = true, seq = $1 WHERE id = $2",
            seq,
            vault,
        )
        .execute(&mut *tx)
        .await?;
    }
    super::org_audit::record_in(
        &mut tx,
        &org_id,
        &super::org_audit::Actor::of(&session, &ip),
        if req.removed.is_empty() {
            "group_key_rotated"
        } else {
            "group_member_removed"
        },
        super::org_audit::Target::group(&group_id),
        serde_json::json!({ "removed": req.removed, "keyVersion": req.key_version }),
    )
    .await?;
    tx.commit().await?;
    for account in &req.removed {
        record_event(
            &state,
            account,
            "group_left",
            &session.device_name,
            &session.client_kind,
            &ip,
        )
        .await?;
    }
    Ok(Json(GroupWrite {
        id: group_id,
        key_version: req.key_version,
        seq,
        vaults,
    }))
}
