//! Shared vaults: creation in an organization, members, key rotation, own
//! key copies and batched re-encryption of items.

use std::collections::BTreeSet;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use passbox_core::identity::{SignedBundle, sealed_hash};
use passbox_core::sharing::build::{
    NewSharedVault, RotateVault, VaultKeyUpload, VaultMemberChange,
};
use passbox_core::sharing::objects::{
    GroupBundle, PrincipalType, Signed, VaultGrant, VaultManifest, VaultRole,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::AnyConnection;

use super::access::{self, require_vault_manager};
use super::auth::{Session, record_event};
use super::signed::{self, bad};
use super::validate;
use crate::db::{self, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::security::ClientIp;
use crate::state::AppState;

/// Most members per vault and items per re-encryption batch.
const MAX_VAULT_MEMBERS: usize = 1000;
const MAX_BATCH_ITEMS: usize = 100;

/// The key hash a principal currently has: its account bundle hash or its
/// group's current bundle hash, if it belongs to `org_id` (and, for
/// accounts, is a confirmed member).
pub async fn principal_key_hash(
    conn: &mut AnyConnection,
    org_id: &str,
    principal_type: PrincipalType,
    principal_id: &str,
) -> ApiResult<Option<[u8; 32]>> {
    match principal_type {
        PrincipalType::Account => {
            match access::membership(conn, org_id, principal_id).await? {
                Some(m) if m.is_confirmed() => {}
                _ => return Ok(None),
            }
            Ok(signed::bundle(conn, principal_id).await?.map(|b| b.hash()))
        }
        PrincipalType::Group => {
            let row: Option<(String, String)> = sqlx::query_as(
                "SELECT bundle, bundle_signature FROM org_groups WHERE id = $1 AND org_id = $2",
            )
            .bind(principal_id)
            .bind(org_id)
            .fetch_optional(&mut *conn)
            .await?;
            Ok(row
                .and_then(|(b, s)| Signed::<GroupBundle>::parse(&b, &s).ok())
                .map(|b| b.hash()))
        }
    }
}

/// Checks an uploaded vault key: the grant matches the manifest version,
/// the principal and the sealed bytes, and is signed by the uploader.
fn check_key(
    key: &VaultKeyUpload,
    manifest: &VaultManifest,
    me: &SignedBundle,
) -> ApiResult<(PrincipalType, VaultRole)> {
    let grant = signed::parse::<VaultGrant>("grant", &key.grant, &key.grant_signature, me)?;
    let sealed = signed::sealed("sealedKey", &key.sealed_key)?;
    let g = &grant.value;
    let principal_type =
        PrincipalType::parse(&key.principal_type).map_err(|_| bad("invalid principalType"))?;
    let entry = manifest
        .entry(principal_type, &key.principal_id)
        .ok_or_else(|| bad("the key's principal is not in the manifest"))?;
    if g.vault_id != manifest.vault_id
        || g.org_id != manifest.org_id
        || g.key_epoch != manifest.key_epoch
        || key.key_epoch != manifest.key_epoch
        || g.manifest_version != manifest.version
        || g.principal_type != principal_type
        || g.principal_id != key.principal_id
        || g.principal_key_hash != entry.key_hash
        || g.role != entry.role
        || g.sealed_hash != sealed_hash(&sealed)
        || g.granter_id != me.bundle.account_id
    {
        return Err(bad("the grant does not match the key and the manifest"));
    }
    if let Some(wrapped) = &key.wrapped_key {
        if principal_type != PrincipalType::Account || key.principal_id != me.bundle.account_id {
            return Err(bad("only your own key can carry a wrapped copy"));
        }
        validate::base64("wrappedKey", wrapped, validate::MAX_SMALL_LEN)?;
    }
    Ok((principal_type, entry.role))
}

#[allow(clippy::too_many_arguments)]
fn check_manifest(
    req_manifest: &str,
    req_signature: &str,
    me: &SignedBundle,
    vault_id: &str,
    org_id: &str,
    version: u64,
    key_epoch: u32,
    prev_hash: [u8; 32],
) -> ApiResult<Signed<VaultManifest>> {
    let manifest = signed::parse::<VaultManifest>("manifest", req_manifest, req_signature, me)?;
    let m = &manifest.value;
    if m.vault_id != vault_id
        || m.org_id != org_id
        || m.version != version
        || m.key_epoch != key_epoch
        || m.prev_hash != prev_hash
        || m.signer_id != me.bundle.account_id
    {
        return Err(bad("the manifest does not match the vault"));
    }
    if m.members.len() > MAX_VAULT_MEMBERS {
        return Err(bad("too many members"));
    }
    if !m
        .members
        .iter()
        .any(|e| e.principal_type == PrincipalType::Account && e.role == VaultRole::Manage)
    {
        return Err(bad("a vault needs at least one manager"));
    }
    Ok(manifest)
}

/// Checks that every manifest entry names a current principal of the
/// organization with its current key.
async fn check_entries(
    conn: &mut AnyConnection,
    org_id: &str,
    manifest: &VaultManifest,
) -> ApiResult<()> {
    for entry in &manifest.members {
        let hash = principal_key_hash(conn, org_id, entry.principal_type, &entry.principal_id)
            .await?
            .ok_or_else(|| {
                bad("a manifest member is not a confirmed member or group of the organization")
            })?;
        if hash != entry.key_hash {
            return Err(bad("a manifest member's key is not their current key"));
        }
    }
    Ok(())
}

async fn insert_manifest(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    vault_id: &str,
    manifest: &Signed<VaultManifest>,
    seq: i64,
    now: i64,
) -> ApiResult<()> {
    let inserted = sqlx::query(
        "INSERT INTO vault_manifests (vault_id, version, manifest, signature, signer_id, seq, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
    )
    .bind(vault_id)
    .bind(i64::try_from(manifest.value.version).map_err(|_| bad("invalid version"))?)
    .bind(manifest.encoded())
    .bind(manifest.encoded_signature())
    .bind(&manifest.value.signer_id)
    .bind(seq)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::conflict(
            "the vault's members were changed meanwhile; sync and try again",
            serde_json::Value::Null,
        ));
    }
    Ok(())
}

async fn upsert_key(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    vault_id: &str,
    key: &VaultKeyUpload,
    seq: i64,
    now: i64,
) -> ApiResult<()> {
    sqlx::query(
        "DELETE FROM vault_keys WHERE vault_id = $1 AND key_epoch = $2 AND principal_type = $3 \
         AND principal_id = $4",
    )
    .bind(vault_id)
    .bind(i64::from(key.key_epoch))
    .bind(&key.principal_type)
    .bind(&key.principal_id)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO vault_keys (vault_id, key_epoch, principal_type, principal_id, sealed_key, \
         wrapped_key, grant_data, grant_signature, seq, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(vault_id)
    .bind(i64::from(key.key_epoch))
    .bind(&key.principal_type)
    .bind(&key.principal_id)
    .bind(&key.sealed_key)
    .bind(key.wrapped_key.as_deref())
    .bind(&key.grant)
    .bind(&key.grant_signature)
    .bind(seq)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn upsert_member(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    vault_id: &str,
    principal_type: &str,
    principal_id: &str,
    role: VaultRole,
    seq: i64,
    now: i64,
) -> ApiResult<()> {
    let updated = sqlx::query(
        "UPDATE vault_members SET role = $1, seq = $2, updated_at = $3 \
         WHERE vault_id = $4 AND principal_type = $5 AND principal_id = $6",
    )
    .bind(role.as_str())
    .bind(seq)
    .bind(now)
    .bind(vault_id)
    .bind(principal_type)
    .bind(principal_id)
    .execute(&mut **tx)
    .await?;
    if updated.rows_affected() == 0 {
        sqlx::query(
            "INSERT INTO vault_members (vault_id, principal_type, principal_id, role, seq, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(vault_id)
        .bind(principal_type)
        .bind(principal_id)
        .bind(role.as_str())
        .bind(seq)
        .bind(now)
        .bind(now)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// Validates and inserts a new shared vault (inside the caller's
/// transaction, which has checked that the uploader may create it).
pub async fn insert_shared_vault(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: &str,
    me: &SignedBundle,
    req: &NewSharedVault,
    now: i64,
) -> ApiResult<i64> {
    validate::id("vault id", &req.id)?;
    validate::base64(
        "encryptedMeta",
        &req.encrypted_meta,
        validate::MAX_SMALL_LEN,
    )?;
    if req.key_epoch != 1 {
        return Err(bad("a new vault starts at key epoch 1"));
    }
    let manifest = check_manifest(
        &req.manifest,
        &req.manifest_signature,
        me,
        &req.id,
        org_id,
        1,
        1,
        [0; 32],
    )?;
    let me_id = &me.bundle.account_id;
    if manifest.value.members.len() != 1
        || manifest.value.members[0].principal_id != *me_id
        || manifest.value.members[0].role != VaultRole::Manage
        || manifest.value.members[0].key_hash != me.hash()
    {
        return Err(bad("a new vault has its creator as the only manager"));
    }
    if req.keys.len() != 1 {
        return Err(bad("a new vault needs exactly the creator's key"));
    }
    check_key(&req.keys[0], &manifest.value, me)?;
    let seq = db::next_seq(tx).await?;
    let inserted = sqlx::query(
        "INSERT INTO vaults (id, account_id, encrypted_key, encrypted_meta, revision, seq, created_at, \
         updated_at, org_id, key_epoch, rotation_pending) \
         VALUES ($1, $2, '', $3, 1, $4, $5, $6, $7, 1, 0) ON CONFLICT DO NOTHING",
    )
    .bind(&req.id)
    .bind(me_id)
    .bind(&req.encrypted_meta)
    .bind(seq)
    .bind(now)
    .bind(now)
    .bind(org_id)
    .execute(&mut **tx)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::conflict(
            "vault already exists",
            serde_json::Value::Null,
        ));
    }
    insert_manifest(tx, &req.id, &manifest, seq, now).await?;
    upsert_member(tx, &req.id, "account", me_id, VaultRole::Manage, seq, now).await?;
    upsert_key(tx, &req.id, &req.keys[0], seq, now).await?;
    Ok(seq)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WriteResult {
    pub seq: i64,
    pub key_epoch: u32,
}

/// Creates a shared vault (owners and admins).
pub async fn create(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(org_id): Path<String>,
    Json(req): Json<NewSharedVault>,
) -> ApiResult<(StatusCode, Json<WriteResult>)> {
    validate::id("organization id", &org_id)?;
    let mut tx = db::begin_write(&state.db).await?;
    access::require_admin(&mut tx, &org_id, &session.account_id).await?;
    let me = signed::own_bundle(&mut tx, &session.account_id).await?;
    let seq = insert_shared_vault(&mut tx, &org_id, &me, &req, now_ms()).await?;
    super::org_audit::record_in(
        &mut tx,
        &org_id,
        &super::org_audit::Actor::of(&session, &ip),
        "vault_created",
        super::org_audit::Target::vault(&req.id),
        serde_json::json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(WriteResult { seq, key_epoch: 1 })))
}

async fn latest_manifest(
    conn: &mut AnyConnection,
    vault_id: &str,
) -> ApiResult<Signed<VaultManifest>> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT manifest, signature FROM vault_manifests WHERE vault_id = $1 ORDER BY version DESC LIMIT 1",
    )
    .bind(vault_id)
    .fetch_optional(&mut *conn)
    .await?;
    let (manifest, signature) =
        row.ok_or_else(|| ApiError::Internal(anyhow::anyhow!("vault without manifest")))?;
    Signed::parse(&manifest, &signature).map_err(|e| ApiError::Internal(anyhow::anyhow!("{e}")))
}

/// The server's member set of a vault: (type, id) → role.
async fn member_set(
    conn: &mut AnyConnection,
    vault_id: &str,
) -> ApiResult<BTreeSet<(String, String, String)>> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT principal_type, principal_id, role FROM vault_members WHERE vault_id = $1",
    )
    .bind(vault_id)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows.into_iter().collect())
}

fn manifest_set(manifest: &VaultManifest) -> BTreeSet<(String, String, String)> {
    manifest
        .members
        .iter()
        .map(|e| {
            (
                e.principal_type.as_str().to_owned(),
                e.principal_id.clone(),
                e.role.as_str().to_owned(),
            )
        })
        .collect()
}

/// Accounts that are members of a vault directly or through groups.
async fn account_members(conn: &mut AnyConnection, vault_id: &str) -> ApiResult<Vec<String>> {
    let direct: Vec<String> = sqlx::query_scalar(
        "SELECT principal_id FROM vault_members WHERE vault_id = $1 AND principal_type = 'account'",
    )
    .bind(vault_id)
    .fetch_all(&mut *conn)
    .await?;
    let via_groups: Vec<String> = sqlx::query_scalar(
        "SELECT group_members.account_id FROM vault_members \
         JOIN org_groups ON org_groups.id = vault_members.principal_id \
         JOIN group_members ON group_members.group_id = org_groups.id \
           AND group_members.key_version = org_groups.key_version \
         WHERE vault_members.vault_id = $1 AND vault_members.principal_type = 'group'",
    )
    .bind(vault_id)
    .fetch_all(&mut *conn)
    .await?;
    let mut all: Vec<String> = direct.into_iter().chain(via_groups).collect();
    all.sort();
    all.dedup();
    Ok(all)
}

/// Adds a member to a vault or changes a member's role (managers).
pub async fn put_member(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(vault_id): Path<String>,
    Json(req): Json<VaultMemberChange>,
) -> ApiResult<Json<WriteResult>> {
    validate::id("vault id", &vault_id)?;
    validate::id("principalId", &req.principal_id)?;
    let principal_type =
        PrincipalType::parse(&req.principal_type).map_err(|_| bad("invalid principalType"))?;
    let role = VaultRole::parse(&req.role).map_err(|_| bad("invalid role"))?;
    let mut tx = db::begin_write(&state.db).await?;
    let (org_id, key_epoch) =
        require_vault_manager(&mut tx, &vault_id, &session.account_id).await?;
    // Guests are view-only (B8): sharing with them means `view`.
    if principal_type == PrincipalType::Account
        && role > VaultRole::View
        && access::is_guest(&mut tx, &org_id, &req.principal_id).await?
    {
        return Err(access::guest_view_only());
    }
    let key_epoch = u32::try_from(key_epoch).map_err(|_| bad("invalid key epoch"))?;
    let me = signed::own_bundle(&mut tx, &session.account_id).await?;
    let latest = latest_manifest(&mut tx, &vault_id).await?;
    let manifest = check_manifest(
        &req.manifest,
        &req.manifest_signature,
        &me,
        &vault_id,
        &org_id,
        latest.value.version + 1,
        key_epoch,
        latest.hash(),
    )?;
    check_entries(&mut tx, &org_id, &manifest.value).await?;
    let entry = manifest
        .value
        .entry(principal_type, &req.principal_id)
        .ok_or_else(|| bad("the manifest does not list the new member"))?;
    if entry.role != role
        || req.key.principal_type != req.principal_type
        || req.key.principal_id != req.principal_id
    {
        return Err(bad("the manifest does not match the change"));
    }
    check_key(&req.key, &manifest.value, &me)?;
    // The manifest must equal the current members plus this change.
    let mut expected = member_set(&mut tx, &vault_id).await?;
    expected.retain(|(t, id, _)| !(*t == req.principal_type && *id == req.principal_id));
    expected.insert((
        req.principal_type.clone(),
        req.principal_id.clone(),
        role.as_str().to_owned(),
    ));
    if expected != manifest_set(&manifest.value) {
        return Err(bad("the manifest does not match the vault's members"));
    }

    let now = now_ms();
    let seq = db::next_seq(&mut tx).await?;
    insert_manifest(&mut tx, &vault_id, &manifest, seq, now).await?;
    upsert_member(
        &mut tx,
        &vault_id,
        &req.principal_type,
        &req.principal_id,
        role,
        seq,
        now,
    )
    .await?;
    upsert_key(&mut tx, &vault_id, &req.key, seq, now).await?;
    super::org_audit::record_in(
        &mut tx,
        &org_id,
        &super::org_audit::Actor::of(&session, &ip),
        "vault_access_granted",
        super::org_audit::Target::vault(&vault_id),
        json!({ "principalType": req.principal_type, "principalId": req.principal_id, "role": req.role }),
    )
    .await?;
    tx.commit().await?;
    if principal_type == PrincipalType::Account && req.principal_id != session.account_id {
        record_event(
            &state,
            &req.principal_id,
            "vault_shared",
            &session.device_name,
            &session.client_kind,
            &ip,
        )
        .await?;
    }
    record_event(
        &state,
        &session.account_id,
        "vault_member_changed",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    Ok(Json(WriteResult { seq, key_epoch }))
}

/// Rotates a vault's key, removing members (managers). This is the only
/// way to remove a member, so a removal always comes with a new key.
pub async fn rotate(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(vault_id): Path<String>,
    Json(req): Json<RotateVault>,
) -> ApiResult<Json<WriteResult>> {
    validate::id("vault id", &vault_id)?;
    validate::base64(
        "encryptedMeta",
        &req.encrypted_meta,
        validate::MAX_SMALL_LEN,
    )?;
    let mut tx = db::begin_write(&state.db).await?;
    let (org_id, key_epoch) =
        require_vault_manager(&mut tx, &vault_id, &session.account_id).await?;
    let key_epoch = u32::try_from(key_epoch).map_err(|_| bad("invalid key epoch"))?;
    if req.key_epoch != key_epoch + 1 {
        return Err(ApiError::conflict(
            "the vault's key was rotated meanwhile; sync and try again",
            json!({ "currentKeyEpoch": key_epoch }),
        ));
    }
    let me = signed::own_bundle(&mut tx, &session.account_id).await?;
    let latest = latest_manifest(&mut tx, &vault_id).await?;
    let manifest = check_manifest(
        &req.manifest,
        &req.manifest_signature,
        &me,
        &vault_id,
        &org_id,
        latest.value.version + 1,
        req.key_epoch,
        latest.hash(),
    )?;
    check_entries(&mut tx, &org_id, &manifest.value).await?;
    // Remaining members: the current ones without the removed (and without
    // members that left the organization, which the client drops as well).
    let removed: BTreeSet<(String, String)> = req
        .removed
        .iter()
        .map(|r| (r.principal_type.clone(), r.principal_id.clone()))
        .collect();
    let mut expected = member_set(&mut tx, &vault_id).await?;
    expected.retain(|(t, id, _)| !removed.contains(&(t.clone(), id.clone())));
    if expected != manifest_set(&manifest.value) {
        return Err(bad("the manifest does not match the remaining members"));
    }
    if req.keys.len() != manifest.value.members.len() {
        return Err(bad("every remaining member needs the new key"));
    }
    let mut seen = BTreeSet::new();
    for key in &req.keys {
        check_key(key, &manifest.value, &me)?;
        if !seen.insert((key.principal_type.clone(), key.principal_id.clone())) {
            return Err(bad("duplicate key"));
        }
    }
    let removed_accounts: Vec<String> = removed
        .iter()
        .filter(|(t, _)| t == "account")
        .map(|(_, id)| id.clone())
        .collect();

    let now = now_ms();
    let seq = db::next_seq(&mut tx).await?;
    insert_manifest(&mut tx, &vault_id, &manifest, seq, now).await?;
    for (principal_type, principal_id) in &removed {
        sqlx::query(
            "DELETE FROM vault_members WHERE vault_id = $1 AND principal_type = $2 AND principal_id = $3",
        )
        .bind(&vault_id)
        .bind(principal_type)
        .bind(principal_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "DELETE FROM vault_keys WHERE vault_id = $1 AND principal_type = $2 AND principal_id = $3",
        )
        .bind(&vault_id)
        .bind(principal_type)
        .bind(principal_id)
        .execute(&mut *tx)
        .await?;
    }
    for key in &req.keys {
        upsert_key(&mut tx, &vault_id, key, seq, now).await?;
    }
    sqlx::query(
        "UPDATE vaults SET key_epoch = $1, encrypted_meta = $2, revision = revision + 1, \
         rotation_pending = 0, seq = $3, updated_at = $4 WHERE id = $5",
    )
    .bind(i64::from(req.key_epoch))
    .bind(&req.encrypted_meta)
    .bind(seq)
    .bind(now)
    .bind(&vault_id)
    .execute(&mut *tx)
    .await?;
    super::org_audit::record_in(
        &mut tx,
        &org_id,
        &super::org_audit::Actor::of(&session, &ip),
        if req.removed.is_empty() { "vault_key_rotated" } else { "vault_access_revoked" },
        super::org_audit::Target::vault(&vault_id),
        json!({ "keyEpoch": req.key_epoch, "removed": req.removed.iter().map(|r| format!("{}:{}", r.principal_type, r.principal_id)).collect::<Vec<_>>() }),
    )
    .await?;
    tx.commit().await?;
    for account in removed_accounts {
        record_event(
            &state,
            &account,
            "vault_unshared",
            &session.device_name,
            &session.client_kind,
            &ip,
        )
        .await?;
    }
    record_event(
        &state,
        &session.account_id,
        "vault_key_rotated",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    Ok(Json(WriteResult {
        seq,
        key_epoch: req.key_epoch,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WrappedKeyRequest {
    wrapped_key: String,
}

/// Stores the caller's own wrapped copy of a vault key it opened.
pub async fn put_wrapped_key(
    State(state): State<AppState>,
    session: Session,
    Path((vault_id, epoch)): Path<(String, i64)>,
    Json(req): Json<WrappedKeyRequest>,
) -> ApiResult<StatusCode> {
    validate::id("vault id", &vault_id)?;
    validate::base64("wrappedKey", &req.wrapped_key, validate::MAX_SMALL_LEN)?;
    let mut tx = db::begin_write(&state.db).await?;
    access::vault_access(&mut tx, &vault_id, &session.account_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let seq = db::next_seq(&mut tx).await?;
    let updated = sqlx::query(
        "UPDATE vault_keys SET wrapped_key = $1, seq = $2 WHERE vault_id = $3 AND key_epoch = $4 \
         AND principal_type = 'account' AND principal_id = $5",
    )
    .bind(&req.wrapped_key)
    .bind(seq)
    .bind(&vault_id)
    .bind(epoch)
    .bind(&session.account_id)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultMembersResponse {
    vault_id: String,
    org_id: String,
    key_epoch: i64,
    rotation_pending: bool,
    members: Vec<VaultMemberRow>,
    /// Accounts with access, directly or through groups.
    accounts: Vec<String>,
    manifests: Vec<passbox_core::sharing::data::ManifestRecord>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultMemberRow {
    principal_type: String,
    principal_id: String,
    role: String,
}

/// Members of a shared vault and its manifest chain (any member).
pub async fn members(
    State(state): State<AppState>,
    session: Session,
    Path(vault_id): Path<String>,
) -> ApiResult<Json<VaultMembersResponse>> {
    validate::id("vault id", &vault_id)?;
    let mut conn = state.db.acquire().await?;
    let Some(access::VaultAccess::Shared {
        org_id, key_epoch, ..
    }) = access::vault_access(&mut conn, &vault_id, &session.account_id).await?
    else {
        return Err(ApiError::NotFound);
    };
    let rotation_pending: i64 =
        sqlx::query_scalar("SELECT rotation_pending FROM vaults WHERE id = $1")
            .bind(&vault_id)
            .fetch_one(&mut *conn)
            .await?;
    let members = member_set(&mut conn, &vault_id)
        .await?
        .into_iter()
        .map(|(principal_type, principal_id, role)| VaultMemberRow {
            principal_type,
            principal_id,
            role,
        })
        .collect();
    let accounts = account_members(&mut conn, &vault_id).await?;
    let manifests = manifest_chain(&mut conn, &vault_id).await?;
    Ok(Json(VaultMembersResponse {
        vault_id,
        org_id,
        key_epoch,
        rotation_pending: rotation_pending != 0,
        members,
        accounts,
        manifests,
    }))
}

pub async fn manifest_chain(
    conn: &mut AnyConnection,
    vault_id: &str,
) -> ApiResult<Vec<passbox_core::sharing::data::ManifestRecord>> {
    let rows: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT version, manifest, signature FROM vault_manifests WHERE vault_id = $1 ORDER BY version",
    )
    .bind(vault_id)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(version, manifest, signature)| passbox_core::sharing::data::ManifestRecord {
                vault_id: vault_id.to_owned(),
                version: u64::try_from(version).unwrap_or_default(),
                manifest,
                signature,
            },
        )
        .collect())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchItem {
    id: String,
    revision: i64,
    key_epoch: i64,
    encrypted_data: String,
}

#[derive(Deserialize)]
pub struct BatchRequest {
    items: Vec<BatchItem>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchResult {
    id: String,
    /// `ok` or `conflict` (the item changed meanwhile; sync and retry).
    status: &'static str,
    revision: i64,
}

/// Writes up to 100 items of one vault in a transaction, for re-encrypting
/// a vault after a key rotation. Each item needs the next revision and the
/// vault's current key epoch; items that changed meanwhile are reported as
/// conflicts and skipped.
pub async fn batch_items(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(vault_id): Path<String>,
    Json(req): Json<BatchRequest>,
) -> ApiResult<Json<Vec<BatchResult>>> {
    validate::id("vault id", &vault_id)?;
    if req.items.is_empty() || req.items.len() > MAX_BATCH_ITEMS {
        return Err(bad("send between 1 and 100 items"));
    }
    for item in &req.items {
        validate::id("item id", &item.id)?;
        validate::revision(item.revision)?;
        validate::base64(
            "encryptedData",
            &item.encrypted_data,
            validate::MAX_ITEM_LEN,
        )?;
    }
    let mut tx = db::begin_write(&state.db).await?;
    let access = access::require_vault_write(&mut tx, &vault_id, &session.account_id).await?;
    let (current_epoch, batch_org) = match &access {
        access::VaultAccess::Shared {
            key_epoch, org_id, ..
        } => (*key_epoch, Some(org_id.clone())),
        access::VaultAccess::Personal => (0, None),
    };
    let now = now_ms();
    let mut results = Vec::with_capacity(req.items.len());
    for item in &req.items {
        if item.key_epoch != current_epoch {
            return Err(ApiError::conflict(
                "the vault's key was rotated; encrypt with the current key epoch",
                json!({ "currentKeyEpoch": current_epoch }),
            ));
        }
        let row: Option<(String, i64)> =
            sqlx::query_as("SELECT vault_id, revision FROM items WHERE id = $1")
                .bind(&item.id)
                .fetch_optional(&mut *tx)
                .await?;
        let status = match row {
            Some((v, _)) if v != vault_id => return Err(ApiError::NotFound),
            Some((_, revision)) if item.revision == revision + 1 => {
                super::items::record_version(&mut tx, &item.id).await?;
                let seq = db::next_seq(&mut tx).await?;
                sqlx::query(
                    "UPDATE items SET encrypted_data = $1, revision = $2, deleted = 0, seq = $3, \
                     updated_at = $4, key_epoch = $5, updated_by = $6 WHERE id = $7",
                )
                .bind(&item.encrypted_data)
                .bind(item.revision)
                .bind(seq)
                .bind(now)
                .bind(item.key_epoch)
                .bind(&session.id)
                .bind(&item.id)
                .execute(&mut *tx)
                .await?;
                "ok"
            }
            None if item.revision == 1 => {
                let seq = db::next_seq(&mut tx).await?;
                sqlx::query(
                    "INSERT INTO items (id, vault_id, encrypted_data, revision, deleted, seq, created_at, \
                     updated_at, key_epoch, updated_by) VALUES ($1, $2, $3, 1, 0, $4, $5, $6, $7, $8)",
                )
                .bind(&item.id)
                .bind(&vault_id)
                .bind(&item.encrypted_data)
                .bind(seq)
                .bind(now)
                .bind(now)
                .bind(item.key_epoch)
                .bind(&session.id)
                .execute(&mut *tx)
                .await?;
                "ok"
            }
            _ => "conflict",
        };
        results.push(BatchResult {
            id: item.id.clone(),
            status,
            revision: item.revision,
        });
    }
    if let Some(org_id) = &batch_org {
        let written = results.iter().filter(|r| r.status == "ok").count();
        super::org_audit::record_in(
            &mut tx,
            org_id,
            &super::org_audit::Actor::of(&session, &ip),
            "vault_items_written",
            super::org_audit::Target::vault(&vault_id),
            json!({ "count": written, "keyEpoch": current_epoch }),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(Json(results))
}

/// Helper for organization removal: marks vaults whose members include the
/// account (directly or through one of `groups`) as needing a rotation and
/// returns their IDs.
pub async fn mark_rotation_pending(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    org_id: &str,
    account_id: &str,
    groups: &[String],
    seq: i64,
) -> ApiResult<Vec<String>> {
    let mut vaults: Vec<String> = sqlx::query_scalar(
        "SELECT vaults.id FROM vaults JOIN vault_members ON vault_members.vault_id = vaults.id \
         WHERE vaults.org_id = $1 AND vault_members.principal_type = 'account' \
         AND vault_members.principal_id = $2",
    )
    .bind(org_id)
    .bind(account_id)
    .fetch_all(&mut **tx)
    .await?;
    for group in groups {
        let shared: Vec<String> = sqlx::query_scalar(
            "SELECT vault_id FROM vault_members WHERE principal_type = 'group' AND principal_id = $1",
        )
        .bind(group)
        .fetch_all(&mut **tx)
        .await?;
        vaults.extend(shared);
    }
    vaults.sort();
    vaults.dedup();
    for vault in &vaults {
        sqlx::query("UPDATE vaults SET rotation_pending = 1, seq = $1 WHERE id = $2")
            .bind(seq)
            .bind(vault)
            .execute(&mut **tx)
            .await?;
    }
    Ok(vaults)
}
