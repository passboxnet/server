//! Vaults. A vault's key is encrypted with the owner's account key and its
//! metadata (name, icon, ...) with the vault key.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::auth::{NewVaultRequest, Session};
use super::validate;
use crate::db::{self, Conn, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::security::ClientIp;
use crate::state::AppState;

/// Decodes Base64url the handler already validated (for `BYTEA` columns).
pub(crate) fn decode(text: &str) -> ApiResult<Vec<u8>> {
    passbox_core::encoding::decode(text).map_err(|_| ApiError::bad_request("invalid Base64url"))
}

pub fn validate_new_vault(vault: &NewVaultRequest) -> ApiResult<()> {
    validate::id("vault id", &vault.id)?;
    validate::base64(
        "encryptedKey",
        &vault.encrypted_key,
        validate::MAX_SMALL_LEN,
    )?;
    validate::base64(
        "encryptedMeta",
        &vault.encrypted_meta,
        validate::MAX_SMALL_LEN,
    )?;
    Ok(())
}

/// Inserts a personal vault (validated with [`validate_new_vault`]).
pub async fn insert_vault(
    conn: &mut Conn,
    account_id: &str,
    vault: &NewVaultRequest,
    now: i64,
) -> ApiResult<i64> {
    let seq = db::next_seq(conn).await?;
    let inserted = sqlx::query!(
        "INSERT INTO vaults (id, account_id, encrypted_key, encrypted_meta, revision, seq, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, 1, $5, $6, $6) ON CONFLICT DO NOTHING",
        vault.id,
        account_id,
        decode(&vault.encrypted_key)?,
        decode(&vault.encrypted_meta)?,
        seq,
        now,
    )
    .execute(conn)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::conflict(
            "vault already exists",
            serde_json::Value::Null,
        ));
    }
    Ok(seq)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WriteResponse {
    pub revision: i64,
    pub seq: i64,
}

pub async fn create(
    State(state): State<AppState>,
    session: Session,
    Json(req): Json<NewVaultRequest>,
) -> ApiResult<(StatusCode, Json<WriteResponse>)> {
    validate_new_vault(&req)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    // Organization policy: organizations can turn personal vaults off.
    super::org_policy::ensure_personal_vaults_allowed(&mut tx, &session.account_id).await?;
    let seq = insert_vault(&mut tx, &session.account_id, &req, now_ms()).await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(WriteResponse { revision: 1, seq }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateVaultRequest {
    /// The new revision; must be exactly one higher than the stored one.
    revision: i64,
    encrypted_meta: String,
    /// Key epoch of `encrypted_meta` (shared vaults; 0 for personal vaults).
    #[serde(default)]
    key_epoch: i64,
}

pub async fn update(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(vault_id): Path<String>,
    Json(req): Json<UpdateVaultRequest>,
) -> ApiResult<Json<WriteResponse>> {
    validate::id("vault id", &vault_id)?;
    validate::revision(req.revision)?;
    validate::base64(
        "encryptedMeta",
        &req.encrypted_meta,
        validate::MAX_SMALL_LEN,
    )?;

    let mut tx = state.db.as_account(&session.account_id).await?;
    let mut shared_org = None;
    match super::access::vault_access(&mut tx, &vault_id, &session.account_id).await? {
        None => return Err(ApiError::NotFound),
        Some(super::access::VaultAccess::Personal) => {}
        Some(super::access::VaultAccess::Shared { org_id, .. }) => {
            shared_org = Some(org_id);
            let (_, key_epoch) =
                super::access::require_vault_manager(&mut tx, &vault_id, &session.account_id)
                    .await?;
            if key_epoch != req.key_epoch {
                return Err(ApiError::conflict(
                    "the vault's key was rotated; encrypt with the current key epoch",
                    json!({ "currentKeyEpoch": key_epoch }),
                ));
            }
        }
    }
    let current = sqlx::query_scalar!(
        "SELECT revision FROM vaults WHERE id = $1 FOR UPDATE",
        vault_id
    )
    .fetch_one(&mut *tx)
    .await?;
    if req.revision != current + 1 {
        return Err(ApiError::conflict(
            "vault was changed by another device",
            json!({ "currentRevision": current }),
        ));
    }
    let seq = db::next_seq(&mut tx).await?;
    sqlx::query!(
        "UPDATE vaults SET encrypted_meta = $1, revision = $2, seq = $3, updated_at = $4 WHERE id = $5",
        decode(&req.encrypted_meta)?,
        req.revision,
        seq,
        now_ms(),
        vault_id,
    )
    .execute(&mut *tx)
    .await?;
    if let Some(org_id) = &shared_org {
        super::org_audit::record_in(
            &mut tx,
            org_id,
            &super::org_audit::Actor::of(&session, &ip),
            "vault_renamed",
            super::org_audit::Target::vault(&vault_id),
            serde_json::json!({}),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(Json(WriteResponse {
        revision: req.revision,
        seq,
    }))
}
