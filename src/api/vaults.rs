//! Vaults. A vault's key is encrypted with the owner's account key and its
//! metadata (name, icon, ...) with the vault key.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::auth::{NewVaultRequest, Session};
use super::validate;
use crate::db::{self, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

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

pub async fn insert_vault(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    account_id: &str,
    vault: &NewVaultRequest,
    now: i64,
) -> ApiResult<i64> {
    let seq = db::next_seq(tx).await?;
    let inserted = sqlx::query(
        "INSERT INTO vaults (id, account_id, encrypted_key, encrypted_meta, revision, seq, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, 1, $5, $6, $7) ON CONFLICT DO NOTHING",
    )
    .bind(&vault.id)
    .bind(account_id)
    .bind(&vault.encrypted_key)
    .bind(&vault.encrypted_meta)
    .bind(seq)
    .bind(now)
    .bind(now)
    .execute(&mut **tx)
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
    let mut tx = state.db.begin().await?;
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
}

pub async fn update(
    State(state): State<AppState>,
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

    let mut tx = state.db.begin().await?;
    let current: Option<i64> =
        sqlx::query_scalar("SELECT revision FROM vaults WHERE id = $1 AND account_id = $2")
            .bind(&vault_id)
            .bind(&session.account_id)
            .fetch_optional(&mut *tx)
            .await?;
    let current = current.ok_or(ApiError::NotFound)?;
    if req.revision != current + 1 {
        return Err(ApiError::conflict(
            "vault was changed by another device",
            json!({ "currentRevision": current }),
        ));
    }
    let seq = db::next_seq(&mut tx).await?;
    sqlx::query("UPDATE vaults SET encrypted_meta = $1, revision = $2, seq = $3, updated_at = $4 WHERE id = $5")
        .bind(&req.encrypted_meta)
        .bind(req.revision)
        .bind(seq)
        .bind(now_ms())
        .bind(&vault_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(WriteResponse {
        revision: req.revision,
        seq,
    }))
}
