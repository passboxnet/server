//! The signed-in devices of an account: list them and sign them out.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Serialize;

use super::auth::{Session, record_event};
use super::validate;
use crate::db::now_ms;
use crate::error::{ApiError, ApiResult};
use crate::security::ClientIp;
use crate::state::AppState;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    id: String,
    device_name: String,
    client_kind: String,
    ip: String,
    created_at: i64,
    last_used_at: i64,
    expires_at: i64,
    /// True for the session making this request.
    current: bool,
}

pub async fn list(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<Json<Vec<SessionInfo>>> {
    let mut tx = state.db.as_account(&session.account_id).await?;
    let rows = sqlx::query!(
        "SELECT id, device_name, client_kind, ip, created_at, last_used_at, expires_at FROM sessions \
         WHERE account_id = $1 AND expires_at > $2 ORDER BY last_used_at DESC",
        session.account_id,
        now_ms(),
    )
    .fetch_all(&mut *tx)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| SessionInfo {
                current: row.id == session.id,
                id: row.id,
                device_name: row.device_name,
                client_kind: row.client_kind,
                ip: row.ip,
                created_at: row.created_at,
                last_used_at: row.last_used_at,
                expires_at: row.expires_at,
            })
            .collect(),
    ))
}

/// Signs out one device.
pub async fn revoke(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    validate::id("session id", &id)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    let result = sqlx::query!(
        "DELETE FROM sessions WHERE id = $1 AND account_id = $2",
        id,
        session.account_id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    record_event(
        &state,
        &session.account_id,
        "session_revoked",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Signs out every device except the current one.
pub async fn revoke_others(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
) -> ApiResult<StatusCode> {
    let mut tx = state.db.as_account(&session.account_id).await?;
    sqlx::query!(
        "DELETE FROM sessions WHERE account_id = $1 AND token_hash <> $2",
        session.account_id,
        session.token_hash(),
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    record_event(
        &state,
        &session.account_id,
        "other_sessions_revoked",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
