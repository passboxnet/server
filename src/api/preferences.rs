//! Account preferences the server needs to know: the language of mails and
//! which notifications to send.

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};

use super::auth::Session;
use crate::error::{ApiError, ApiResult};
use crate::mail::Locale;
use crate::state::AppState;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Preferences {
    /// `en`, `de`, or `null` for the instance default.
    locale: Option<Locale>,
    /// Mail when a new device signs in.
    notify_new_device: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreferencesUpdate {
    /// `en`, `de`, or an empty string for the instance default. Omitted
    /// fields stay unchanged.
    #[serde(default)]
    locale: Option<String>,
    #[serde(default)]
    notify_new_device: Option<bool>,
}

async fn load(state: &AppState, account_id: &str) -> ApiResult<Preferences> {
    let mut tx = state.db.as_account(account_id).await?;
    let row = sqlx::query!(
        "SELECT locale, notify_new_device FROM accounts WHERE id = $1",
        account_id
    )
    .fetch_one(&mut *tx)
    .await?;
    Ok(Preferences {
        locale: Locale::parse(&row.locale),
        notify_new_device: row.notify_new_device,
    })
}

pub async fn get(State(state): State<AppState>, session: Session) -> ApiResult<Json<Preferences>> {
    Ok(Json(load(&state, &session.account_id).await?))
}

pub async fn put(
    State(state): State<AppState>,
    session: Session,
    Json(update): Json<PreferencesUpdate>,
) -> ApiResult<Json<Preferences>> {
    let mut tx = state.db.as_account(&session.account_id).await?;
    if let Some(locale) = update.locale {
        let value = if locale.is_empty() {
            ""
        } else {
            Locale::parse(&locale)
                .ok_or_else(|| ApiError::bad_request("locale must be en, de or empty"))?
                .as_str()
        };
        sqlx::query!(
            "UPDATE accounts SET locale = $1 WHERE id = $2",
            value,
            session.account_id,
        )
        .execute(&mut *tx)
        .await?;
    }
    if let Some(notify) = update.notify_new_device {
        sqlx::query!(
            "UPDATE accounts SET notify_new_device = $1 WHERE id = $2",
            notify,
            session.account_id,
        )
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(Json(load(&state, &session.account_id).await?))
}
