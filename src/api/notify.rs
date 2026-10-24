//! Security notifications by mail. Failing to queue a notification never
//! fails the request that caused it; the error is logged.

use serde_json::json;

use crate::mail::Template;
use crate::state::AppState;

/// After a successful login: mails the account owner when the login came
/// from a new device, that is, without a valid device token. The very first
/// login of an account (right after registering) is not reported, and the
/// owner can turn the mail off (`notifyNewDevice`).
pub async fn signed_in(
    state: &AppState,
    account_id: &str,
    known_device: bool,
    device_name: &str,
    ip: &str,
    now: i64,
) {
    if known_device {
        return;
    }
    if let Err(err) = new_device(state, account_id, device_name, ip, now).await {
        tracing::warn!(error = ?err, "could not queue the new-device mail");
    }
}

async fn new_device(
    state: &AppState,
    account_id: &str,
    device_name: &str,
    ip: &str,
    now: i64,
) -> anyhow::Result<()> {
    let notify: Option<i64> =
        sqlx::query_scalar("SELECT notify_new_device FROM accounts WHERE id = $1")
            .bind(account_id)
            .fetch_optional(&state.db)
            .await?;
    if notify.unwrap_or(0) == 0 {
        return Ok(());
    }
    // Called before this login is recorded in the activity log.
    let signed_in_before: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM account_events WHERE account_id = $1 AND kind = 'login' LIMIT 1",
    )
    .bind(account_id)
    .fetch_optional(&state.db)
    .await?;
    if signed_in_before.is_none() {
        return Ok(());
    }
    state
        .mailer
        .enqueue_for_account(
            account_id,
            Template::NewDevice,
            json!({ "device": device_name, "ip": ip, "time": now }),
        )
        .await?;
    Ok(())
}

/// After a master password change.
pub async fn password_changed(state: &AppState, account_id: &str, device_name: &str, ip: &str) {
    let params = json!({ "device": device_name, "ip": ip, "time": crate::db::now_ms() });
    if let Err(err) = state
        .mailer
        .enqueue_for_account(account_id, Template::MasterPasswordChanged, params)
        .await
    {
        tracing::warn!(error = ?err, "could not queue the password-changed mail");
    }
}

/// After two-factor sign-in was turned on (`enabled`), off (`disabled`) or
/// a method or the recovery codes changed (`changed`).
pub async fn two_factor_changed(
    state: &AppState,
    account_id: &str,
    change: &str,
    device_name: &str,
    ip: &str,
) {
    let params =
        json!({ "change": change, "device": device_name, "ip": ip, "time": crate::db::now_ms() });
    if let Err(err) = state
        .mailer
        .enqueue_for_account(account_id, Template::TwoFactorChanged, params)
        .await
    {
        tracing::warn!(error = ?err, "could not queue the two-factor mail");
    }
}
