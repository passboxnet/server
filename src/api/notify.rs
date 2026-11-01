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
    let mut tx = state.db.as_account(account_id).await?;
    let notify = sqlx::query_scalar!(
        "SELECT notify_new_device FROM accounts WHERE id = $1",
        account_id
    )
    .fetch_optional(&mut *tx)
    .await?;
    if !notify.unwrap_or(false) {
        return Ok(());
    }
    // Called before this login is recorded in the activity log.
    let signed_in_before = sqlx::query_scalar!(
        r#"SELECT 1 AS "found!" FROM account_events WHERE account_id = $1 AND kind = 'login' LIMIT 1"#,
        account_id
    )
    .fetch_optional(&mut *tx)
    .await?;
    drop(tx);
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

/// After the account's address was changed: to the old address, so a
/// hijacked session cannot move the account away unnoticed.
pub async fn email_changed(
    state: &AppState,
    account_id: &str,
    old_email: &str,
    new_email: &str,
    device_name: &str,
    ip: &str,
) {
    let result = async {
        let mut tx = state.db.as_account(account_id).await?;
        let locale = sqlx::query_scalar!("SELECT locale FROM accounts WHERE id = $1", account_id)
            .fetch_one(&mut *tx)
            .await?;
        let locale = match crate::mail::Locale::parse(&locale) {
            Some(locale) => locale,
            None => {
                crate::instance::load_settings(&mut tx)
                    .await?
                    .default_locale
            }
        };
        drop(tx);
        let params = json!({
            "email": old_email,
            "newEmail": new_email,
            "device": device_name,
            "ip": ip,
            "time": crate::db::now_ms(),
        });
        state
            .mailer
            .enqueue(old_email, Template::EmailChanged, locale, params)
            .await
    }
    .await;
    if let Err(err) = result {
        tracing::warn!(error = ?err, "could not queue the email-changed mail");
    }
}
