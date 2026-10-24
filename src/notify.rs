//! Notifications for people (invitation mails), queued for a mailer.
//!
//! This is the hook between sharing and mail delivery. The sharing code
//! only calls the functions here inside its own transaction; they insert a
//! row into `notification_outbox`:
//!
//! | column | content |
//! | --- | --- |
//! | `kind` | `org_invitation` |
//! | `recipient` | normalized email address |
//! | `params` | JSON, see [`InvitationParams`] |
//! | `delivered_at` | 0 until a mailer delivered it |
//!
//! A mailer (SMTP or anything else) polls rows with `delivered_at = 0`,
//! renders the mail, sends it and then sets `delivered_at` and replaces
//! `params` with `{}`, because the link contains the invitation token. When
//! a mail subsystem with its own outbox exists, replace the body of
//! [`queue_org_invitation`] with an insert into that outbox; nothing else in
//! the sharing code depends on this table.
//!
//! Without a mailer, invitations still work: the inviter's client receives
//! the link and can pass it on by other means.

use passbox_core::id;
use serde::Serialize;

use crate::error::{ApiError, ApiResult};

/// Template parameters of an `org_invitation` notification.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitationParams<'a> {
    pub invitation_id: &'a str,
    pub org_id: &'a str,
    /// `family` or `team`. Organization names are encrypted; the server
    /// does not know them.
    pub org_kind: &'a str,
    pub inviter_email: &'a str,
    pub role: &'a str,
    /// Path of the invitation link relative to the server's public URL,
    /// `/invite/{token}`; the organization fingerprint follows as fragment
    /// when the inviter's client provided it (`#org=...`).
    pub path: &'a str,
    pub expires_at: i64,
}

/// Queues an invitation mail.
pub async fn queue_org_invitation(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    recipient: &str,
    params: &InvitationParams<'_>,
    now: i64,
) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO notification_outbox (id, kind, recipient, params, created_at, delivered_at) \
         VALUES ($1, $2, $3, $4, $5, 0)",
    )
    .bind(id::new_id().map_err(|e| ApiError::Internal(e.into()))?)
    .bind("org_invitation")
    .bind(recipient)
    .bind(serde_json::to_string(params).map_err(|e| ApiError::Internal(e.into()))?)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
