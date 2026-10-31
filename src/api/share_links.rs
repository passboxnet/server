//! Share links for people without an account.
//!
//! The sender's device encrypts a snapshot with a random key that only
//! travels in the link's fragment (`passbox_core::share_link`). The server
//! stores the ciphertext, the hash of the access token, the expiry and the
//! view limit. Opening a link needs the access token (derived from the key
//! and, if set, the passphrase), so knowing a link ID alone neither reveals
//! anything nor uses up views. Links are deleted when they expire, after
//! the last allowed view, after too many wrong passphrases, or by their
//! creator. Organization policies can forbid or limit links for items
//! of their vaults; the server enforces that for the vault the client names.

use std::time::Duration;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use passbox_core::policy::{MAX_SHARE_LINK_DAYS, ShareLinkRule};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::access;
use super::auth::Session;
use super::validate;
use crate::db::{Public, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::security::ClientIp;
use crate::state::AppState;

const DAY_MS: i64 = 24 * 60 * 60 * 1000;
/// Most views a link may allow (0 = unlimited).
pub const MAX_VIEWS: i64 = 1000;
/// Links per account that have not expired.
pub const MAX_ACTIVE_LINKS: i64 = 500;
/// Wrong access tokens (passphrases) before a link is deleted.
pub const MAX_FAILED_ATTEMPTS: i64 = 10;
/// Snapshot size limit (Base64url characters).
pub const MAX_BLOB_LEN: usize = 512 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRequest {
    id: String,
    encrypted_label: String,
    blob: String,
    auth_hash: String,
    #[serde(default)]
    salt: Option<String>,
    expires_at: i64,
    /// 0 = unlimited.
    #[serde(default)]
    max_views: i64,
    /// The vault the shared item comes from (for its organization's policy).
    #[serde(default)]
    vault_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkInfo {
    id: String,
    encrypted_label: String,
    vault_id: Option<String>,
    expires_at: i64,
    max_views: i64,
    views: i64,
    has_passphrase: bool,
    created_at: i64,
    last_viewed_at: i64,
}

#[derive(Serialize)]
pub struct ListResponse {
    links: Vec<LinkInfo>,
}

/// Deletes expired links of every account (a function: accounts cannot
/// see each other's links).
async fn purge_expired(conn: &mut sqlx::PgConnection) -> ApiResult<()> {
    sqlx::query!("SELECT passbox.purge_expired_share_links($1)", now_ms())
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// `POST /api/v1/share-links`.
pub async fn create(
    State(state): State<AppState>,
    session: Session,
    Json(req): Json<CreateRequest>,
) -> ApiResult<(StatusCode, Json<LinkInfo>)> {
    validate::id("id", &req.id)?;
    validate::base64(
        "encryptedLabel",
        &req.encrypted_label,
        validate::MAX_SMALL_LEN,
    )?;
    validate::base64("blob", &req.blob, MAX_BLOB_LEN)?;
    if validate::base64("authHash", &req.auth_hash, 64)?.len() != 32 {
        return Err(ApiError::bad_request("authHash must be 32 bytes"));
    }
    if let Some(salt) = &req.salt
        && validate::base64("salt", salt, 64)?.len() != 16
    {
        return Err(ApiError::bad_request("salt must be 16 bytes"));
    }
    let now = now_ms();
    if req.expires_at <= now || req.expires_at > now + i64::from(MAX_SHARE_LINK_DAYS) * DAY_MS {
        return Err(ApiError::bad_request(format!(
            "links expire within {MAX_SHARE_LINK_DAYS} days"
        )));
    }
    if !(0..=MAX_VIEWS).contains(&req.max_views) {
        return Err(ApiError::bad_request(format!(
            "maxViews must be between 0 and {MAX_VIEWS}"
        )));
    }

    let mut tx = state.db.as_account(&session.account_id).await?;
    let mut org_id = None;
    if let Some(vault_id) = &req.vault_id {
        validate::id("vaultId", vault_id)?;
        match access::vault_access(&mut tx, vault_id, &session.account_id).await? {
            None => return Err(ApiError::NotFound),
            Some(access::VaultAccess::Personal) => {}
            Some(access::VaultAccess::Shared { org_id: org, .. }) => {
                if access::is_guest(&mut tx, &org, &session.account_id).await? {
                    return Err(access::guest_view_only());
                }
                if let Some(rules) = super::org_policy::current_rules(&mut tx, &org).await? {
                    check_policy(&rules, now, req.expires_at, req.max_views)?;
                }
                org_id = Some(org);
            }
        }
    }
    purge_expired(&mut tx).await?;
    let active: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"count!\" FROM share_links WHERE account_id = $1",
        &session.account_id,
    )
    .fetch_one(&mut *tx)
    .await?;
    if active >= MAX_ACTIVE_LINKS {
        return Err(ApiError::bad_request(format!(
            "you have {MAX_ACTIVE_LINKS} active links; delete some first"
        )));
    }
    sqlx::query!(
        "INSERT INTO share_links (id, account_id, org_id, vault_id, encrypted_label, blob, auth_hash, salt, \
         expires_at, max_views, views, failed_attempts, created_at, last_viewed_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 0, 0, $11, 0)",
        &req.id,
        &session.account_id,
        org_id.as_deref(),
        req.vault_id.as_deref(),
        super::vaults::decode(&req.encrypted_label)?,
        super::vaults::decode(&req.blob)?,
        &req.auth_hash,
        req.salt.as_deref(),
        req.expires_at,
        req.max_views,
        now,
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            ApiError::bad_request("a link with this ID exists")
        }
        e => e.into(),
    })?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(LinkInfo {
            id: req.id,
            encrypted_label: req.encrypted_label,
            vault_id: req.vault_id,
            expires_at: req.expires_at,
            max_views: req.max_views,
            views: 0,
            has_passphrase: req.salt.is_some(),
            created_at: now,
            last_viewed_at: 0,
        }),
    ))
}

/// The organization's limits for links (403 `policy_violation`).
fn check_policy(
    rules: &passbox_core::policy::PolicyRules,
    now: i64,
    expires_at: i64,
    max_views: i64,
) -> ApiResult<()> {
    match rules.share_links {
        ShareLinkRule::Allowed => Ok(()),
        ShareLinkRule::Forbidden => Err(ApiError::forbidden(
            "policy_violation",
            "your organization does not allow share links for its items",
        )),
        ShareLinkRule::Restricted => {
            if expires_at > now + i64::from(rules.share_link_max_days) * DAY_MS {
                return Err(ApiError::forbidden(
                    "policy_violation",
                    format!(
                        "your organization allows share links for at most {} days",
                        rules.share_link_max_days
                    ),
                ));
            }
            let limit = i64::from(rules.share_link_max_views);
            if limit > 0 && (max_views == 0 || max_views > limit) {
                return Err(ApiError::forbidden(
                    "policy_violation",
                    format!("your organization allows at most {limit} views per share link"),
                ));
            }
            Ok(())
        }
    }
}

type LinkRow = (
    String,
    Vec<u8>,
    Option<String>,
    i64,
    i64,
    i64,
    Option<String>,
    i64,
    i64,
);

/// `GET /api/v1/share-links`: the account's links that have not expired.
pub async fn list(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<Json<ListResponse>> {
    let mut conn = state.db.as_account(&session.account_id).await?;
    let rows: Vec<LinkRow> = sqlx::query!(
        "SELECT id, encrypted_label, vault_id, expires_at, max_views, views, salt, created_at, last_viewed_at \
         FROM share_links WHERE account_id = $1 AND expires_at > $2 ORDER BY created_at DESC",
        &session.account_id,
        now_ms(),
    ).map(|row| (row.id, row.encrypted_label, row.vault_id, row.expires_at, row.max_views, row.views, row.salt, row.created_at, row.last_viewed_at))
    .fetch_all(&mut *conn)
    .await?;
    Ok(Json(ListResponse {
        links: rows
            .into_iter()
            .map(
                |(
                    id,
                    encrypted_label,
                    vault_id,
                    expires_at,
                    max_views,
                    views,
                    salt,
                    created_at,
                    last_viewed_at,
                )| {
                    LinkInfo {
                        id,
                        encrypted_label: passbox_core::encoding::encode(&encrypted_label),
                        vault_id,
                        expires_at,
                        max_views,
                        views,
                        has_passphrase: salt.is_some(),
                        created_at,
                        last_viewed_at,
                    }
                },
            )
            .collect(),
    }))
}

/// `DELETE /api/v1/share-links/{id}`: ends a link at once.
pub async fn delete(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    validate::id("id", &id)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    let result = sqlx::query!(
        "DELETE FROM share_links WHERE id = $1 AND account_id = $2",
        &id,
        &session.account_id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicInfo {
    /// Base64url passphrase salt; `null` if the link has no passphrase.
    salt: Option<String>,
    expires_at: i64,
    /// Views left (`null` = unlimited).
    views_left: Option<i64>,
}

fn rate_limited(state: &AppState, ip: &str, what: &str) -> ApiResult<()> {
    if let Some(wait) = state.limiter.hit(
        &format!("share-link-{what}:{ip}"),
        60,
        Duration::from_secs(60),
    ) {
        return Err(ApiError::RateLimited(wait));
    }
    Ok(())
}

/// `GET /api/v1/public/share-links/{id}`: what the viewer page needs before
/// opening (no session).
pub async fn public_info(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
) -> ApiResult<Json<PublicInfo>> {
    rate_limited(&state, &ip, "info")?;
    validate::id("id", &id)?;
    // The viewer's context reads no table: the functions answer for one
    // link ID only.
    let mut tx = state.db.public(Public::ShareLink).await?;
    let row = sqlx::query!(
        r#"SELECT salt, expires_at AS "expires_at!", max_views AS "max_views!", views AS "views!"
           FROM passbox.share_link_info($1, $2)"#,
        &id,
        now_ms(),
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    let (salt, expires_at, max_views, views) = (row.salt, row.expires_at, row.max_views, row.views);
    Ok(Json(PublicInfo {
        salt,
        expires_at,
        views_left: (max_views > 0).then(|| (max_views - views).max(0)),
    }))
}

#[derive(Deserialize)]
pub struct OpenRequest {
    auth: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenResponse {
    blob: String,
    expires_at: i64,
    /// Views left after this one (`null` = unlimited).
    views_left: Option<i64>,
}

fn same(a: &str, b: &str) -> bool {
    // Compare hashes of both, so timing does not depend on the stored value.
    Sha256::digest(a.as_bytes()) == Sha256::digest(b.as_bytes())
}

/// `POST /api/v1/public/share-links/{id}/open`: the encrypted snapshot, for
/// a caller with the access token. Counts a view; the last allowed view
/// deletes the link.
pub async fn open(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(id): Path<String>,
    Json(req): Json<OpenRequest>,
) -> ApiResult<Json<OpenResponse>> {
    rate_limited(&state, &ip, "open")?;
    validate::id("id", &id)?;
    validate::base64("auth", &req.auth, 64)?;
    let presented = passbox_core::share_link::auth_hash(&req.auth)
        .map_err(|_| ApiError::bad_request("invalid auth"))?;
    let mut tx = state.db.public(Public::ShareLink).await?;
    let now = now_ms();
    // Locks the link until this transaction ends.
    let row = sqlx::query!(
        r#"SELECT blob AS "blob!", auth_hash AS "auth_hash!", expires_at AS "expires_at!",
                  max_views AS "max_views!", views AS "views!", failed_attempts AS "failed_attempts!"
           FROM passbox.share_link_for_open($1, $2)"#,
        &id,
        now,
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    let (blob, auth_hash, expires_at, max_views, views, failed) = (
        row.blob,
        row.auth_hash,
        row.expires_at,
        row.max_views,
        row.views,
        row.failed_attempts,
    );
    if !same(&presented, &auth_hash) {
        sqlx::query!(
            "SELECT passbox.share_link_failed($1, $2)",
            &id,
            failed + 1 >= MAX_FAILED_ATTEMPTS,
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Err(ApiError::forbidden(
            "wrong_passphrase",
            "the passphrase is not correct",
        ));
    }
    let views = views + 1;
    sqlx::query!(
        "SELECT passbox.share_link_viewed($1, $2, $3, $4, $5)",
        &id,
        &presented,
        views,
        max_views > 0 && views >= max_views,
        now,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(OpenResponse {
        blob: passbox_core::encoding::encode(&blob),
        expires_at,
        views_left: (max_views > 0).then(|| (max_views - views).max(0)),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use passbox_core::policy::PolicyRules;

    #[test]
    fn policy_limits() {
        let now = 1_000;
        let mut rules = PolicyRules::default();
        assert!(check_policy(&rules, now, now + 400 * DAY_MS, 0).is_ok());
        rules.share_links = ShareLinkRule::Forbidden;
        assert!(check_policy(&rules, now, now + DAY_MS, 1).is_err());
        rules.share_links = ShareLinkRule::Restricted;
        rules.share_link_max_days = 7;
        rules.share_link_max_views = 5;
        assert!(check_policy(&rules, now, now + 7 * DAY_MS, 5).is_ok());
        assert!(check_policy(&rules, now, now + 8 * DAY_MS, 5).is_err());
        assert!(check_policy(&rules, now, now + DAY_MS, 0).is_err());
        assert!(check_policy(&rules, now, now + DAY_MS, 6).is_err());
        rules.share_link_max_views = 0;
        assert!(check_policy(&rules, now, now + DAY_MS, 0).is_ok());
    }
}
