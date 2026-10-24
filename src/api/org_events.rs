//! Events API and webhooks for SIEM systems (wave D5).
//!
//! - **Pull:** an admin creates a token for the organization; a SIEM
//!   collector calls `GET /api/v1/org-events?after={seq}` with
//!   `Authorization: Bearer pbxe_…` and receives the audit entries after
//!   `seq` in order, with their hashes, so it keeps an independent copy of
//!   the chain. Only the SHA-256 of tokens is stored.
//! - **Push:** an admin registers an HTTPS URL; a background task POSTs new
//!   entries in batches, signed with HMAC-SHA256 over
//!   `"{timestamp}.{body}"` (`X-Passbox-Signature: v1=<hex>`), and retries
//!   with backoff until the receiver answers 2xx.
//!
//! Webhook URLs must use HTTPS and resolve to public addresses, unless the
//! server runs with `PASSBOX_WEBHOOK_ALLOW_PRIVATE=true` (self-hosted SIEM
//! in the same network).

use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use data_encoding::HEXLOWER;
use hmac::{Hmac, KeyInit, Mac};
use passbox_core::audit::AuditRecord;
use passbox_core::{encoding, id, random};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use super::access;
use super::auth::Session;
use super::org_audit::{self, Actor, AuditHead, AuditQuery, Target};
use super::validate;
use crate::db::{self, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::security::ClientIp;
use crate::state::AppState;

const TOKEN_PREFIX: &str = "pbxe_";
const MAX_TOKENS: i64 = 20;
const MAX_WEBHOOKS: i64 = 10;
/// Entries per webhook delivery and per pull page.
const BATCH: i64 = 100;
const PULL_MAX: i64 = 1000;

fn hash_token(token: &str) -> String {
    HEXLOWER.encode(&Sha256::digest(token.as_bytes()))
}

// --- Tokens -------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenInfo {
    id: String,
    name: String,
    created_by: String,
    created_at: i64,
    last_used_at: i64,
}

/// `GET /orgs/{id}/event-tokens` (admins).
pub async fn tokens(
    State(state): State<AppState>,
    session: Session,
    Path(org_id): Path<String>,
) -> ApiResult<Json<Vec<TokenInfo>>> {
    validate::id("organization id", &org_id)?;
    let mut conn = state.db.acquire().await?;
    access::require_admin(&mut conn, &org_id, &session.account_id).await?;
    let rows: Vec<(String, String, String, i64, i64)> = sqlx::query_as(
        "SELECT id, name, created_by, created_at, last_used_at FROM org_event_tokens \
         WHERE org_id = $1 AND revoked_at = 0 ORDER BY created_at",
    )
    .bind(&org_id)
    .fetch_all(&mut *conn)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(
                |(id, name, created_by, created_at, last_used_at)| TokenInfo {
                    id,
                    name,
                    created_by,
                    created_at,
                    last_used_at,
                },
            )
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct NewToken {
    name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedToken {
    id: String,
    /// Shown once; only its hash is stored.
    token: String,
}

fn clean_name(name: &str) -> ApiResult<String> {
    let name: String = name.chars().filter(|c| !c.is_control()).collect();
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 60 {
        return Err(ApiError::bad_request(
            "the name must have 1 to 60 characters",
        ));
    }
    Ok(name.to_owned())
}

/// `POST /orgs/{id}/event-tokens` (admins).
pub async fn create_token(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(org_id): Path<String>,
    Json(req): Json<NewToken>,
) -> ApiResult<(StatusCode, Json<CreatedToken>)> {
    validate::id("organization id", &org_id)?;
    let name = clean_name(&req.name)?;
    let mut tx = db::begin_write(&state.db).await?;
    access::require_admin(&mut tx, &org_id, &session.account_id).await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM org_event_tokens WHERE org_id = $1 AND revoked_at = 0",
    )
    .bind(&org_id)
    .fetch_one(&mut *tx)
    .await?;
    if count >= MAX_TOKENS {
        return Err(ApiError::bad_request("revoke an unused token first"));
    }
    let token_id = id::new_id().map_err(|e| ApiError::Internal(e.into()))?;
    let token = format!(
        "{TOKEN_PREFIX}{}",
        encoding::encode(&random::bytes::<32>().map_err(|e| ApiError::Internal(e.into()))?)
    );
    sqlx::query(
        "INSERT INTO org_event_tokens (id, org_id, name, token_hash, created_by, created_at, last_used_at, \
         revoked_at) VALUES ($1, $2, $3, $4, $5, $6, 0, 0)",
    )
    .bind(&token_id)
    .bind(&org_id)
    .bind(&name)
    .bind(hash_token(&token))
    .bind(&session.account_id)
    .bind(now_ms())
    .execute(&mut *tx)
    .await?;
    org_audit::record_in(
        &mut tx,
        &org_id,
        &Actor::of(&session, &ip),
        "event_token_created",
        Target {
            kind: "event_token",
            id: &token_id,
        },
        json!({ "name": name }),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(CreatedToken {
            id: token_id,
            token,
        }),
    ))
}

/// `DELETE /orgs/{id}/event-tokens/{tid}` (admins).
pub async fn revoke_token(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path((org_id, token_id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    validate::id("organization id", &org_id)?;
    validate::id("token id", &token_id)?;
    let mut tx = db::begin_write(&state.db).await?;
    access::require_admin(&mut tx, &org_id, &session.account_id).await?;
    let updated = sqlx::query(
        "UPDATE org_event_tokens SET revoked_at = $1 WHERE id = $2 AND org_id = $3 AND revoked_at = 0",
    )
    .bind(now_ms())
    .bind(&token_id)
    .bind(&org_id)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    org_audit::record_in(
        &mut tx,
        &org_id,
        &Actor::of(&session, &ip),
        "event_token_revoked",
        Target {
            kind: "event_token",
            id: &token_id,
        },
        json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Pull API -------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct PullQuery {
    #[serde(default)]
    after: i64,
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PullResponse {
    org_id: String,
    events: Vec<AuditRecord>,
    head: AuditHead,
    /// Pass as `after` for the next page.
    next_after: u64,
    has_more: bool,
}

/// `GET /api/v1/org-events?after={seq}&limit={n}` with an events token:
/// entries after `seq`, oldest first.
pub async fn pull(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PullQuery>,
) -> ApiResult<Json<PullResponse>> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|t| t.starts_with(TOKEN_PREFIX) && t.len() < 128)
        .ok_or(ApiError::Unauthorized)?;
    let hash = hash_token(token);
    if let Some(wait) =
        state
            .limiter
            .hit(&format!("org-events:{hash}"), 120, Duration::from_secs(60))
    {
        return Err(ApiError::RateLimited(wait));
    }
    let mut conn = state.db.acquire().await?;
    let row: Option<(String, String, i64)> = sqlx::query_as(
        "SELECT id, org_id, last_used_at FROM org_event_tokens WHERE token_hash = $1 AND revoked_at = 0",
    )
    .bind(&hash)
    .fetch_optional(&mut *conn)
    .await?;
    let (token_id, org_id, last_used_at) = row.ok_or(ApiError::Unauthorized)?;
    let now = now_ms();
    if now - last_used_at > 60_000 {
        sqlx::query("UPDATE org_event_tokens SET last_used_at = $1 WHERE id = $2")
            .bind(now)
            .bind(&token_id)
            .execute(&mut *conn)
            .await?;
    }
    let limit = q.limit.unwrap_or(BATCH * 5).clamp(1, PULL_MAX);
    let query = AuditQuery {
        after: Some(q.after.max(0)),
        limit: Some(limit + 1),
        ..AuditQuery::default()
    };
    let mut events = org_audit::query(&mut conn, &org_id, &query, PULL_MAX + 1).await?;
    let has_more = events.len() as i64 > limit;
    events.truncate(usize::try_from(limit).unwrap_or_default());
    let head = org_audit::head(&mut conn, &org_id).await?;
    let next_after = events
        .last()
        .map_or(u64::try_from(q.after.max(0)).unwrap_or_default(), |e| e.seq);
    Ok(Json(PullResponse {
        org_id,
        events,
        head,
        next_after,
        has_more,
    }))
}

// --- Webhooks --------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookInfo {
    id: String,
    url: String,
    active: bool,
    cursor_seq: i64,
    failures: i64,
    last_status: i64,
    last_error: String,
    last_delivery_at: i64,
    created_at: i64,
}

type WebhookRow = (String, String, i64, i64, i64, i64, String, i64, i64);

/// `GET /orgs/{id}/webhooks` (admins). Secrets are never shown again.
pub async fn webhooks(
    State(state): State<AppState>,
    session: Session,
    Path(org_id): Path<String>,
) -> ApiResult<Json<Vec<WebhookInfo>>> {
    validate::id("organization id", &org_id)?;
    let mut conn = state.db.acquire().await?;
    access::require_admin(&mut conn, &org_id, &session.account_id).await?;
    let rows: Vec<WebhookRow> = sqlx::query_as(
        "SELECT id, url, active, cursor_seq, failures, last_status, last_error, last_delivery_at, created_at \
         FROM org_webhooks WHERE org_id = $1 ORDER BY created_at",
    )
    .bind(&org_id)
    .fetch_all(&mut *conn)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(
                |(
                    id,
                    url,
                    active,
                    cursor_seq,
                    failures,
                    last_status,
                    last_error,
                    last_delivery_at,
                    created_at,
                )| WebhookInfo {
                    id,
                    url,
                    active: active != 0,
                    cursor_seq,
                    failures,
                    last_status,
                    last_error,
                    last_delivery_at,
                    created_at,
                },
            )
            .collect(),
    ))
}

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64
                || v4.octets()[0] == 0)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80)
        }
    }
}

/// Checks a webhook URL: HTTPS (HTTP only with private addresses
/// allowed), no credentials, and a host that resolves to public addresses
/// only (unless private addresses are allowed). Blocking: resolves DNS.
pub fn check_url(url: &str, allow_private: bool) -> Result<(), String> {
    if url.len() > 2048 {
        return Err("the URL is too long".into());
    }
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| "enter a full URL starting with https://".to_owned())?;
    let default_port = match scheme {
        "https" => 443,
        "http" if allow_private => 80,
        _ => return Err("webhook URLs must start with https://".into()),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return Err("the URL must name a host and must not contain credentials".into());
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.ends_with(']') || authority.starts_with('[') => {
            match port.parse::<u16>() {
                Ok(port) => (host, port),
                Err(_) if authority.starts_with('[') && authority.ends_with(']') => {
                    (authority, default_port)
                }
                Err(_) => return Err("the URL has an invalid port".into()),
            }
        }
        _ => (authority, default_port),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if allow_private {
        return Ok(());
    }
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|_| format!("{host} could not be resolved"))?
        .collect();
    if addrs.is_empty() || addrs.iter().any(|a| !is_public(a.ip())) {
        return Err(format!(
            "{host} resolves to a private or local address; self-hosters can allow that with PASSBOX_WEBHOOK_ALLOW_PRIVATE=true"
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct NewWebhook {
    url: String,
    /// Deliver only entries from now on (default) or the whole log.
    #[serde(default)]
    from_start: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedWebhook {
    id: String,
    /// Shown once: verify `X-Passbox-Signature` with it.
    secret: String,
}

/// `POST /orgs/{id}/webhooks` (admins).
pub async fn create_webhook(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(org_id): Path<String>,
    Json(req): Json<NewWebhook>,
) -> ApiResult<(StatusCode, Json<CreatedWebhook>)> {
    validate::id("organization id", &org_id)?;
    let url = req.url.trim().to_owned();
    {
        let mut conn = state.db.acquire().await?;
        access::require_admin(&mut conn, &org_id, &session.account_id).await?;
    }
    let allow_private = state.webhook_allow_private;
    let check = url.clone();
    tokio::task::spawn_blocking(move || check_url(&check, allow_private))
        .await
        .map_err(|e| ApiError::Internal(e.into()))?
        .map_err(ApiError::bad_request)?;
    let mut tx = db::begin_write(&state.db).await?;
    access::require_admin(&mut tx, &org_id, &session.account_id).await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM org_webhooks WHERE org_id = $1")
        .bind(&org_id)
        .fetch_one(&mut *tx)
        .await?;
    if count >= MAX_WEBHOOKS {
        return Err(ApiError::bad_request("remove a webhook first"));
    }
    let head = org_audit::head(&mut tx, &org_id).await?;
    let webhook_id = id::new_id().map_err(|e| ApiError::Internal(e.into()))?;
    let secret = format!(
        "whsec_{}",
        encoding::encode(&random::bytes::<32>().map_err(|e| ApiError::Internal(e.into()))?)
    );
    let now = now_ms();
    sqlx::query(
        "INSERT INTO org_webhooks (id, org_id, url, secret, active, cursor_seq, failures, next_attempt_at, \
         locked_until, last_status, last_error, last_delivery_at, created_by, created_at) \
         VALUES ($1, $2, $3, $4, 1, $5, 0, 0, 0, 0, '', 0, $6, $7)",
    )
    .bind(&webhook_id)
    .bind(&org_id)
    .bind(&url)
    .bind(&secret)
    .bind(if req.from_start {
        i64::try_from(head.pruned_seq).unwrap_or_default()
    } else {
        i64::try_from(head.seq).unwrap_or_default()
    })
    .bind(&session.account_id)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    org_audit::record_in(
        &mut tx,
        &org_id,
        &Actor::of(&session, &ip),
        "webhook_created",
        Target {
            kind: "webhook",
            id: &webhook_id,
        },
        json!({ "url": url }),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(CreatedWebhook {
            id: webhook_id,
            secret,
        }),
    ))
}

/// `DELETE /orgs/{id}/webhooks/{wid}` (admins).
pub async fn delete_webhook(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path((org_id, webhook_id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    validate::id("organization id", &org_id)?;
    validate::id("webhook id", &webhook_id)?;
    let mut tx = db::begin_write(&state.db).await?;
    access::require_admin(&mut tx, &org_id, &session.account_id).await?;
    let deleted = sqlx::query("DELETE FROM org_webhooks WHERE id = $1 AND org_id = $2")
        .bind(&webhook_id)
        .bind(&org_id)
        .execute(&mut *tx)
        .await?;
    if deleted.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    org_audit::record_in(
        &mut tx,
        &org_id,
        &Actor::of(&session, &ip),
        "webhook_deleted",
        Target {
            kind: "webhook",
            id: &webhook_id,
        },
        json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Delivery -------------------------------------------------------------------------

/// `v1=<hex HMAC-SHA256(secret, "{timestamp}.{body}")>`.
pub fn signature(secret: &str, timestamp: i64, body: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC takes any key");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body.as_bytes());
    format!("v1={}", HEXLOWER.encode(&mac.finalize().into_bytes()))
}

fn backoff_ms(failures: i64) -> i64 {
    let exp = failures.clamp(0, 7) as u32;
    (30_000i64 * 2i64.pow(exp)).min(60 * 60 * 1000)
}

/// Sends one batch. Blocking (runs on the blocking pool).
fn deliver(url: &str, secret: &str, body: &str, allow_private: bool) -> Result<u16, String> {
    check_url(url, allow_private)?;
    let timestamp = now_ms() / 1000;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(15)))
        .tls_config(
            ureq::tls::TlsConfig::builder()
                .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                .build(),
        )
        .build()
        .into();
    let response = agent
        .post(url)
        .header("content-type", "application/json")
        .header("user-agent", concat!("Passbox/", env!("CARGO_PKG_VERSION")))
        .header("x-passbox-timestamp", timestamp.to_string())
        .header("x-passbox-signature", signature(secret, timestamp, body))
        .send(body)
        .map_err(|e| e.to_string())?;
    Ok(response.status().as_u16())
}

/// Delivers pending entries to every due webhook once. Returns the number
/// of successful deliveries.
pub async fn deliver_due(state: &AppState) -> ApiResult<usize> {
    let now = now_ms();
    let due: Vec<(String, String, String, String, i64, i64)> = sqlx::query_as(
        "SELECT w.id, w.org_id, w.url, w.secret, w.cursor_seq, w.failures FROM org_webhooks w \
         JOIN org_audit_heads h ON h.org_id = w.org_id \
         WHERE w.active = 1 AND w.next_attempt_at <= $1 AND w.locked_until < $2 AND h.seq > w.cursor_seq",
    )
    .bind(now)
    .bind(now)
    .fetch_all(&state.db)
    .await?;
    let mut delivered = 0;
    for (webhook_id, org_id, url, secret, cursor, failures) in due {
        // Claim it so a second server process does not deliver it too.
        let claimed = sqlx::query(
            "UPDATE org_webhooks SET locked_until = $1 WHERE id = $2 AND locked_until < $3",
        )
        .bind(now + 60_000)
        .bind(&webhook_id)
        .bind(now)
        .execute(&state.db)
        .await?;
        if claimed.rows_affected() == 0 {
            continue;
        }
        let (events, head) = {
            let mut conn = state.db.acquire().await?;
            let query = AuditQuery {
                after: Some(cursor),
                limit: Some(BATCH),
                ..AuditQuery::default()
            };
            (
                org_audit::query(&mut conn, &org_id, &query, BATCH).await?,
                org_audit::head(&mut conn, &org_id).await?,
            )
        };
        let Some(last) = events.last().map(|e| e.seq) else {
            continue;
        };
        let body = json!({
            "orgId": org_id,
            "webhookId": webhook_id,
            "events": events,
            "head": head,
        })
        .to_string();
        let allow_private = state.webhook_allow_private;
        let target = url.clone();
        let result =
            tokio::task::spawn_blocking(move || deliver(&target, &secret, &body, allow_private))
                .await
                .map_err(|e| ApiError::Internal(e.into()))?;
        let finished = now_ms();
        match result {
            Ok(status) if (200..300).contains(&status) => {
                sqlx::query(
                    "UPDATE org_webhooks SET cursor_seq = $1, failures = 0, next_attempt_at = 0, locked_until = 0, \
                     last_status = $2, last_error = '', last_delivery_at = $3 WHERE id = $4",
                )
                .bind(i64::try_from(last).unwrap_or_default())
                .bind(i64::from(status))
                .bind(finished)
                .bind(&webhook_id)
                .execute(&state.db)
                .await?;
                delivered += 1;
            }
            other => {
                let (status, error) = match other {
                    Ok(status) => (i64::from(status), format!("the receiver answered {status}")),
                    Err(error) => (0, error.chars().take(300).collect()),
                };
                sqlx::query(
                    "UPDATE org_webhooks SET failures = failures + 1, next_attempt_at = $1, locked_until = 0, \
                     last_status = $2, last_error = $3 WHERE id = $4",
                )
                .bind(finished + backoff_ms(failures))
                .bind(status)
                .bind(&error)
                .bind(&webhook_id)
                .execute(&state.db)
                .await?;
            }
        }
    }
    Ok(delivered)
}

/// Runs webhook deliveries every 15 seconds and audit retention every hour.
pub fn spawn_worker(state: AppState) {
    tokio::spawn(async move {
        let mut tick: u64 = 0;
        loop {
            if tick.is_multiple_of(240)
                && let Err(err) = org_audit::apply_retention(&state).await
            {
                tracing::warn!(error = ?err, "audit log retention failed");
            }
            if let Err(err) = deliver_due(&state).await {
                tracing::warn!(error = ?err, "webhook delivery failed");
            }
            tick = tick.wrapping_add(1);
            tokio::time::sleep(Duration::from_secs(15)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_must_be_https_and_public() {
        assert!(check_url("http://example.com/hook", false).is_err());
        assert!(check_url("ftp://example.com", false).is_err());
        assert!(check_url("https://user:pw@example.com", false).is_err());
        assert!(check_url("https://127.0.0.1/hook", false).is_err());
        assert!(check_url("https://10.1.2.3:8443/hook", false).is_err());
        assert!(check_url("https://[::1]/hook", false).is_err());
        assert!(check_url("https://169.254.169.254/latest", false).is_err());
        assert!(check_url("https://[::ffff:192.168.0.1]/x", false).is_err());
        assert!(check_url("https://93.184.215.14/hook", false).is_ok());
        assert!(check_url("http://siem.internal:8088/hook", true).is_ok());
        assert!(check_url("https://example.com:notaport/", false).is_err());
    }

    #[test]
    fn signatures_cover_timestamp_and_body() {
        let a = signature("whsec_x", 1, "{}");
        assert!(a.starts_with("v1="));
        assert_ne!(a, signature("whsec_x", 2, "{}"));
        assert_ne!(a, signature("whsec_x", 1, "{ }"));
        assert_ne!(a, signature("whsec_y", 1, "{}"));
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        assert_eq!(backoff_ms(0), 30_000);
        assert_eq!(backoff_ms(1), 60_000);
        assert_eq!(backoff_ms(100), 60 * 60 * 1000);
    }
}
