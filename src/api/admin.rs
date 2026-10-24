//! Instance administration: settings, accounts, mail, invitations and the
//! audit log of admin actions. Every endpoint needs an instance admin.
//!
//! The audit log (`admin_events`) is hash-chained: each row stores the hash
//! of the previous row and a SHA-256 hash over its own content and that
//! previous hash. Changing or deleting a row breaks the chain, and the
//! `admin_event_seq` counter reveals rows deleted from the end. The chain
//! makes tampering by someone with database access detectable, not
//! impossible: they could rewrite every following row. Export the log to
//! keep an independent copy.

use axum::Json;
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use data_encoding::HEXLOWER;
use passbox_core::{encoding, id, random};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::auth::Session;
use super::validate;
use crate::db::now_ms;
use crate::error::{ApiError, ApiResult};
use crate::instance::{self, InstanceSettings, RegistrationGrant};
use crate::mail::{Locale, MailStatus, Mailer, Template};
use crate::security::ClientIp;
use crate::state::AppState;

// --- Extractor ------------------------------------------------------------------

/// A request by an instance admin. Fails with 401 without a session and
/// with 403 `forbidden` for other accounts.
pub struct AdminSession {
    pub session: Session,
    pub email: String,
}

impl FromRequestParts<AppState> for AdminSession {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let session = Session::from_request_parts(parts, state).await?;
        let (email, flag): (String, i64) =
            sqlx::query_as("SELECT email, instance_admin FROM accounts WHERE id = $1")
                .bind(&session.account_id)
                .fetch_one(&state.db)
                .await?;
        if flag == 0 && !instance::is_env_admin(state, &email) {
            return Err(ApiError::forbidden(
                "forbidden",
                "only instance administrators can do this",
            ));
        }
        Ok(Self { session, email })
    }
}

// --- Audit log --------------------------------------------------------------------

/// Who performed an admin action.
pub struct Actor<'a> {
    pub account_id: &'a str,
    pub email: &'a str,
    pub ip: &'a str,
}

/// The hashed content of an audit log row.
struct EventFields<'a> {
    seq: i64,
    id: &'a str,
    actor: &'a Actor<'a>,
    action: &'a str,
    target: &'a str,
    details: &'a str,
    created_at: i64,
}

fn event_hash(prev_hash: &str, event: &EventFields<'_>) -> String {
    // A JSON array keeps the fields unambiguous.
    let canonical = json!([
        prev_hash,
        event.seq,
        event.id,
        event.actor.account_id,
        event.actor.email,
        event.action,
        event.target,
        event.details,
        event.actor.ip,
        event.created_at
    ])
    .to_string();
    HEXLOWER.encode(&Sha256::digest(canonical.as_bytes()))
}

/// Appends an event to the admin audit log inside `tx`.
pub async fn record_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    actor: &Actor<'_>,
    action: &str,
    target: &str,
    details: &Value,
) -> ApiResult<()> {
    // The counter row lock orders concurrent writers.
    let seq: i64 = sqlx::query_scalar(
        "UPDATE counters SET value = value + 1 WHERE name = 'admin_event_seq' RETURNING value",
    )
    .fetch_one(&mut **tx)
    .await?;
    let prev_hash: Option<String> =
        sqlx::query_scalar("SELECT hash FROM admin_events WHERE seq = $1")
            .bind(seq - 1)
            .fetch_optional(&mut **tx)
            .await?;
    let prev_hash = prev_hash.unwrap_or_default();
    let id = id::new_id().map_err(|e| ApiError::Internal(e.into()))?;
    let details = details.to_string();
    let created_at = now_ms();
    let hash = event_hash(
        &prev_hash,
        &EventFields {
            seq,
            id: &id,
            actor,
            action,
            target,
            details: &details,
            created_at,
        },
    );
    sqlx::query(
        "INSERT INTO admin_events (seq, id, actor_id, actor_email, action, target, details, ip, \
         created_at, prev_hash, hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(seq)
    .bind(&id)
    .bind(actor.account_id)
    .bind(actor.email)
    .bind(action)
    .bind(target)
    .bind(&details)
    .bind(actor.ip)
    .bind(created_at)
    .bind(&prev_hash)
    .bind(&hash)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Appends an event to the admin audit log in its own transaction.
pub async fn record(
    state: &AppState,
    actor: &Actor<'_>,
    action: &str,
    target: &str,
    details: &Value,
) -> ApiResult<()> {
    let mut tx = crate::db::begin_write(&state.db).await?;
    record_in(&mut tx, actor, action, target, details).await?;
    tx.commit().await?;
    Ok(())
}

/// Logs what made a registration possible: the first account becoming
/// instance admin, or an invitation being used.
pub async fn account_registered(
    state: &AppState,
    account_id: &str,
    email: &str,
    grant: &RegistrationGrant,
    first_admin: bool,
    ip: &str,
) -> ApiResult<()> {
    let actor = Actor {
        account_id,
        email,
        ip,
    };
    if first_admin {
        tracing::info!(account_id, "first account became instance admin");
        record(
            state,
            &actor,
            "instance_admin_bootstrap",
            account_id,
            &json!({}),
        )
        .await?;
    }
    if let Some(invite_id) = &grant.invite_id {
        record(
            state,
            &actor,
            "invite_used",
            invite_id,
            &json!({ "email": email }),
        )
        .await?;
    }
    Ok(())
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChainStatus {
    /// True if every row matches its hash and links to the previous one,
    /// and no rows are missing.
    pub valid: bool,
    /// Number of events checked.
    pub length: i64,
    /// Sequence number of the first event that does not verify (or of the
    /// first missing one).
    pub broken_at: Option<i64>,
}

type EventRow = (
    i64,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    i64,
    String,
    String,
);

macro_rules! event_columns {
    () => {
        "seq, id, actor_id, actor_email, action, target, details, ip, created_at, prev_hash, hash"
    };
}

/// Checks the whole hash chain.
pub async fn verify_chain(state: &AppState) -> ApiResult<ChainStatus> {
    let rows: Vec<EventRow> = sqlx::query_as(concat!(
        "SELECT ",
        event_columns!(),
        " FROM admin_events ORDER BY seq"
    ))
    .fetch_all(&state.db)
    .await?;
    let counter: i64 =
        sqlx::query_scalar("SELECT value FROM counters WHERE name = 'admin_event_seq'")
            .fetch_one(&state.db)
            .await?;
    let mut prev_hash = String::new();
    let mut expected_seq = 1;
    let length = i64::try_from(rows.len()).unwrap_or(i64::MAX);
    for (seq, id, actor_id, actor_email, action, target, details, ip, created_at, prev, hash) in
        rows
    {
        let actor = Actor {
            account_id: &actor_id,
            email: &actor_email,
            ip: &ip,
        };
        let computed = event_hash(
            &prev,
            &EventFields {
                seq,
                id: &id,
                actor: &actor,
                action: &action,
                target: &target,
                details: &details,
                created_at,
            },
        );
        if seq != expected_seq || prev != prev_hash || computed != hash {
            return Ok(ChainStatus {
                valid: false,
                length,
                broken_at: Some(expected_seq.min(seq)),
            });
        }
        prev_hash = hash;
        expected_seq += 1;
    }
    if counter != expected_seq - 1 {
        return Ok(ChainStatus {
            valid: false,
            length,
            broken_at: Some(expected_seq),
        });
    }
    Ok(ChainStatus {
        valid: true,
        length,
        broken_at: None,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminEvent {
    seq: i64,
    id: String,
    actor_id: String,
    actor_email: String,
    action: String,
    target: String,
    details: Value,
    ip: String,
    created_at: i64,
    prev_hash: String,
    hash: String,
}

#[derive(Deserialize)]
pub struct EventsQuery {
    #[serde(default)]
    limit: Option<i64>,
    /// Only events with a lower sequence number (for paging).
    #[serde(default)]
    before: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventsResponse {
    /// Newest first.
    events: Vec<AdminEvent>,
    chain: ChainStatus,
}

pub async fn events(
    State(state): State<AppState>,
    _admin: AdminSession,
    Query(query): Query<EventsQuery>,
) -> ApiResult<Json<EventsResponse>> {
    let limit = query.limit.unwrap_or(50).clamp(1, 500);
    let before = query.before.unwrap_or(i64::MAX);
    let rows: Vec<EventRow> = sqlx::query_as(concat!(
        "SELECT ",
        event_columns!(),
        " FROM admin_events WHERE seq < $1 ORDER BY seq DESC LIMIT $2"
    ))
    .bind(before)
    .bind(limit)
    .fetch_all(&state.db)
    .await?;
    let events = rows
        .into_iter()
        .map(
            |(
                seq,
                id,
                actor_id,
                actor_email,
                action,
                target,
                details,
                ip,
                created_at,
                prev_hash,
                hash,
            )| {
                AdminEvent {
                    seq,
                    id,
                    actor_id,
                    actor_email,
                    action,
                    target,
                    details: serde_json::from_str(&details).unwrap_or(Value::Null),
                    ip,
                    created_at,
                    prev_hash,
                    hash,
                }
            },
        )
        .collect();
    Ok(Json(EventsResponse {
        events,
        chain: verify_chain(&state).await?,
    }))
}

// --- Settings ---------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsResponse {
    settings: InstanceSettings,
    mail: MailStatus,
    /// Accounts that are admins through `PASSBOX_ADMIN_EMAILS`.
    env_admin_emails: Vec<String>,
}

async fn settings_response(state: &AppState) -> ApiResult<SettingsResponse> {
    Ok(SettingsResponse {
        settings: instance::load_settings(&state.db).await?,
        mail: state.mailer.status().await?,
        env_admin_emails: state.admin_emails.to_vec(),
    })
}

pub async fn get_settings(
    State(state): State<AppState>,
    _admin: AdminSession,
) -> ApiResult<Json<SettingsResponse>> {
    Ok(Json(settings_response(&state).await?))
}

pub async fn put_settings(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    admin: AdminSession,
    Json(settings): Json<InstanceSettings>,
) -> ApiResult<Json<SettingsResponse>> {
    let settings = settings.validated()?;
    let old = instance::load_settings(&state.db).await?;
    let old_json = serde_json::to_value(&old).map_err(|e| ApiError::Internal(e.into()))?;
    let new_json = serde_json::to_value(&settings).map_err(|e| ApiError::Internal(e.into()))?;
    // Record which settings changed, with their new values.
    let mut changes = serde_json::Map::new();
    if let (Some(old), Some(new)) = (old_json.as_object(), new_json.as_object()) {
        for (key, value) in new {
            if old.get(key) != Some(value) {
                changes.insert(key.clone(), value.clone());
            }
        }
    }
    if !changes.is_empty() {
        let mut tx = crate::db::begin_write(&state.db).await?;
        instance::save_settings(&mut tx, &settings).await?;
        record_in(
            &mut tx,
            &Actor {
                account_id: &admin.session.account_id,
                email: &admin.email,
                ip: &ip,
            },
            "settings_updated",
            "instance",
            &Value::Object(changes),
        )
        .await?;
        tx.commit().await?;
    }
    Ok(Json(settings_response(&state).await?))
}

// --- Accounts ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct UsersQuery {
    /// Part of the email to search for.
    #[serde(default)]
    q: String,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUser {
    id: String,
    email: String,
    created_at: i64,
    /// Last sign-in or request, whichever is later (`null` if never).
    last_activity_at: Option<i64>,
    /// `active` or `disabled`.
    status: &'static str,
    disabled_at: Option<i64>,
    instance_admin: bool,
    active_sessions: i64,
    /// Whether two-step sign-in is on; `null` while the server has no
    /// login 2FA.
    two_factor_enabled: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsersResponse {
    users: Vec<AdminUser>,
    total: i64,
}

/// Escapes `%`, `_` and `\` for `LIKE ... ESCAPE '\'`.
fn like_pattern(query: &str) -> String {
    let mut pattern = String::from("%");
    for c in query.trim().to_lowercase().chars() {
        if matches!(c, '%' | '_' | '\\') {
            pattern.push('\\');
        }
        pattern.push(c);
    }
    pattern.push('%');
    pattern
}

type UserRow = (String, String, i64, i64, i64, i64, Option<i64>, Option<i64>);

pub async fn users(
    State(state): State<AppState>,
    _admin: AdminSession,
    Query(query): Query<UsersQuery>,
) -> ApiResult<Json<UsersResponse>> {
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0).max(0);
    let pattern = like_pattern(&query.q);
    let now = now_ms();
    let rows: Vec<UserRow> = sqlx::query_as(
        "SELECT a.id, a.email, a.created_at, a.disabled_at, a.instance_admin, \
         (SELECT COUNT(*) FROM sessions s WHERE s.account_id = a.id AND s.expires_at > $1), \
         (SELECT MAX(s.last_used_at) FROM sessions s WHERE s.account_id = a.id), \
         (SELECT MAX(e.created_at) FROM account_events e WHERE e.account_id = a.id AND e.kind = 'login') \
         FROM accounts a WHERE a.email LIKE $2 ESCAPE '\\' \
         ORDER BY a.created_at DESC, a.id LIMIT $3 OFFSET $4",
    )
    .bind(now)
    .bind(&pattern)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;
    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM accounts WHERE email LIKE $1 ESCAPE '\\'")
            .bind(&pattern)
            .fetch_one(&state.db)
            .await?;
    let users = rows
        .into_iter()
        .map(
            |(id, email, created_at, disabled_at, flag, active_sessions, last_used, last_login)| {
                let instance_admin = flag != 0 || instance::is_env_admin(&state, &email);
                AdminUser {
                    id,
                    email,
                    created_at,
                    last_activity_at: last_used.max(last_login).filter(|t| *t > 0),
                    status: if disabled_at == 0 {
                        "active"
                    } else {
                        "disabled"
                    },
                    disabled_at: (disabled_at != 0).then_some(disabled_at),
                    instance_admin,
                    active_sessions,
                    two_factor_enabled: None,
                }
            },
        )
        .collect();
    Ok(Json(UsersResponse { users, total }))
}

/// Disables an account: it cannot sign in anymore and all its sessions end
/// immediately. Its data stays.
pub async fn disable_user(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    admin: AdminSession,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    validate::id("id", &id)?;
    if id == admin.session.account_id {
        return Err(ApiError::bad_request("you cannot disable your own account"));
    }
    let email = account_email(&state, &id).await?;
    let mut tx = crate::db::begin_write(&state.db).await?;
    let changed =
        sqlx::query("UPDATE accounts SET disabled_at = $1 WHERE id = $2 AND disabled_at = 0")
            .bind(now_ms())
            .bind(&id)
            .execute(&mut *tx)
            .await?;
    let revoked = sqlx::query("DELETE FROM sessions WHERE account_id = $1")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    if changed.rows_affected() > 0 {
        record_in(
            &mut tx,
            &Actor {
                account_id: &admin.session.account_id,
                email: &admin.email,
                ip: &ip,
            },
            "user_disabled",
            &id,
            &json!({ "email": email, "sessionsRevoked": revoked.rows_affected() }),
        )
        .await?;
    }
    tx.commit().await?;
    tracing::info!(account_id = %id, "account disabled");
    Ok(StatusCode::NO_CONTENT)
}

pub async fn enable_user(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    admin: AdminSession,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    validate::id("id", &id)?;
    let email = account_email(&state, &id).await?;
    let mut tx = crate::db::begin_write(&state.db).await?;
    let changed =
        sqlx::query("UPDATE accounts SET disabled_at = 0 WHERE id = $1 AND disabled_at <> 0")
            .bind(&id)
            .execute(&mut *tx)
            .await?;
    if changed.rows_affected() > 0 {
        record_in(
            &mut tx,
            &Actor {
                account_id: &admin.session.account_id,
                email: &admin.email,
                ip: &ip,
            },
            "user_enabled",
            &id,
            &json!({ "email": email }),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn account_email(state: &AppState, id: &str) -> ApiResult<String> {
    sqlx::query_scalar("SELECT email FROM accounts WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(ApiError::NotFound)
}

// --- Mail -------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestMailRequest {
    /// Recipient; defaults to the admin's own email.
    #[serde(default)]
    to: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestMailResponse {
    id: String,
    to: String,
    /// False when no SMTP server is configured: the mail is only logged.
    mail_configured: bool,
}

pub async fn test_mail(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    admin: AdminSession,
    Json(request): Json<TestMailRequest>,
) -> ApiResult<Json<TestMailResponse>> {
    let to = match request
        .to
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        Some(to) => validate::email(to)?,
        None => admin.email.clone(),
    };
    let locale = admin_locale(&state, &admin).await?;
    let id = state
        .mailer
        .enqueue(
            &to,
            Template::Test,
            locale,
            json!({ "requestedBy": admin.email }),
        )
        .await?;
    record(
        &state,
        &Actor {
            account_id: &admin.session.account_id,
            email: &admin.email,
            ip: &ip,
        },
        "test_mail_sent",
        &id,
        &json!({ "to": to }),
    )
    .await?;
    Ok(Json(TestMailResponse {
        id,
        to,
        mail_configured: state.mailer.is_configured(),
    }))
}

async fn admin_locale(state: &AppState, admin: &AdminSession) -> ApiResult<Locale> {
    let locale: String = sqlx::query_scalar("SELECT locale FROM accounts WHERE id = $1")
        .bind(&admin.session.account_id)
        .fetch_one(&state.db)
        .await?;
    Ok(match Locale::parse(&locale) {
        Some(locale) => locale,
        None => instance::load_settings(&state.db).await?.default_locale,
    })
}

// --- Invitations ------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteRequest {
    email: String,
    /// Language of the invitation mail; defaults to the instance default.
    #[serde(default)]
    locale: Option<String>,
    /// Origin of the web app to link to when `PASSBOX_PUBLIC_URL` is not
    /// set, for example `https://vault.example.com`.
    #[serde(default)]
    link_base: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Invite {
    id: String,
    email: String,
    invited_by: String,
    created_at: i64,
    expires_at: i64,
    used_at: Option<i64>,
    /// `pending`, `used` or `expired`.
    status: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteCreated {
    #[serde(flatten)]
    invite: Invite,
    /// The invitation link (also sent by mail), or `null` if neither
    /// `PASSBOX_PUBLIC_URL` nor `linkBase` is known.
    link: Option<String>,
    mail_configured: bool,
}

/// Percent-encodes a query parameter value.
fn encode_query(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The link that opens the web app's sign-up with an invitation.
pub fn invite_link(
    mailer: &Mailer,
    link_base: Option<&str>,
    token: &str,
    email: &str,
) -> Option<String> {
    let base = mailer.public_url().map(str::to_owned).or_else(|| {
        link_base
            .map(|b| b.trim().trim_end_matches('/'))
            .filter(|b| {
                (b.starts_with("https://") || b.starts_with("http://"))
                    && b.len() <= 300
                    && !b
                        .chars()
                        .any(|c| c.is_whitespace() || c.is_control() || c == '#' || c == '?')
            })
            .map(str::to_owned)
    })?;
    Some(format!(
        "{base}/#/?invite={}&email={}",
        encode_query(token),
        encode_query(email)
    ))
}

pub async fn create_invite(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    admin: AdminSession,
    Json(req): Json<InviteRequest>,
) -> ApiResult<(StatusCode, Json<InviteCreated>)> {
    let email = validate::email(&req.email)?;
    let exists: Option<i64> = sqlx::query_scalar("SELECT 1 FROM accounts WHERE email = $1")
        .bind(&email)
        .fetch_optional(&state.db)
        .await?;
    if exists.is_some() {
        return Err(ApiError::conflict(
            "an account with this email already exists",
            Value::Null,
        ));
    }
    let locale = match req.locale.as_deref().and_then(Locale::parse) {
        Some(locale) => locale,
        None => instance::load_settings(&state.db).await?.default_locale,
    };
    let token = encoding::encode(&random::bytes::<32>().map_err(|e| ApiError::Internal(e.into()))?);
    let id = id::new_id().map_err(|e| ApiError::Internal(e.into()))?;
    let now = now_ms();
    let expires_at = now + instance::INVITE_TTL_MS;
    let link = invite_link(&state.mailer, req.link_base.as_deref(), &token, &email);

    let mut tx = crate::db::begin_write(&state.db).await?;
    // A new invitation replaces earlier unused ones for the same email.
    sqlx::query("DELETE FROM instance_invites WHERE email = $1 AND used_at = 0")
        .bind(&email)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO instance_invites (id, email, token_hash, invited_by, created_at, expires_at, used_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 0)",
    )
    .bind(&id)
    .bind(&email)
    .bind(instance::hash_invite_token(&token))
    .bind(&admin.email)
    .bind(now)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;
    Mailer::enqueue_in(
        &mut tx,
        &email,
        Template::Invitation,
        locale,
        &json!({
            "inviter": admin.email,
            "link": link.clone().unwrap_or_default(),
            "expiresAt": expires_at,
        }),
    )
    .await?;
    record_in(
        &mut tx,
        &Actor {
            account_id: &admin.session.account_id,
            email: &admin.email,
            ip: &ip,
        },
        "invite_created",
        &id,
        &json!({ "email": email }),
    )
    .await?;
    tx.commit().await?;
    state.mailer.wake();

    Ok((
        StatusCode::CREATED,
        Json(InviteCreated {
            invite: Invite {
                id,
                email,
                invited_by: admin.email,
                created_at: now,
                expires_at,
                used_at: None,
                status: "pending",
            },
            link,
            mail_configured: state.mailer.is_configured(),
        }),
    ))
}

pub async fn invites(
    State(state): State<AppState>,
    _admin: AdminSession,
) -> ApiResult<Json<Vec<Invite>>> {
    let rows: Vec<(String, String, String, i64, i64, i64)> = sqlx::query_as(
        "SELECT id, email, invited_by, created_at, expires_at, used_at FROM instance_invites \
         ORDER BY created_at DESC LIMIT 200",
    )
    .fetch_all(&state.db)
    .await?;
    let now = now_ms();
    Ok(Json(
        rows.into_iter()
            .map(
                |(id, email, invited_by, created_at, expires_at, used_at)| Invite {
                    id,
                    email,
                    invited_by,
                    created_at,
                    expires_at,
                    used_at: (used_at != 0).then_some(used_at),
                    status: if used_at != 0 {
                        "used"
                    } else if expires_at <= now {
                        "expired"
                    } else {
                        "pending"
                    },
                },
            )
            .collect(),
    ))
}

pub async fn revoke_invite(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    admin: AdminSession,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    validate::id("id", &id)?;
    let mut tx = crate::db::begin_write(&state.db).await?;
    let deleted = sqlx::query("DELETE FROM instance_invites WHERE id = $1 AND used_at = 0")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    if deleted.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    record_in(
        &mut tx,
        &Actor {
            account_id: &admin.session.account_id,
            email: &admin.email,
            ip: &ip,
        },
        "invite_revoked",
        &id,
        &json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn like_patterns_escape_wildcards() {
        assert_eq!(like_pattern(" Ada "), "%ada%");
        assert_eq!(like_pattern("a_b%c\\"), "%a\\_b\\%c\\\\%");
    }

    #[test]
    fn query_values_are_encoded() {
        assert_eq!(encode_query("ada+x@example.com"), "ada%2Bx%40example.com");
    }

    #[test]
    fn event_hash_covers_every_field() {
        let actor = Actor {
            account_id: "a",
            email: "admin@example.com",
            ip: "127.0.0.1",
        };
        let fields = |seq, action, created_at| EventFields {
            seq,
            id: "id",
            actor: &actor,
            action,
            target: "instance",
            details: "{}",
            created_at,
        };
        let base = event_hash("", &fields(1, "settings_updated", 1));
        assert_ne!(base, event_hash("x", &fields(1, "settings_updated", 1)));
        assert_ne!(base, event_hash("", &fields(2, "settings_updated", 1)));
        assert_ne!(base, event_hash("", &fields(1, "user_disabled", 1)));
        assert_ne!(base, event_hash("", &fields(1, "settings_updated", 2)));
        assert_eq!(base.len(), 64);
    }
}
