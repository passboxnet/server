//! Have I Been Pwned through the user's own server (G6, G11).
//!
//! - **Pwned Passwords proxy** (`GET /api/v1/breach/range/{prefix}`): clients
//!   send the same 5-character SHA-1 prefix they would send to
//!   `api.pwnedpasswords.com`; the server fetches the padded range and
//!   returns it. Have I Been Pwned then sees the server's IP address instead
//!   of the user's, and the server learns only hash prefixes, which match
//!   hundreds of passwords each. Cached in memory, rate limited per account.
//!   `PASSBOX_BREACH_PROXY=off` turns it off.
//! - **Email breach monitoring** (`/api/v1/breach/emails`): with the
//!   operator's own API key (`PASSBOX_HIBP_API_KEY`), users add email
//!   addresses, confirm each with a code mailed to it, and the server checks
//!   them periodically and mails new breaches. Only the address and the
//!   breach list are stored. Sending the address to Have I Been Pwned is the
//!   point of the feature; clients say so before the user opts in.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use data_encoding::HEXLOWER;
use passbox_core::{id, random};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use super::auth::Session;
use crate::db::now_ms;
use crate::error::{ApiError, ApiResult};
use crate::mail::{Locale, Template, request_locale};
use crate::state::AppState;

/// Default Pwned Passwords range endpoint (append the prefix).
pub const DEFAULT_RANGE_URL: &str = "https://api.pwnedpasswords.com/range/";
/// Default Have I Been Pwned API v3 base.
pub const DEFAULT_API_URL: &str = "https://haveibeenpwned.com/api/v3/";
const USER_AGENT: &str = concat!("Passbox-Server/", env!("CARGO_PKG_VERSION"));

/// Range requests per account and hour (a vault with this many distinct
/// password prefixes can be checked in one go).
const RANGE_LIMIT_PER_HOUR: u32 = 3000;
const RANGE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const RANGE_CACHE_ENTRIES: usize = 2048;
const MAX_EMAILS: i64 = 10;
const CODE_TTL_MS: i64 = 30 * 60 * 1000;
const CODE_RESEND_MS: i64 = 60 * 1000;
const CODE_MAX_ATTEMPTS: i64 = 5;
const MANUAL_CHECK_MS: i64 = 10 * 60 * 1000;

/// One breach from Have I Been Pwned's breach model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct HibpBreach {
    pub name: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub breach_date: String,
    #[serde(default)]
    pub added_date: String,
    #[serde(default)]
    pub pwn_count: i64,
    #[serde(default)]
    pub data_classes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamError {
    /// 429 from Have I Been Pwned; wait this long.
    RateLimited(Duration),
    /// 401/403: the API key is wrong or the subscription ended.
    Unauthorized,
    Failed(String),
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RateLimited(wait) => write!(f, "rate limited for {}s", wait.as_secs()),
            Self::Unauthorized => f.write_str("the Have I Been Pwned API key was rejected"),
            Self::Failed(message) => f.write_str(message),
        }
    }
}

/// Reaches Have I Been Pwned (blocking; runs on blocking threads). Tests
/// inject their own implementation.
pub trait BreachUpstream: Send + Sync {
    /// The padded range response for a 5-character upper-case hex prefix.
    fn range(&self, prefix: &str) -> Result<String, UpstreamError>;
    /// Breaches of an email address; empty when it is in none.
    fn breached_account(&self, email: &str) -> Result<Vec<HibpBreach>, UpstreamError>;
}

/// [`BreachUpstream`] over HTTPS.
pub struct HttpUpstream {
    agent: ureq::Agent,
    range_url: String,
    api_url: String,
    api_key: Option<String>,
}

impl HttpUpstream {
    pub fn new(range_url: &str, api_url: &str, api_key: Option<String>) -> Self {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(15)))
            .max_redirects(0)
            .user_agent(USER_AGENT)
            .build();
        Self {
            agent: config.into(),
            range_url: range_url.to_owned(),
            api_url: api_url.to_owned(),
            api_key,
        }
    }
}

fn retry_after(headers: &ureq::http::HeaderMap) -> Duration {
    headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map_or(Duration::from_secs(10), |s| {
            Duration::from_secs(s.clamp(1, 3600))
        })
}

impl BreachUpstream for HttpUpstream {
    fn range(&self, prefix: &str) -> Result<String, UpstreamError> {
        let failed = |e: ureq::Error| UpstreamError::Failed(e.to_string());
        let mut response = self
            .agent
            .get(format!("{}{prefix}", self.range_url))
            .header("Add-Padding", "true")
            .call()
            .map_err(failed)?;
        match response.status().as_u16() {
            200 => response
                .body_mut()
                .with_config()
                .limit(4 * 1024 * 1024)
                .read_to_string()
                .map_err(failed),
            429 => Err(UpstreamError::RateLimited(retry_after(response.headers()))),
            status => Err(UpstreamError::Failed(format!("status {status}"))),
        }
    }

    fn breached_account(&self, email: &str) -> Result<Vec<HibpBreach>, UpstreamError> {
        let Some(key) = &self.api_key else {
            return Err(UpstreamError::Unauthorized);
        };
        let failed = |e: ureq::Error| UpstreamError::Failed(e.to_string());
        let account: String = url::form_urlencoded::byte_serialize(email.as_bytes()).collect();
        let mut response = self
            .agent
            .get(format!(
                "{}breachedaccount/{account}?truncateResponse=false",
                self.api_url
            ))
            .header("hibp-api-key", key)
            .call()
            .map_err(failed)?;
        match response.status().as_u16() {
            200 => {
                let body = response
                    .body_mut()
                    .with_config()
                    .limit(8 * 1024 * 1024)
                    .read_to_string()
                    .map_err(failed)?;
                serde_json::from_str(&body).map_err(|e| UpstreamError::Failed(e.to_string()))
            }
            404 => Ok(Vec::new()),
            401 | 403 => Err(UpstreamError::Unauthorized),
            429 => Err(UpstreamError::RateLimited(retry_after(response.headers()))),
            status => Err(UpstreamError::Failed(format!("status {status}"))),
        }
    }
}

/// Settings, upstream and cache of the breach features.
pub struct BreachService {
    /// `PASSBOX_BREACH_PROXY`.
    pub proxy: bool,
    /// An API key is configured (`PASSBOX_HIBP_API_KEY`).
    pub monitoring: bool,
    /// How often confirmed addresses are checked.
    pub check_interval: Duration,
    /// Breached-account requests per minute (the subscription's limit).
    pub requests_per_minute: u32,
    upstream: Arc<dyn BreachUpstream>,
    ranges: Mutex<HashMap<String, (Instant, Arc<String>)>>,
}

impl BreachService {
    pub fn new(proxy: bool, monitoring: bool, upstream: Arc<dyn BreachUpstream>) -> Self {
        Self {
            proxy,
            monitoring,
            check_interval: Duration::from_secs(24 * 60 * 60),
            requests_per_minute: 10,
            upstream,
            ranges: Mutex::new(HashMap::new()),
        }
    }

    /// The default: proxy on, no monitoring, real Have I Been Pwned.
    pub fn http() -> Self {
        Self::new(
            true,
            false,
            Arc::new(HttpUpstream::new(DEFAULT_RANGE_URL, DEFAULT_API_URL, None)),
        )
    }

    async fn range(&self, prefix: &str) -> Result<Arc<String>, UpstreamError> {
        {
            let cache = self.ranges.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((at, body)) = cache.get(prefix) {
                if at.elapsed() < RANGE_TTL {
                    return Ok(body.clone());
                }
            }
        }
        let upstream = self.upstream.clone();
        let name = prefix.to_owned();
        let body = tokio::task::spawn_blocking(move || upstream.range(&name))
            .await
            .map_err(|e| UpstreamError::Failed(e.to_string()))??;
        let body = Arc::new(body);
        let mut cache = self.ranges.lock().unwrap_or_else(|e| e.into_inner());
        if cache.len() >= RANGE_CACHE_ENTRIES {
            cache.clear();
        }
        cache.insert(prefix.to_owned(), (Instant::now(), body.clone()));
        Ok(body)
    }

    async fn breached_account(&self, email: &str) -> Result<Vec<HibpBreach>, UpstreamError> {
        let upstream = self.upstream.clone();
        let email = email.to_owned();
        tokio::task::spawn_blocking(move || upstream.breached_account(&email))
            .await
            .map_err(|e| UpstreamError::Failed(e.to_string()))?
    }
}

// --- Pwned Passwords proxy ----------------------------------------------------------

/// `GET /api/v1/breach/range/{prefix}`: the padded Pwned Passwords range,
/// as plain text (`SUFFIX:COUNT` lines).
pub async fn range(
    State(state): State<AppState>,
    session: Session,
    Path(prefix): Path<String>,
) -> ApiResult<Response> {
    if !state.breach.proxy {
        return Err(ApiError::NotFound);
    }
    let prefix = prefix.to_ascii_uppercase();
    if prefix.len() != 5 || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::bad_request(
            "the prefix must be the first 5 hex characters of a SHA-1 hash",
        ));
    }
    if let Some(wait) = state.limiter.hit(
        &format!("breach-range:{}", session.account_id),
        RANGE_LIMIT_PER_HOUR,
        Duration::from_secs(60 * 60),
    ) {
        return Err(ApiError::RateLimited(wait));
    }
    match state.breach.range(&prefix).await {
        Ok(body) => {
            let mut response = (StatusCode::OK, body.as_str().to_owned()).into_response();
            let headers = response.headers_mut();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            headers.insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("private, no-store"),
            );
            Ok(response)
        }
        Err(UpstreamError::RateLimited(wait)) => Err(ApiError::RateLimited(wait)),
        Err(err) => {
            tracing::warn!(error = %err, "Pwned Passwords range request failed");
            Err(ApiError::forbidden(
                "breach_unavailable",
                "Have I Been Pwned could not be reached from the server; try again later",
            ))
        }
    }
}

// --- Email monitoring ---------------------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BreachView {
    name: String,
    title: String,
    domain: String,
    breach_date: String,
    added_date: String,
    pwn_count: i64,
    data_classes: Vec<String>,
    first_seen_at: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitoredEmail {
    id: String,
    email: String,
    verified: bool,
    /// Last check (Unix ms, 0 = never).
    checked_at: i64,
    /// Why the last check failed, if it did.
    check_error: Option<String>,
    created_at: i64,
    breaches: Vec<BreachView>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorOverview {
    /// The operator configured an API key.
    available: bool,
    check_interval_hours: u64,
    emails: Vec<MonitoredEmail>,
}

type EmailRow = (String, String, i64, i64, String, i64);
/// name, title, domain, breach date, added date, count, data classes (JSON), first seen.
type BreachRow = (String, String, String, String, String, i64, String, i64);

async fn load_email(state: &AppState, row: EmailRow) -> ApiResult<MonitoredEmail> {
    let (id, email, verified_at, checked_at, check_error, created_at) = row;
    let breaches: Vec<BreachRow> = sqlx::query_as(
        "SELECT name, title, domain, breach_date, added_date, pwn_count, data_classes, first_seen_at \
         FROM breach_monitor_results WHERE email_id = $1 ORDER BY breach_date DESC, name",
    )
    .bind(&id)
    .fetch_all(&state.db)
    .await?;
    Ok(MonitoredEmail {
        id,
        email,
        verified: verified_at > 0,
        checked_at,
        check_error: Some(check_error).filter(|e| !e.is_empty()),
        created_at,
        breaches: breaches
            .into_iter()
            .map(
                |(
                    name,
                    title,
                    domain,
                    breach_date,
                    added_date,
                    pwn_count,
                    classes,
                    first_seen_at,
                )| {
                    BreachView {
                        name,
                        title,
                        domain,
                        breach_date,
                        added_date,
                        pwn_count,
                        data_classes: serde_json::from_str(&classes).unwrap_or_default(),
                        first_seen_at,
                    }
                },
            )
            .collect(),
    })
}

async fn own_email(state: &AppState, session: &Session, id: &str) -> ApiResult<EmailRow> {
    sqlx::query_as(
        "SELECT id, email, verified_at, checked_at, check_error, created_at \
         FROM breach_monitor_emails WHERE id = $1 AND account_id = $2",
    )
    .bind(id)
    .bind(&session.account_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)
}

fn require_monitoring(state: &AppState) -> ApiResult<()> {
    if state.breach.monitoring {
        Ok(())
    } else {
        Err(ApiError::forbidden(
            "monitoring_unavailable",
            "email breach monitoring is not set up on this server (PASSBOX_HIBP_API_KEY)",
        ))
    }
}

/// `GET /api/v1/breach/emails`.
pub async fn emails(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<Json<MonitorOverview>> {
    let rows: Vec<EmailRow> = sqlx::query_as(
        "SELECT id, email, verified_at, checked_at, check_error, created_at \
         FROM breach_monitor_emails WHERE account_id = $1 ORDER BY created_at, email",
    )
    .bind(&session.account_id)
    .fetch_all(&state.db)
    .await?;
    let mut emails = Vec::with_capacity(rows.len());
    for row in rows {
        emails.push(load_email(&state, row).await?);
    }
    Ok(Json(MonitorOverview {
        available: state.breach.monitoring,
        check_interval_hours: state.breach.check_interval.as_secs() / 3600,
        emails,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddEmail {
    email: String,
    /// Language of the confirmation mail (`en`, `de`); defaults to the request's.
    #[serde(default)]
    locale: Option<String>,
}

fn hash_code(email_id: &str, code: &str) -> String {
    HEXLOWER.encode(&Sha256::digest(format!("{email_id}:{code}").as_bytes()))
}

fn valid_email(email: &str) -> bool {
    let Some((local, domain)) = email.rsplit_once('@') else {
        return false;
    };
    !local.is_empty()
        && email.len() <= 254
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !email.chars().any(|c| c.is_whitespace() || c.is_control())
}

async fn send_code(state: &AppState, email_id: &str, email: &str, locale: Locale) -> ApiResult<()> {
    let bytes = random::bytes::<8>().map_err(|e| ApiError::Internal(e.into()))?;
    let code = format!("{:06}", u64::from_be_bytes(bytes) % 1_000_000);
    let now = now_ms();
    sqlx::query(
        "UPDATE breach_monitor_emails SET code_hash = $1, code_expires_at = $2, code_attempts = 0, \
         code_sent_at = $3 WHERE id = $4",
    )
    .bind(hash_code(email_id, &code))
    .bind(now + CODE_TTL_MS)
    .bind(now)
    .bind(email_id)
    .execute(&state.db)
    .await?;
    state
        .mailer
        .enqueue(
            email,
            Template::BreachMonitorCode,
            locale,
            json!({ "email": email, "code": code, "minutes": CODE_TTL_MS / 60_000 }),
        )
        .await?;
    Ok(())
}

/// `POST /api/v1/breach/emails`: adds an address (or sends a new code for
/// an unconfirmed one) and mails a confirmation code to it.
pub async fn add_email(
    State(state): State<AppState>,
    session: Session,
    headers: HeaderMap,
    Json(body): Json<AddEmail>,
) -> ApiResult<(StatusCode, Json<MonitoredEmail>)> {
    require_monitoring(&state)?;
    let email = body.email.trim().to_lowercase();
    if !valid_email(&email) {
        return Err(ApiError::bad_request("enter a valid email address"));
    }
    if let Some(wait) = state.limiter.hit(
        &format!("breach-code:{}", session.account_id),
        10,
        Duration::from_secs(60 * 60),
    ) {
        return Err(ApiError::RateLimited(wait));
    }
    let locale = match request_locale(body.locale.as_deref(), &headers) {
        Some(locale) => locale,
        None => {
            crate::instance::load_settings(&state.db)
                .await?
                .default_locale
        }
    };
    let existing: Option<(String, i64, i64)> = sqlx::query_as(
        "SELECT id, verified_at, code_sent_at FROM breach_monitor_emails WHERE account_id = $1 AND email = $2",
    )
    .bind(&session.account_id)
    .bind(&email)
    .fetch_optional(&state.db)
    .await?;
    let id = match existing {
        Some((id, verified_at, _)) if verified_at > 0 => {
            let row = own_email(&state, &session, &id).await?;
            return Ok((StatusCode::OK, Json(load_email(&state, row).await?)));
        }
        Some((_, _, sent_at)) if now_ms() - sent_at < CODE_RESEND_MS => {
            return Err(ApiError::RateLimited(Duration::from_millis(
                (CODE_RESEND_MS - (now_ms() - sent_at)).max(1000) as u64,
            )));
        }
        Some((id, _, _)) => id,
        None => {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM breach_monitor_emails WHERE account_id = $1",
            )
            .bind(&session.account_id)
            .fetch_one(&state.db)
            .await?;
            if count >= MAX_EMAILS {
                return Err(ApiError::bad_request(format!(
                    "you can monitor up to {MAX_EMAILS} email addresses; remove one first"
                )));
            }
            let id = id::new_id().map_err(|e| ApiError::Internal(e.into()))?;
            sqlx::query(
                "INSERT INTO breach_monitor_emails (id, account_id, email, verified_at, code_hash, \
                 code_expires_at, code_attempts, code_sent_at, checked_at, check_error, created_at) \
                 VALUES ($1, $2, $3, 0, '', 0, 0, 0, 0, '', $4)",
            )
            .bind(&id)
            .bind(&session.account_id)
            .bind(&email)
            .bind(now_ms())
            .execute(&state.db)
            .await?;
            id
        }
    };
    send_code(&state, &id, &email, locale).await?;
    let row = own_email(&state, &session, &id).await?;
    Ok((StatusCode::CREATED, Json(load_email(&state, row).await?)))
}

#[derive(Deserialize)]
pub struct VerifyEmail {
    code: String,
}

/// `POST /api/v1/breach/emails/{id}/verify`: confirms the address with the
/// mailed code and runs the first check.
pub async fn verify_email(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
    Json(body): Json<VerifyEmail>,
) -> ApiResult<Json<MonitoredEmail>> {
    require_monitoring(&state)?;
    let (_, email, verified_at, _, _, _) = own_email(&state, &session, &id).await?;
    if verified_at == 0 {
        let (code_hash, expires_at, attempts): (String, i64, i64) = sqlx::query_as(
            "SELECT code_hash, code_expires_at, code_attempts FROM breach_monitor_emails WHERE id = $1",
        )
        .bind(&id)
        .fetch_one(&state.db)
        .await?;
        if code_hash.is_empty() || expires_at < now_ms() || attempts >= CODE_MAX_ATTEMPTS {
            return Err(ApiError::forbidden(
                "code_expired",
                "the code expired or was entered wrong too often; request a new one",
            ));
        }
        let code: String = body.code.chars().filter(char::is_ascii_digit).collect();
        if hash_code(&id, &code) != code_hash {
            sqlx::query(
                "UPDATE breach_monitor_emails SET code_attempts = code_attempts + 1 WHERE id = $1",
            )
            .bind(&id)
            .execute(&state.db)
            .await?;
            return Err(ApiError::InvalidTwoFactorCode);
        }
        sqlx::query(
            "UPDATE breach_monitor_emails SET verified_at = $1, code_hash = '', code_expires_at = 0 WHERE id = $2",
        )
        .bind(now_ms())
        .bind(&id)
        .execute(&state.db)
        .await?;
        // The first check: results are shown, not mailed.
        let _ = check_email(&state, &id, &email, false).await;
    }
    let row = own_email(&state, &session, &id).await?;
    Ok(Json(load_email(&state, row).await?))
}

/// `POST /api/v1/breach/emails/{id}/check`: checks a confirmed address now
/// (at most every ten minutes).
pub async fn check_now(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
) -> ApiResult<Json<MonitoredEmail>> {
    require_monitoring(&state)?;
    let (_, email, verified_at, checked_at, _, _) = own_email(&state, &session, &id).await?;
    if verified_at == 0 {
        return Err(ApiError::bad_request("confirm the address first"));
    }
    let since = now_ms() - checked_at;
    if since < MANUAL_CHECK_MS {
        return Err(ApiError::RateLimited(Duration::from_millis(
            (MANUAL_CHECK_MS - since).max(1000) as u64,
        )));
    }
    if let Err(err) = check_email(&state, &id, &email, true).await {
        tracing::warn!(error = %err, "email breach check failed");
    }
    let row = own_email(&state, &session, &id).await?;
    Ok(Json(load_email(&state, row).await?))
}

/// `DELETE /api/v1/breach/emails/{id}`: stops monitoring and deletes the
/// stored results.
pub async fn delete_email(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    own_email(&state, &session, &id).await?;
    sqlx::query("DELETE FROM breach_monitor_results WHERE email_id = $1")
        .bind(&id)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM breach_monitor_emails WHERE id = $1")
        .bind(&id)
        .execute(&state.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Checks one confirmed address, stores new breaches and, when `notify`
/// and the address had been checked before, mails them to the account.
async fn check_email(
    state: &AppState,
    email_id: &str,
    email: &str,
    notify: bool,
) -> Result<usize, UpstreamError> {
    let now = now_ms();
    let result = state.breach.breached_account(email).await;
    let breaches = match result {
        Ok(breaches) => breaches,
        Err(err) => {
            let message = match &err {
                UpstreamError::RateLimited(_) => {
                    "Have I Been Pwned is busy; the server tries again later"
                }
                UpstreamError::Unauthorized => {
                    "the server's Have I Been Pwned API key was rejected"
                }
                UpstreamError::Failed(_) => "Have I Been Pwned could not be reached",
            };
            let _ = sqlx::query("UPDATE breach_monitor_emails SET check_error = $1 WHERE id = $2")
                .bind(message)
                .bind(email_id)
                .execute(&state.db)
                .await;
            return Err(err);
        }
    };
    let store = async {
        let (account_id, previous_check): (String, i64) = sqlx::query_as(
            "SELECT account_id, checked_at FROM breach_monitor_emails WHERE id = $1",
        )
        .bind(email_id)
        .fetch_one(&state.db)
        .await?;
        let known: BTreeSet<String> =
            sqlx::query_scalar("SELECT name FROM breach_monitor_results WHERE email_id = $1")
                .bind(email_id)
                .fetch_all(&state.db)
                .await?
                .into_iter()
                .collect();
        let mut new = Vec::new();
        for breach in &breaches {
            if known.contains(&breach.name) {
                continue;
            }
            sqlx::query(
                "INSERT INTO breach_monitor_results (email_id, name, title, domain, breach_date, \
                 added_date, pwn_count, data_classes, first_seen_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (email_id, name) DO NOTHING",
            )
            .bind(email_id)
            .bind(&breach.name)
            .bind(if breach.title.is_empty() { &breach.name } else { &breach.title })
            .bind(&breach.domain)
            .bind(&breach.breach_date)
            .bind(&breach.added_date)
            .bind(breach.pwn_count)
            .bind(serde_json::to_string(&breach.data_classes).unwrap_or_else(|_| "[]".into()))
            .bind(now)
            .execute(&state.db)
            .await?;
            new.push(breach);
        }
        sqlx::query(
            "UPDATE breach_monitor_emails SET checked_at = $1, check_error = '' WHERE id = $2",
        )
        .bind(now)
        .bind(email_id)
        .execute(&state.db)
        .await?;
        if notify && previous_check > 0 && !new.is_empty() {
            let titles: Vec<&str> = new
                .iter()
                .map(|b| {
                    if b.title.is_empty() {
                        b.name.as_str()
                    } else {
                        b.title.as_str()
                    }
                })
                .collect();
            let link = state
                .mailer
                .public_url()
                .map(|url| format!("{}/#/security", url.trim_end_matches('/')))
                .unwrap_or_default();
            state
                .mailer
                .enqueue_for_account(
                    &account_id,
                    Template::BreachMonitorAlert,
                    json!({ "monitored": email, "breaches": titles.join(", "), "count": new.len(), "link": link }),
                )
                .await?;
        }
        anyhow::Ok(new.len())
    };
    store
        .await
        .map_err(|e| UpstreamError::Failed(e.to_string()))
}

/// Checks confirmed addresses whose last check is older than the interval,
/// pacing requests to the subscription's rate limit. Returns how many were
/// checked.
pub async fn check_due(state: &AppState) -> anyhow::Result<usize> {
    if !state.breach.monitoring {
        return Ok(0);
    }
    let due_before = now_ms() - state.breach.check_interval.as_millis() as i64;
    let due: Vec<(String, String)> = sqlx::query_as(
        "SELECT id, email FROM breach_monitor_emails WHERE verified_at > 0 AND checked_at < $1 \
         ORDER BY checked_at LIMIT 50",
    )
    .bind(due_before)
    .fetch_all(&state.db)
    .await?;
    let pause = Duration::from_millis(60_000 / u64::from(state.breach.requests_per_minute.max(1)));
    let mut checked = 0;
    for (id, email) in due {
        match check_email(state, &id, &email, true).await {
            Ok(_) => checked += 1,
            Err(UpstreamError::RateLimited(wait)) => {
                tokio::time::sleep(wait).await;
            }
            Err(UpstreamError::Unauthorized) => {
                tracing::error!(
                    "Have I Been Pwned rejected PASSBOX_HIBP_API_KEY; email monitoring paused"
                );
                break;
            }
            Err(err) => tracing::warn!(error = %err, "email breach check failed"),
        }
        tokio::time::sleep(pause).await;
    }
    Ok(checked)
}

/// Runs [`check_due`] every few minutes.
pub fn spawn_worker(state: AppState) {
    if !state.breach.monitoring {
        return;
    }
    tokio::spawn(async move {
        loop {
            if let Err(err) = check_due(&state).await {
                tracing::warn!(error = ?err, "email breach monitoring failed");
            }
            tokio::time::sleep(Duration::from_secs(5 * 60)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_emails() {
        assert!(valid_email("me@example.com"));
        assert!(!valid_email("me@example"));
        assert!(!valid_email("@example.com"));
        assert!(!valid_email("me @example.com"));
    }

    #[test]
    fn parses_the_breach_model() {
        let breaches: Vec<HibpBreach> = serde_json::from_str(
            r#"[{"Name":"Adobe","Title":"Adobe","Domain":"adobe.com","BreachDate":"2013-10-04",
                "AddedDate":"2013-12-04T00:00:00Z","PwnCount":152445165,"Description":"…",
                "DataClasses":["Email addresses","Passwords"],"IsVerified":true}]"#,
        )
        .unwrap();
        assert_eq!(breaches[0].name, "Adobe");
        assert_eq!(breaches[0].data_classes.len(), 2);
    }
}
