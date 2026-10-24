//! The SSO sign-in flow (authorization code + PKCE).
//!
//! ```text
//! client                         server                              identity provider
//!   │ POST /sso/start {orgId}      │                                         │
//!   │ ◀── authorizationUrl,        │ stores state hash, nonce, PKCE verifier, │
//!   │     flowSecret               │ SHA-256(flowSecret)                      │
//!   │ ── browser redirect ───────────────────────────────────────────────▶   │
//!   │                              │ ◀── GET /sso/callback?code&state ─────  │
//!   │                              │ ── POST token (code, verifier, secret) ▶ │
//!   │                              │ ◀── ID token; verify signature + claims │
//!   │ ◀── 303 {publicUrl}/#/sso?ticket=… (or ?error=code)                     │
//!   │ POST /sso/redeem {ticket, flowSecret}                                   │
//!   │ ◀── proof (10 min, single use) → login/finish {ssoProof} or /sso/unlock │
//! ```
//!
//! The flow secret binds the ticket to the browser tab that started the
//! flow: a ticket that ends up elsewhere (a forwarded link, a login CSRF
//! attempt) cannot be redeemed. The redirect target is always the server's
//! public URL, never a client-supplied address.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use data_encoding::HEXLOWER;
use passbox_core::oidc::{self as core_oidc, Expectations, Jwks};
use passbox_core::{encoding, id, random};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use sqlx::AnyConnection;

use super::oidc::{self, TokenError, TokenRequest, query_encode};
use super::{
    JWKS_MAX_AGE_MS, StoredConfig, load_config, normalize_domain, redirect_uri, sso_error,
};
use crate::api::access;
use crate::api::auth::{self, Session, record_event};
use crate::api::validate;
use crate::db::{self, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::security::ClientIp;
use crate::state::AppState;

const FLOW_TTL_MS: i64 = 10 * 60 * 1000;
const TICKET_TTL_MS: i64 = 5 * 60 * 1000;
pub(crate) const PROOF_TTL_MS: i64 = 10 * 60 * 1000;
/// Flows started per IP and minute.
const STARTS_PER_MINUTE: u32 = 30;

pub(crate) fn hash(value: &str) -> String {
    HEXLOWER.encode(&Sha256::digest(value.as_bytes()))
}

fn token() -> ApiResult<String> {
    Ok(encoding::encode(
        &random::bytes::<32>().map_err(|e| ApiError::Internal(e.into()))?,
    ))
}

fn limit(state: &AppState, key: String, max: u32, secs: u64) -> ApiResult<()> {
    match state
        .limiter
        .hit(&key, max, std::time::Duration::from_secs(secs))
    {
        Some(wait) => Err(ApiError::RateLimited(wait)),
        None => Ok(()),
    }
}

// --- Discovery by email --------------------------------------------------------------

#[derive(Deserialize)]
pub struct DiscoverRequest {
    email: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SsoOption {
    org_id: String,
    display_name: String,
    provider: String,
    /// Members must sign in with SSO.
    required: bool,
    /// Trusted devices may unlock with SSO instead of the master password.
    device_unlock: bool,
}

#[derive(Serialize)]
pub struct DiscoverResponse {
    sso: Option<SsoOption>,
}

/// `POST /sso/discover`: which organization's identity provider signs in
/// people with this email's domain. Answers per domain only, so it does
/// not reveal whether an account exists.
pub async fn discover(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<DiscoverRequest>,
) -> ApiResult<Json<DiscoverResponse>> {
    auth::limit_ip(&state, &ip)?;
    let email = validate::email(&req.email)?;
    let domain = email.rsplit_once('@').map(|(_, d)| d).unwrap_or_default();
    let row: Option<(String, String, String, i64, i64)> = sqlx::query_as(
        "SELECT org_sso.org_id, org_sso.display_name, org_sso.provider, org_sso.required, \
         org_sso.allow_device_unlock FROM sso_domains JOIN org_sso ON org_sso.org_id = sso_domains.org_id \
         WHERE sso_domains.domain = $1 AND org_sso.enabled = 1",
    )
    .bind(domain)
    .fetch_optional(&state.db)
    .await?;
    Ok(Json(DiscoverResponse {
        sso: row.map(
            |(org_id, display_name, provider, required, device_unlock)| SsoOption {
                org_id,
                display_name,
                provider,
                required: required != 0,
                device_unlock: device_unlock != 0,
            },
        ),
    }))
}

// --- Starting a flow ---------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartRequest {
    org_id: String,
    /// Passed to the provider as `login_hint`.
    #[serde(default)]
    email: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartResponse {
    /// Send the browser here.
    authorization_url: String,
    /// Keep it in the tab (`sessionStorage`) and send it with the ticket.
    flow_secret: String,
    expires_at: i64,
}

async fn discovery_of(config: &StoredConfig) -> ApiResult<oidc::Discovery> {
    match &config.discovery {
        Some(discovery) => Ok(discovery.clone()),
        None => oidc::discover(&config.settings.issuer)
            .await
            .map_err(|e| sso_error(e.code(), e.message())),
    }
}

async fn begin(
    state: &AppState,
    config: &StoredConfig,
    purpose: &str,
    initiated_by: &str,
    login_hint: Option<&str>,
) -> ApiResult<StartResponse> {
    let redirect = redirect_uri(state).ok_or_else(|| {
        sso_error(
            "sso_public_url_missing",
            "single sign-on needs PASSBOX_PUBLIC_URL on the server",
        )
    })?;
    let discovery = discovery_of(config).await?;
    let state_value = token()?;
    let nonce = token()?;
    let verifier = core_oidc::random_token().map_err(|e| ApiError::Internal(e.into()))?;
    let flow_secret = token()?;
    let now = now_ms();
    let expires_at = now + FLOW_TTL_MS;
    let return_to = state
        .mailer
        .public_url()
        .map(|u| format!("{}/", u.trim_end_matches('/')))
        .unwrap_or_default();
    sqlx::query("DELETE FROM sso_flows WHERE expires_at < $1")
        .bind(now)
        .execute(&state.db)
        .await?;
    sqlx::query(
        "INSERT INTO sso_flows (state_hash, org_id, purpose, nonce, code_verifier, binding_hash, return_to, \
         initiated_by, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(hash(&state_value))
    .bind(&config.org_id)
    .bind(purpose)
    .bind(&nonce)
    .bind(&verifier)
    .bind(hash(&flow_secret))
    .bind(&return_to)
    .bind(initiated_by)
    .bind(now)
    .bind(expires_at)
    .execute(&state.db)
    .await?;
    let separator = if discovery.authorization_endpoint.contains('?') {
        '&'
    } else {
        '?'
    };
    let mut url = format!(
        "{}{separator}response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}\
         &code_challenge={}&code_challenge_method=S256",
        discovery.authorization_endpoint,
        query_encode(&config.settings.client_id),
        query_encode(&redirect),
        query_encode(&config.settings.scopes),
        query_encode(&state_value),
        query_encode(&nonce),
        query_encode(&core_oidc::pkce_challenge(&verifier)),
    );
    if let Some(hint) = login_hint {
        url.push_str(&format!("&login_hint={}", query_encode(hint)));
    }
    if purpose == "test" {
        // Show the provider's sign-in even when a session exists there.
        url.push_str("&prompt=login");
    }
    Ok(StartResponse {
        authorization_url: url,
        flow_secret,
        expires_at,
    })
}

/// `POST /sso/start`: starts a sign-in at the organization's provider.
pub async fn start(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<StartRequest>,
) -> ApiResult<Json<StartResponse>> {
    limit(&state, format!("sso-start:{ip}"), STARTS_PER_MINUTE, 60)?;
    validate::id("orgId", &req.org_id)?;
    let hint = match &req.email {
        Some(email) if !email.trim().is_empty() => Some(validate::email(email)?),
        _ => None,
    };
    let mut conn = state.db.acquire().await?;
    let config = load_config(&mut conn, &req.org_id)
        .await?
        .filter(|c| c.settings.enabled)
        .ok_or_else(|| {
            sso_error(
                "sso_not_configured",
                "this organization does not use single sign-on",
            )
        })?;
    drop(conn);
    Ok(Json(
        begin(&state, &config, "login", "", hint.as_deref()).await?,
    ))
}

/// `POST /orgs/{org_id}/sso/test/start` (owners and admins): signs in at the
/// provider without signing in to Passbox and shows what it sent.
pub async fn test_start(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(org_id): Path<String>,
) -> ApiResult<Json<StartResponse>> {
    limit(&state, format!("sso-start:{ip}"), STARTS_PER_MINUTE, 60)?;
    validate::id("organization id", &org_id)?;
    let mut conn = state.db.acquire().await?;
    access::require_admin(&mut conn, &org_id, &session.account_id).await?;
    let config = load_config(&mut conn, &org_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    drop(conn);
    Ok(Json(
        begin(&state, &config, "test", &session.account_id, None).await?,
    ))
}

// --- Callback ------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CallbackQuery {
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

fn redirect(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, location.to_owned()),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
    )
        .into_response()
}

fn error_page(state: &AppState, code: &str) -> Response {
    match state.mailer.public_url() {
        Some(base) => redirect(&format!(
            "{}/#/sso?error={code}",
            base.trim_end_matches('/')
        )),
        None => (
            StatusCode::BAD_REQUEST,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "This single sign-on link is invalid or has expired. Start the sign-in again in Passbox.",
        )
            .into_response(),
    }
}

/// What the callback established about the person.
struct Identity {
    subject: String,
    email: Option<String>,
    email_verified: bool,
    name: String,
    groups: Vec<String>,
    claims: Map<String, Value>,
}

async fn verify_token(
    state: &AppState,
    config: &StoredConfig,
    id_token: &str,
    nonce: &str,
) -> Result<Map<String, Value>, &'static str> {
    let discovery = config.discovery.as_ref().ok_or("sso_not_configured")?;
    let header = core_oidc::token_header(id_token).map_err(|_| "sso_invalid_token")?;
    let mut jwks = Jwks::parse(&config.jwks).unwrap_or_default();
    let now = now_ms();
    let unknown_kid = header.kid.as_deref().is_some_and(|kid| !jwks.has_kid(kid));
    if (unknown_kid || now - config.jwks_fetched_at > JWKS_MAX_AGE_MS || jwks.keys.is_empty())
        && state
            .limiter
            .hit(
                &format!("sso-jwks:{}", config.org_id),
                6,
                std::time::Duration::from_secs(60),
            )
            .is_none()
        && let Ok((raw, fresh)) = oidc::fetch_jwks(&discovery.jwks_uri).await
    {
        jwks = fresh;
        let _ = sqlx::query("UPDATE org_sso SET jwks = $1, jwks_fetched_at = $2 WHERE org_id = $3")
            .bind(raw)
            .bind(now)
            .bind(&config.org_id)
            .execute(&state.db)
            .await;
    }
    core_oidc::verify_id_token(
        id_token,
        &jwks,
        &Expectations {
            issuer: &discovery.issuer,
            client_id: &config.settings.client_id,
            nonce,
            now: now / 1000,
        },
    )
    .map_err(|error| {
        tracing::info!(org_id = %config.org_id, %error, "ID token rejected");
        "sso_invalid_token"
    })
}

fn identity(config: &StoredConfig, claims: Map<String, Value>) -> Identity {
    let s = &config.settings;
    let email = core_oidc::claim(&claims, &s.email_claim)
        .and_then(Value::as_str)
        .map(|e| e.trim().to_lowercase())
        .filter(|e| validate::email(e).is_ok());
    // Some providers (Microsoft Entra ID) do not send `email_verified`; the
    // setting decides whether to require it.
    let email_verified =
        !s.require_verified_email || core_oidc::claim_bool(&claims, "email_verified");
    let name = core_oidc::claim(&claims, &s.name_claim)
        .and_then(Value::as_str)
        .map(|n| n.chars().take(120).collect())
        .unwrap_or_default();
    Identity {
        subject: claims
            .get("sub")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        email,
        email_verified,
        name,
        groups: core_oidc::claim_strings(&claims, &s.groups_claim)
            .into_iter()
            .take(100)
            .collect(),
        claims,
    }
}

/// The Passbox account the identity signs in, if any.
enum Resolved {
    Account { account_id: String, email: String },
    NoAccount { email: String },
}

/// Maps the provider's identity to an account of the organization:
/// first by the linked subject, otherwise (first sign-in) by a verified
/// email of an allowed domain. With `commit`, links the subject and
/// accepts a pending invitation of the organization (directory-provisioned
/// people); without, only reports (the "test connection" check).
async fn resolve(
    conn: &mut AnyConnection,
    config: &StoredConfig,
    who: &Identity,
    commit: bool,
) -> ApiResult<Result<Resolved, &'static str>> {
    let org_id = &config.org_id;
    let linked: Option<(String, String)> = sqlx::query_as(
        "SELECT sso_identities.account_id, accounts.email FROM sso_identities \
         JOIN accounts ON accounts.id = sso_identities.account_id \
         WHERE sso_identities.org_id = $1 AND sso_identities.subject = $2 AND sso_identities.issuer = $3",
    )
    .bind(org_id)
    .bind(&who.subject)
    .bind(&config.settings.issuer)
    .fetch_optional(&mut *conn)
    .await?;
    let (account_id, email, new_link) = match linked {
        Some((account_id, email)) => (account_id, email, false),
        None => {
            let Some(email) = who.email.clone() else {
                return Ok(Err("sso_no_email"));
            };
            if !who.email_verified {
                return Ok(Err("sso_email_unverified"));
            }
            let domain = email.rsplit_once('@').map(|(_, d)| d).unwrap_or_default();
            if !normalize_domain(domain)
                .is_some_and(|d| config.settings.allowed_domains.contains(&d))
            {
                return Ok(Err("sso_domain_not_allowed"));
            }
            let account: Option<String> =
                sqlx::query_scalar("SELECT id FROM accounts WHERE email = $1")
                    .bind(&email)
                    .fetch_optional(&mut *conn)
                    .await?;
            match account {
                Some(account_id) => (account_id, email, true),
                None => return Ok(Ok(Resolved::NoAccount { email })),
            }
        }
    };
    let disabled: i64 = sqlx::query_scalar("SELECT disabled_at FROM accounts WHERE id = $1")
        .bind(&account_id)
        .fetch_one(&mut *conn)
        .await?;
    if disabled != 0 {
        return Ok(Err("account_disabled"));
    }
    match access::membership(conn, org_id, &account_id).await? {
        Some(m) if m.status == "suspended" => return Ok(Err("sso_suspended")),
        Some(_) => {}
        None => {
            // Invited (for example provisioned by the directory): signing in
            // through the organization's provider accepts the invitation.
            let invitation: Option<(String, String, String)> = sqlx::query_as(
                "SELECT id, role, created_by FROM org_invitations WHERE org_id = $1 AND email = $2 \
                 AND status = 'pending' AND expires_at > $3 ORDER BY created_at DESC LIMIT 1",
            )
            .bind(org_id)
            .bind(&email)
            .bind(now_ms())
            .fetch_optional(&mut *conn)
            .await?;
            let has_keys = crate::api::signed::bundle(conn, &account_id)
                .await?
                .is_some();
            let Some((invitation_id, role, created_by)) = invitation.filter(|_| has_keys) else {
                return Ok(Err("sso_not_member"));
            };
            if commit {
                accept_invitation(
                    conn,
                    org_id,
                    &account_id,
                    &invitation_id,
                    &role,
                    &created_by,
                )
                .await?;
            }
        }
    }
    if commit {
        let now = now_ms();
        if new_link {
            sqlx::query(
                "INSERT INTO sso_identities (org_id, subject, issuer, account_id, email, created_at, last_login_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
            )
            .bind(org_id)
            .bind(&who.subject)
            .bind(&config.settings.issuer)
            .bind(&account_id)
            .bind(&email)
            .bind(now)
            .bind(now)
            .execute(&mut *conn)
            .await?;
        } else {
            sqlx::query(
                "UPDATE sso_identities SET last_login_at = $1 WHERE org_id = $2 AND subject = $3",
            )
            .bind(now)
            .bind(org_id)
            .bind(&who.subject)
            .execute(&mut *conn)
            .await?;
        }
    }
    Ok(Ok(Resolved::Account { account_id, email }))
}

async fn accept_invitation(
    conn: &mut AnyConnection,
    org_id: &str,
    account_id: &str,
    invitation_id: &str,
    role: &str,
    created_by: &str,
) -> ApiResult<()> {
    let now = now_ms();
    let seq: i64 = sqlx::query_scalar(
        "UPDATE counters SET value = value + 1 WHERE name = 'change_seq' RETURNING value",
    )
    .fetch_one(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO org_members (org_id, account_id, role, status, attestation, attestation_signature, \
         invited_by, seq, created_at, updated_at) VALUES ($1, $2, $3, 'accepted', NULL, NULL, $4, $5, $6, $7)",
    )
    .bind(org_id)
    .bind(account_id)
    .bind(role)
    .bind(created_by)
    .bind(seq)
    .bind(now)
    .bind(now)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "UPDATE org_invitations SET status = 'accepted', accepted_by = $1, accepted_at = $2 WHERE id = $3",
    )
    .bind(account_id)
    .bind(now)
    .bind(invitation_id)
    .execute(&mut *conn)
    .await?;
    sqlx::query("UPDATE scim_users SET account_id = $1 WHERE org_id = $2 AND email = (SELECT email FROM accounts WHERE id = $1)")
        .bind(account_id)
        .bind(org_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// The outcome of a "test connection" sign-in.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestResult {
    /// `ok`, or the error a real sign-in would end with.
    outcome: String,
    subject: String,
    email: Option<String>,
    email_verified: bool,
    name: String,
    groups: Vec<String>,
    /// A Passbox account with this email exists (and would be signed in).
    account_found: bool,
    claims: std::collections::BTreeMap<String, String>,
}

#[allow(clippy::too_many_lines)]
async fn handle_callback(
    state: &AppState,
    ip: &str,
    query: CallbackQuery,
) -> ApiResult<Result<String, &'static str>> {
    let Some(state_value) = query.state.filter(|s| s.len() <= 128) else {
        return Ok(Err("sso_expired"));
    };
    let flow: Option<FlowRow> =
        sqlx::query_as(
            "DELETE FROM sso_flows WHERE state_hash = $1 RETURNING org_id, purpose, nonce, code_verifier, \
             binding_hash, return_to, initiated_by, expires_at",
        )
        .bind(hash(&state_value))
        .fetch_optional(&state.db)
        .await?;
    let Some((org_id, purpose, nonce, verifier, binding_hash, return_to, initiated_by, expires_at)) =
        flow
    else {
        return Ok(Err("sso_expired"));
    };
    if expires_at < now_ms() {
        return Ok(Err("sso_expired"));
    }
    if query.error.is_some() {
        return Ok(Err("sso_idp_denied"));
    }
    let Some(code) = query.code.filter(|c| !c.is_empty() && c.len() <= 4096) else {
        return Ok(Err("sso_idp_denied"));
    };
    let mut conn = state.db.acquire().await?;
    let Some(config) = load_config(&mut conn, &org_id).await? else {
        return Ok(Err("sso_not_configured"));
    };
    drop(conn);
    if purpose == "login" && !config.settings.enabled {
        return Ok(Err("sso_not_configured"));
    }
    let Some(discovery) = config.discovery.clone() else {
        return Ok(Err("sso_not_configured"));
    };
    let key = super::sso_key(&state.db).await?;
    let id_token = match oidc::exchange_code(TokenRequest {
        token_endpoint: discovery.token_endpoint.clone(),
        auth: config.token_auth(),
        client_id: config.settings.client_id.clone(),
        client_secret: config.client_secret(&key)?,
        code,
        redirect_uri: redirect_uri(state).unwrap_or_default(),
        code_verifier: verifier,
    })
    .await
    {
        Ok(token) => token,
        Err(error) => {
            tracing::info!(org_id = %org_id, ?error, "token request failed");
            return Ok(Err(match error {
                TokenError::Fetch(_) => "sso_unreachable",
                TokenError::Rejected(_) => "sso_token_rejected",
                TokenError::NoIdToken => "sso_invalid_token",
            }));
        }
    };
    let claims = match verify_token(state, &config, &id_token, &nonce).await {
        Ok(claims) => claims,
        Err(code) => return Ok(Err(code)),
    };
    let who = identity(&config, claims);

    let ticket = token()?;
    let now = now_ms();
    let (outcome, account_id, email, result) = if purpose == "test" {
        let mut conn = state.db.acquire().await?;
        let resolved = resolve(&mut conn, &config, &who, false).await?;
        drop(conn);
        let (outcome, account_found) = match &resolved {
            Ok(Resolved::Account { .. }) => ("ok", true),
            Ok(Resolved::NoAccount { .. }) => ("sso_no_account", false),
            Err(code) => (*code, false),
        };
        let result = TestResult {
            outcome: outcome.to_owned(),
            subject: who.subject.clone(),
            email: who.email.clone(),
            email_verified: who.email_verified,
            name: who.name.clone(),
            groups: who.groups.clone(),
            account_found,
            claims: core_oidc::summarize(&who.claims),
        };
        (
            "ok".to_owned(),
            None,
            who.email.clone().unwrap_or_default(),
            serde_json::to_string(&result).map_err(|e| ApiError::Internal(e.into()))?,
        )
    } else {
        let mut tx = db::begin_write(&state.db).await?;
        let resolved = resolve(&mut tx, &config, &who, true).await?;
        tx.commit().await?;
        match resolved {
            Err(code) => return Ok(Err(code)),
            Ok(Resolved::NoAccount { email }) => {
                ("no_account".to_owned(), None, email, String::new())
            }
            Ok(Resolved::Account { account_id, email }) => {
                record_event(state, &account_id, "sso_authenticated", "", "", ip).await?;
                ("ok".to_owned(), Some(account_id), email, String::new())
            }
        }
    };
    sqlx::query("DELETE FROM sso_tickets WHERE expires_at < $1")
        .bind(now)
        .execute(&state.db)
        .await?;
    sqlx::query(
        "INSERT INTO sso_tickets (ticket_hash, binding_hash, org_id, purpose, outcome, account_id, email, result, \
         initiated_by, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(hash(&ticket))
    .bind(&binding_hash)
    .bind(&org_id)
    .bind(&purpose)
    .bind(&outcome)
    .bind(&account_id)
    .bind(&email)
    .bind(&result)
    .bind(&initiated_by)
    .bind(now + TICKET_TTL_MS)
    .execute(&state.db)
    .await?;
    Ok(Ok(format!("{return_to}#/sso?ticket={ticket}")))
}

/// `GET /sso/callback`: the provider's redirect. Answers with a redirect
/// to the web app carrying a ticket or an error code (never tokens).
pub async fn callback(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Query(query): Query<CallbackQuery>,
) -> Response {
    if let Err(error) = limit(&state, format!("sso-callback:{ip}"), 60, 60) {
        return error.into_response();
    }
    match handle_callback(&state, &ip, query).await {
        Ok(Ok(location)) => redirect(&location),
        Ok(Err(code)) => error_page(&state, code),
        Err(error) => {
            let _ = error.into_response();
            error_page(&state, "sso_failed")
        }
    }
}

// --- Redeeming the ticket ------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedeemRequest {
    ticket: String,
    flow_secret: String,
    /// This device's trusted device ID, if it has one.
    #[serde(default)]
    device_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedeemResponse {
    /// `ok`, or `no_account` when no Passbox account has the email yet.
    status: &'static str,
    org_id: String,
    email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    account_id: Option<String>,
    /// Send with `login/finish` (`ssoProof`) or `/sso/unlock`.
    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof_expires_at: Option<i64>,
    /// The organization lets trusted devices unlock with SSO.
    device_unlock: bool,
    /// `deviceId` is a trusted device of the account.
    device_trusted: bool,
}

/// Consumes a ticket. Fails unless the flow secret matches.
async fn take_ticket(state: &AppState, ticket: &str, flow_secret: &str) -> ApiResult<Ticket> {
    if ticket.len() > 128 || flow_secret.len() > 128 {
        return Err(ApiError::bad_request("invalid ticket"));
    }
    let row: Option<TicketRow> = sqlx::query_as(
        "DELETE FROM sso_tickets WHERE ticket_hash = $1 RETURNING binding_hash, org_id, purpose, outcome, \
         account_id, email, result, initiated_by, expires_at",
    )
    .bind(hash(ticket))
    .fetch_optional(&state.db)
    .await?;
    let Some((binding, org_id, purpose, outcome, account_id, email, result, initiated_by, expires)) =
        row
    else {
        return Err(sso_error(
            "sso_expired",
            "this sign-in has expired; start again",
        ));
    };
    if expires < now_ms() || binding != hash(flow_secret) {
        return Err(sso_error(
            "sso_expired",
            "this sign-in was started in another window or has expired; start again",
        ));
    }
    Ok(Ticket {
        org_id,
        purpose,
        outcome,
        account_id,
        email,
        result,
        initiated_by,
    })
}

type FlowRow = (String, String, String, String, String, String, String, i64);
type TicketRow = (
    String,
    String,
    String,
    String,
    Option<String>,
    String,
    String,
    String,
    i64,
);

/// A redeemed ticket.
struct Ticket {
    org_id: String,
    purpose: String,
    outcome: String,
    account_id: Option<String>,
    email: String,
    result: String,
    initiated_by: String,
}

/// Issues a single-use proof of an SSO sign-in.
pub(crate) async fn issue_proof(
    state: &AppState,
    account_id: &str,
    org_id: &str,
) -> ApiResult<(String, i64)> {
    let proof = token()?;
    let now = now_ms();
    let expires_at = now + PROOF_TTL_MS;
    sqlx::query("DELETE FROM sso_proofs WHERE expires_at < $1")
        .bind(now)
        .execute(&state.db)
        .await?;
    sqlx::query(
        "INSERT INTO sso_proofs (proof_hash, account_id, org_id, created_at, expires_at) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(hash(&proof))
    .bind(account_id)
    .bind(org_id)
    .bind(now)
    .bind(expires_at)
    .execute(&state.db)
    .await?;
    Ok((proof, expires_at))
}

/// Consumes a proof and returns its account and organization.
pub(crate) async fn take_proof(state: &AppState, proof: &str) -> ApiResult<(String, String)> {
    if proof.is_empty() || proof.len() > 128 {
        return Err(sso_error(
            "sso_proof_invalid",
            "the SSO sign-in is not valid; sign in with SSO again",
        ));
    }
    let row: Option<(String, String, i64)> = sqlx::query_as(
        "DELETE FROM sso_proofs WHERE proof_hash = $1 RETURNING account_id, org_id, expires_at",
    )
    .bind(hash(proof))
    .fetch_optional(&state.db)
    .await?;
    match row {
        Some((account_id, org_id, expires_at)) if expires_at >= now_ms() => {
            Ok((account_id, org_id))
        }
        _ => Err(sso_error(
            "sso_proof_invalid",
            "the SSO sign-in has expired; sign in with SSO again",
        )),
    }
}

/// `POST /sso/redeem`: turns the ticket from the callback into a proof.
pub async fn redeem(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<RedeemRequest>,
) -> ApiResult<Json<RedeemResponse>> {
    auth::limit_ip(&state, &ip)?;
    let Ticket {
        org_id,
        purpose,
        outcome,
        account_id,
        email,
        ..
    } = take_ticket(&state, &req.ticket, &req.flow_secret).await?;
    if purpose != "login" {
        return Err(ApiError::bad_request(
            "this ticket is for a connection test",
        ));
    }
    let mut conn = state.db.acquire().await?;
    let device_unlock = load_config(&mut conn, &org_id)
        .await?
        .is_some_and(|c| c.settings.enabled && c.settings.allow_device_unlock);
    let (proof, proof_expires_at, device_trusted) = match (&account_id, outcome.as_str()) {
        (Some(account_id), "ok") => {
            let trusted = match &req.device_id {
                Some(device_id) if device_id.len() <= 64 => sqlx::query_scalar::<_, i64>(
                    "SELECT 1 FROM trusted_devices WHERE id = $1 AND account_id = $2",
                )
                .bind(device_id)
                .bind(account_id)
                .fetch_optional(&mut *conn)
                .await?
                .is_some(),
                _ => false,
            };
            drop(conn);
            let (proof, expires) = issue_proof(&state, account_id, &org_id).await?;
            (Some(proof), Some(expires), trusted)
        }
        _ => (None, None, false),
    };
    Ok(Json(RedeemResponse {
        status: if proof.is_some() { "ok" } else { "no_account" },
        org_id,
        email,
        account_id,
        proof,
        proof_expires_at,
        device_unlock,
        device_trusted,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestResultRequest {
    ticket: String,
    flow_secret: String,
}

/// `POST /orgs/{org_id}/sso/test/result` (the admin who started the test).
pub async fn test_result(
    State(state): State<AppState>,
    session: Session,
    Path(org_id): Path<String>,
    Json(req): Json<TestResultRequest>,
) -> ApiResult<Json<Value>> {
    validate::id("organization id", &org_id)?;
    let Ticket {
        org_id: ticket_org,
        purpose,
        result,
        initiated_by,
        ..
    } = take_ticket(&state, &req.ticket, &req.flow_secret).await?;
    if purpose != "test" || ticket_org != org_id || initiated_by != session.account_id {
        return Err(ApiError::NotFound);
    }
    let result: TestResult =
        serde_json::from_str(&result).map_err(|e| ApiError::Internal(e.into()))?;
    Ok(Json(json!(result)))
}

// --- "SSO required" at login/finish ----------------------------------------------------

/// The result of the SSO check of a password login.
#[derive(Debug, Default)]
pub(crate) struct SsoLogin {
    /// The login carried a valid SSO proof or the device signed in with SSO
    /// recently: the identity provider stands in for the second factor.
    pub satisfied: bool,
    /// Remember SSO on the new device token until then (Unix ms; 0 keeps).
    pub remember_until: i64,
}

/// Organizations that require SSO from this account (it is a member, but
/// not an owner or admin, who can always use the master password so a
/// broken provider cannot lock an organization out).
async fn requiring_orgs(state: &AppState, account_id: &str) -> ApiResult<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT org_sso.org_id FROM org_sso JOIN org_members ON org_members.org_id = org_sso.org_id \
         WHERE org_members.account_id = $1 AND org_sso.enabled = 1 AND org_sso.required = 1 \
         AND org_members.role = 'member'",
    )
    .bind(account_id)
    .fetch_all(&state.db)
    .await?)
}

async fn reauth_until(state: &AppState, org_id: &str, now: i64) -> ApiResult<i64> {
    let hours: Option<i64> =
        sqlx::query_scalar("SELECT reauth_hours FROM org_sso WHERE org_id = $1")
            .bind(org_id)
            .fetch_optional(&state.db)
            .await?;
    Ok(now + hours.unwrap_or(12) * 60 * 60 * 1000)
}

/// Checks a password login against the organizations' "SSO required"
/// policy, after the password was verified. Fails with `sso_required` when
/// SSO is required and neither a proof nor a recent SSO sign-in on this
/// device is there.
pub(crate) async fn login_gate(
    state: &AppState,
    account_id: &str,
    proof: Option<&str>,
    device_token_hash: Option<&str>,
) -> ApiResult<SsoLogin> {
    let now = now_ms();
    let mut result = SsoLogin::default();
    if let Some(proof) = proof.filter(|p| !p.is_empty()) {
        let (proof_account, org_id) = take_proof(state, proof).await?;
        if proof_account != account_id {
            return Err(sso_error(
                "sso_proof_invalid",
                "the SSO sign-in belongs to another account",
            ));
        }
        result.satisfied = true;
        result.remember_until = reauth_until(state, &org_id, now).await?;
    }
    let required = requiring_orgs(state, account_id).await?;
    if required.is_empty() || result.satisfied {
        return Ok(result);
    }
    let remembered: Option<i64> = sqlx::query_scalar(
        "SELECT sso_until FROM device_tokens WHERE token_hash = $1 AND account_id = $2",
    )
    .bind(device_token_hash.unwrap_or(""))
    .bind(account_id)
    .fetch_optional(&state.db)
    .await?;
    if remembered.is_some_and(|until| until > now) {
        result.satisfied = true;
        return Ok(result);
    }
    Err(sso_error(
        "sso_required",
        "your organization requires signing in with single sign-on",
    ))
}

/// Remembers the SSO sign-in on the device token issued with the session.
pub(crate) async fn remember(state: &AppState, device_token: &str, until: i64) -> ApiResult<()> {
    if until == 0 {
        return Ok(());
    }
    sqlx::query("UPDATE device_tokens SET sso_until = $1 WHERE token_hash = $2 AND sso_until < $1")
        .bind(until)
        .bind(auth::hash_token(device_token))
        .execute(&state.db)
        .await?;
    Ok(())
}

/// Ends everything that lets an account in: sessions, device tokens (and
/// with them remembered SSO and two-factor sign-ins), proofs and trusted
/// devices. Used when the directory deprovisions someone.
pub(crate) async fn end_access(conn: &mut AnyConnection, account_id: &str) -> ApiResult<()> {
    for statement in [
        "DELETE FROM sessions WHERE account_id = $1",
        "DELETE FROM device_tokens WHERE account_id = $1",
        "DELETE FROM sso_proofs WHERE account_id = $1",
        "DELETE FROM trusted_devices WHERE account_id = $1",
        "DELETE FROM trusted_device_requests WHERE account_id = $1",
    ] {
        sqlx::query(statement)
            .bind(account_id)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

/// A new ID for rows that need one.
pub(crate) fn new_id() -> ApiResult<String> {
    id::new_id().map_err(|e| ApiError::Internal(e.into()))
}
