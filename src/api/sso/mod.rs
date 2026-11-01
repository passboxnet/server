//! Single sign-on with OpenID Connect and unlocking with SSO on trusted
//! devices.
//!
//! - [`config`] (this module): an organization's OIDC configuration
//!   (owners and admins), connection checks.
//! - [`login`]: discovery by email domain, the authorization code flow with
//!   PKCE, the callback, tickets and proofs, and the "SSO required" check
//!   at `login/finish`.
//! - [`devices`]: trusted devices that unlock with SSO instead of the
//!   master password, and approving new devices.
//!
//! SSO proves who someone is. It never gives the server anything that
//! decrypts data: without a trusted device the user still unlocks with the
//! master password and the Secret Key. See `docs/architecture/sso.md`.

pub mod devices;
pub mod login;
pub mod oidc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use passbox_core::aead::SymmetricKey;
use passbox_core::{encoding, random};
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;

pub use self::oidc::allow_http_loopback;
use self::oidc::{Discovery, FetchError, TokenAuth};
use super::access;
use super::auth::{Session, record_event};
use super::validate;
use crate::db::now_ms;
use crate::error::{ApiError, ApiResult};
use crate::security::ClientIp;
use crate::state::AppState;

/// Identity provider presets offered in the settings (labels only; every
/// provider uses the same generic OIDC code).
pub const PROVIDERS: [&str; 7] = [
    "generic",
    "entra",
    "google",
    "okta",
    "keycloak",
    "authentik",
    "zitadel",
];
const MAX_DOMAINS: usize = 50;
/// The JWKS is fetched again after this long, or earlier for an unknown `kid`.
pub(crate) const JWKS_MAX_AGE_MS: i64 = 60 * 60 * 1000;

pub(crate) fn sso_error(code: &'static str, message: impl Into<String>) -> ApiError {
    ApiError::forbidden(code, message)
}

fn fetch_error(error: FetchError) -> ApiError {
    sso_error(error.code(), error.message())
}

/// The key that encrypts client secrets at rest, created on first use. It
/// sits in `server_secrets` like the two-factor key: this protects against
/// leaks of single tables or exports, not a full database copy.
async fn sso_key(db: &crate::db::Db) -> ApiResult<SymmetricKey> {
    let candidate = random::bytes::<32>().map_err(|e| ApiError::Internal(e.into()))?;
    let mut tx = db.system(crate::db::Job::Secrets).await?;
    sqlx::query!(
        "INSERT INTO server_secrets (name, value) VALUES ('sso_key', $1) ON CONFLICT (name) DO NOTHING",
        candidate.as_slice(),
    )
    .execute(&mut *tx)
    .await?;
    let stored = sqlx::query_scalar!("SELECT value FROM server_secrets WHERE name = 'sso_key'")
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    let bytes: [u8; 32] = Some(stored)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("corrupt sso_key")))?;
    Ok(SymmetricKey::from_bytes(bytes))
}

fn secret_aad(org_id: &str) -> Vec<u8> {
    format!("passbox/v1/server/sso-client-secret|{org_id}").into_bytes()
}

/// Settings an admin edits.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SsoSettings {
    pub enabled: bool,
    /// Members (other than owners and admins) must sign in with SSO.
    #[serde(default)]
    pub required: bool,
    /// Members may unlock with SSO on trusted devices.
    #[serde(default)]
    pub allow_device_unlock: bool,
    #[serde(default = "default_provider")]
    pub provider: String,
    /// Shown on the sign-in button, for example "Contoso (Microsoft Entra ID)".
    pub display_name: String,
    pub issuer: String,
    pub client_id: String,
    /// Write only. Omitted or `null` keeps the stored secret; `""` removes it.
    #[serde(default, skip_serializing)]
    pub client_secret: Option<String>,
    #[serde(default = "default_auth_method")]
    pub token_auth_method: String,
    #[serde(default = "default_scopes")]
    pub scopes: String,
    #[serde(default = "default_email_claim")]
    pub email_claim: String,
    #[serde(default = "default_true")]
    pub require_verified_email: bool,
    #[serde(default = "default_name_claim")]
    pub name_claim: String,
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// How long an SSO sign-in is remembered on a device for the "SSO
    /// required" policy (hours).
    #[serde(default = "default_reauth_hours")]
    pub reauth_hours: u32,
}

fn default_provider() -> String {
    "generic".into()
}
fn default_auth_method() -> String {
    "client_secret_basic".into()
}
fn default_scopes() -> String {
    "openid email profile".into()
}
fn default_email_claim() -> String {
    "email".into()
}
fn default_name_claim() -> String {
    "name".into()
}
fn default_groups_claim() -> String {
    "groups".into()
}
fn default_true() -> bool {
    true
}
fn default_reauth_hours() -> u32 {
    12
}

/// The stored configuration with its server-side parts.
#[derive(Debug, Clone)]
pub(crate) struct StoredConfig {
    pub org_id: String,
    pub settings: SsoSettings,
    pub encrypted_client_secret: String,
    pub discovery: Option<Discovery>,
    pub jwks: String,
    pub jwks_fetched_at: i64,
    pub updated_at: i64,
}

impl StoredConfig {
    pub fn client_secret(&self, key: &SymmetricKey) -> ApiResult<String> {
        if self.encrypted_client_secret.is_empty() {
            return Ok(String::new());
        }
        let envelope = encoding::decode(&self.encrypted_client_secret)
            .map_err(|e| ApiError::Internal(e.into()))?;
        let plaintext = key
            .decrypt(&envelope, &secret_aad(&self.org_id))
            .map_err(|e| ApiError::Internal(e.into()))?;
        String::from_utf8(plaintext.to_vec())
            .map_err(|_| ApiError::Internal(anyhow::anyhow!("client secret is not UTF-8")))
    }

    pub fn token_auth(&self) -> TokenAuth {
        TokenAuth::parse(&self.settings.token_auth_method).unwrap_or(TokenAuth::Basic)
    }
}

pub(crate) async fn load_config(
    conn: &mut PgConnection,
    org_id: &str,
) -> ApiResult<Option<StoredConfig>> {
    let row = sqlx::query!(
        "SELECT org_id, enabled, required, allow_device_unlock, provider, display_name, issuer, client_id, \
         encrypted_client_secret, token_auth_method, scopes, email_claim, require_verified_email, name_claim, \
         groups_claim, allowed_domains, reauth_hours, discovery, jwks, jwks_fetched_at, updated_at \
         FROM org_sso WHERE org_id = $1",
        org_id,
    )
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    Ok(Some(StoredConfig {
        org_id: row.org_id,
        settings: SsoSettings {
            enabled: row.enabled,
            required: row.required,
            allow_device_unlock: row.allow_device_unlock,
            provider: row.provider,
            display_name: row.display_name,
            issuer: row.issuer,
            client_id: row.client_id,
            client_secret: None,
            token_auth_method: row.token_auth_method,
            scopes: row.scopes,
            email_claim: row.email_claim,
            require_verified_email: row.require_verified_email,
            name_claim: row.name_claim,
            groups_claim: row.groups_claim,
            allowed_domains: row
                .allowed_domains
                .split(',')
                .filter(|d| !d.is_empty())
                .map(str::to_owned)
                .collect(),
            reauth_hours: u32::try_from(row.reauth_hours).unwrap_or(12),
        },
        encrypted_client_secret: row.encrypted_client_secret,
        discovery: serde_json::from_str(&row.discovery).ok(),
        jwks: row.jwks,
        jwks_fetched_at: row.jwks_fetched_at,
        updated_at: row.updated_at,
    }))
}

/// The redirect URI to register at the identity provider.
pub(crate) fn redirect_uri(state: &AppState) -> Option<String> {
    state
        .mailer
        .public_url()
        .map(|base| format!("{}/api/v1/sso/callback", base.trim_end_matches('/')))
}

fn is_claim_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.:/-".contains(c))
}

/// Normalizes and checks an email domain (`example.com`, lower case).
pub(crate) fn normalize_domain(value: &str) -> Option<String> {
    let domain = value.trim().trim_start_matches('@').to_lowercase();
    let valid = domain.len() <= 253
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains("..")
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
    valid.then_some(domain)
}

fn bad(message: impl Into<String>) -> ApiError {
    ApiError::bad_request(message)
}

fn clean_text(value: &str, max: usize) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(max)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn validate_settings(settings: &mut SsoSettings) -> ApiResult<()> {
    if !PROVIDERS.contains(&settings.provider.as_str()) {
        return Err(bad("unknown provider"));
    }
    settings.display_name = clean_text(&settings.display_name, 80);
    if settings.display_name.is_empty() {
        return Err(bad("displayName is required"));
    }
    settings.issuer = settings.issuer.trim().to_owned();
    if settings.issuer.len() > 512 {
        return Err(bad("issuer is too long"));
    }
    oidc::check_url(&settings.issuer).map_err(fetch_error)?;
    settings.client_id = settings.client_id.trim().to_owned();
    if settings.client_id.is_empty()
        || settings.client_id.len() > 256
        || settings.client_id.chars().any(char::is_control)
    {
        return Err(bad("invalid clientId"));
    }
    if let Some(secret) = &settings.client_secret
        && (secret.len() > 1024 || secret.chars().any(char::is_control))
    {
        return Err(bad("invalid clientSecret"));
    }
    if TokenAuth::parse(&settings.token_auth_method).is_none() {
        return Err(bad(
            "tokenAuthMethod must be client_secret_basic, client_secret_post or none",
        ));
    }
    let scopes: Vec<&str> = settings.scopes.split_whitespace().collect();
    if !scopes.contains(&"openid")
        || scopes.len() > 20
        || scopes.iter().any(|s| {
            s.len() > 128
                || !s
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_:./-".contains(c))
        })
    {
        return Err(bad(
            "scopes must include openid and contain only valid scope names",
        ));
    }
    settings.scopes = scopes.join(" ");
    for (field, value) in [
        ("emailClaim", &settings.email_claim),
        ("nameClaim", &settings.name_claim),
        ("groupsClaim", &settings.groups_claim),
    ] {
        if !is_claim_name(value) {
            return Err(bad(format!("invalid {field}")));
        }
    }
    let mut domains = Vec::new();
    for domain in &settings.allowed_domains {
        let domain =
            normalize_domain(domain).ok_or_else(|| bad(format!("invalid domain {domain:?}")))?;
        if !domains.contains(&domain) {
            domains.push(domain);
        }
    }
    if domains.len() > MAX_DOMAINS {
        return Err(bad("too many domains"));
    }
    settings.allowed_domains = domains;
    if settings.enabled && settings.allowed_domains.is_empty() {
        return Err(bad("name at least one email domain"));
    }
    if !(1..=720).contains(&settings.reauth_hours) {
        return Err(bad("reauthHours must be between 1 and 720"));
    }
    if !settings.enabled {
        settings.required = false;
        settings.allow_device_unlock = false;
    }
    Ok(())
}

/// The configuration as admins see it (never the client secret).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SsoConfigResponse {
    #[serde(flatten)]
    settings: SsoSettings,
    has_client_secret: bool,
    /// Register this at the identity provider. `null` without `PASSBOX_PUBLIC_URL`.
    redirect_uri: Option<String>,
    /// Endpoints from the last successful discovery.
    discovery: Option<DiscoverySummary>,
    updated_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoverySummary {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

impl From<&Discovery> for DiscoverySummary {
    fn from(d: &Discovery) -> Self {
        Self {
            issuer: d.issuer.clone(),
            authorization_endpoint: d.authorization_endpoint.clone(),
            token_endpoint: d.token_endpoint.clone(),
            jwks_uri: d.jwks_uri.clone(),
        }
    }
}

fn response(state: &AppState, config: StoredConfig) -> SsoConfigResponse {
    SsoConfigResponse {
        has_client_secret: !config.encrypted_client_secret.is_empty(),
        redirect_uri: redirect_uri(state),
        discovery: config.discovery.as_ref().map(DiscoverySummary::from),
        updated_at: config.updated_at,
        settings: config.settings,
    }
}

/// `GET /orgs/{org_id}/sso` (owners and admins): the configuration, or
/// `null` when none is set up.
pub async fn get(
    State(state): State<AppState>,
    session: Session,
    Path(org_id): Path<String>,
) -> ApiResult<Json<Option<SsoConfigResponse>>> {
    validate::id("organization id", &org_id)?;
    let mut conn = state.db.as_account(&session.account_id).await?;
    access::require_admin(&mut conn, &org_id, &session.account_id).await?;
    let config = load_config(&mut conn, &org_id).await?;
    drop(conn);
    Ok(Json(config.map(|c| response(&state, c))))
}

/// `PUT /orgs/{org_id}/sso` (owners and admins). Enabling checks the
/// provider's discovery document and keys first and claims the email
/// domains (each domain belongs to one organization on the instance).
pub async fn put(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(org_id): Path<String>,
    Json(mut settings): Json<SsoSettings>,
) -> ApiResult<Json<SsoConfigResponse>> {
    validate::id("organization id", &org_id)?;
    validate_settings(&mut settings)?;
    let previous = {
        let mut conn = state.db.as_account(&session.account_id).await?;
        access::require_admin(&mut conn, &org_id, &session.account_id).await?;
        if settings.enabled {
            crate::ext::check_feature(
                &state,
                &mut conn,
                &org_id,
                crate::ext::OrgFeature::Sso,
                true,
            )
            .await?;
        }
        let kind: String =
            sqlx::query_scalar!("SELECT kind FROM organizations WHERE id = $1", &org_id,)
                .fetch_one(&mut *conn)
                .await?;
        if kind != "team" {
            return Err(sso_error(
                "sso_team_only",
                "single sign-on is available for team organizations",
            ));
        }
        load_config(&mut conn, &org_id).await?
    };

    // Talk to the provider before the transaction (it can take seconds).
    let mut discovery_json = String::new();
    let mut jwks_json = String::new();
    let mut jwks_fetched_at = 0;
    if settings.enabled {
        let discovery = oidc::discover(&settings.issuer)
            .await
            .map_err(fetch_error)?;
        let (jwks, _) = oidc::fetch_jwks(&discovery.jwks_uri)
            .await
            .map_err(fetch_error)?;
        settings.issuer = discovery.issuer.clone();
        discovery_json =
            serde_json::to_string(&discovery).map_err(|e| ApiError::Internal(e.into()))?;
        jwks_json = jwks;
        jwks_fetched_at = now_ms();
    }

    let key = sso_key(&state.db).await?;
    let encrypted_client_secret = match &settings.client_secret {
        Some(secret) if secret.is_empty() => String::new(),
        Some(secret) => encoding::encode(
            &key.encrypt(secret.as_bytes(), &secret_aad(&org_id))
                .map_err(|e| ApiError::Internal(e.into()))?,
        ),
        None => previous
            .as_ref()
            .map(|p| p.encrypted_client_secret.clone())
            .unwrap_or_default(),
    };
    if settings.enabled
        && settings.token_auth_method != "none"
        && encrypted_client_secret.is_empty()
    {
        return Err(bad(
            "a client secret is required unless tokenAuthMethod is none",
        ));
    }

    let now = now_ms();
    let mut tx = state.db.as_account(&session.account_id).await?;
    access::require_admin(&mut tx, &org_id, &session.account_id).await?;
    sqlx::query!("DELETE FROM sso_domains WHERE org_id = $1", &org_id,)
        .execute(&mut *tx)
        .await?;
    if settings.enabled {
        for domain in &settings.allowed_domains {
            // Domains of other organizations are not readable: the
            // function answers whether this one is taken.
            let taken =
                sqlx::query_scalar!(r#"SELECT passbox.sso_domain_taken($1) AS "taken!""#, domain,)
                    .fetch_one(&mut *tx)
                    .await?;
            if taken {
                return Err(ApiError::conflict(
                    format!("{domain} already signs in through another organization"),
                    serde_json::json!({ "code": "sso_domain_taken", "domain": domain }),
                ));
            }
            sqlx::query!(
                "INSERT INTO sso_domains (domain, org_id) VALUES ($1, $2)",
                domain,
                &org_id,
            )
            .execute(&mut *tx)
            .await?;
        }
    }
    // Links to provider accounts belong to one issuer.
    if previous
        .as_ref()
        .is_some_and(|p| p.settings.issuer != settings.issuer)
    {
        sqlx::query!("DELETE FROM sso_identities WHERE org_id = $1", &org_id,)
            .execute(&mut *tx)
            .await?;
    }
    let (discovery_json, jwks_json, jwks_fetched_at) = if settings.enabled {
        (discovery_json, jwks_json, jwks_fetched_at)
    } else {
        previous
            .as_ref()
            .map(|p| {
                (
                    p.discovery
                        .as_ref()
                        .and_then(|d| serde_json::to_string(d).ok())
                        .unwrap_or_default(),
                    p.jwks.clone(),
                    p.jwks_fetched_at,
                )
            })
            .unwrap_or_default()
    };
    sqlx::query!("DELETE FROM org_sso WHERE org_id = $1", &org_id,)
        .execute(&mut *tx)
        .await?;
    sqlx::query!(
        "INSERT INTO org_sso (org_id, enabled, required, allow_device_unlock, provider, display_name, issuer, \
         client_id, encrypted_client_secret, token_auth_method, scopes, email_claim, require_verified_email, \
         name_claim, groups_claim, allowed_domains, reauth_hours, discovery, jwks, jwks_fetched_at, updated_by, \
         created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, \
         $17, $18, $19, $20, $21, $22, $23)",
        &org_id,
        settings.enabled,
        settings.required,
        settings.allow_device_unlock,
        &settings.provider,
        &settings.display_name,
        &settings.issuer,
        &settings.client_id,
        &encrypted_client_secret,
        &settings.token_auth_method,
        &settings.scopes,
        &settings.email_claim,
        settings.require_verified_email,
        &settings.name_claim,
        &settings.groups_claim,
        settings.allowed_domains.join(","),
        i64::from(settings.reauth_hours),
        &discovery_json,
        &jwks_json,
        jwks_fetched_at,
        &session.account_id,
        now,
        now,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    record_event(
        &state,
        &session.account_id,
        "org_sso_updated",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    let mut conn = state.db.as_account(&session.account_id).await?;
    let stored = load_config(&mut conn, &org_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    drop(conn);
    Ok(Json(response(&state, stored)))
}

/// `DELETE /orgs/{org_id}/sso` (owners and admins): removes the
/// configuration, its domains, links and trusted devices' permission.
pub async fn delete(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(org_id): Path<String>,
) -> ApiResult<StatusCode> {
    validate::id("organization id", &org_id)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    access::require_admin(&mut tx, &org_id, &session.account_id).await?;
    for statement in [
        "DELETE FROM sso_domains WHERE org_id = $1",
        "DELETE FROM sso_identities WHERE org_id = $1",
        "DELETE FROM sso_flows WHERE org_id = $1",
        "DELETE FROM sso_tickets WHERE org_id = $1",
        "DELETE FROM sso_proofs WHERE org_id = $1",
        "DELETE FROM trusted_device_requests WHERE org_id = $1",
        "DELETE FROM org_sso WHERE org_id = $1",
    ] {
        sqlx::query(statement)
            .bind(&org_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    record_event(
        &state,
        &session.account_id,
        "org_sso_removed",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckRequest {
    /// Checks this issuer instead of the saved one (before saving).
    #[serde(default)]
    issuer: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckProblem {
    code: &'static str,
    message: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckResponse {
    ok: bool,
    discovery: Option<DiscoverySummary>,
    /// Signing keys found in the JWKS.
    keys: usize,
    /// ID token algorithms the provider offers that Passbox accepts.
    algorithms: Vec<String>,
    problem: Option<CheckProblem>,
    redirect_uri: Option<String>,
}

/// `POST /orgs/{org_id}/sso/check` (owners and admins): fetches the
/// discovery document and the JWKS and reports what was found. Only
/// parsed fields and error codes are returned, never response bodies.
pub async fn check(
    State(state): State<AppState>,
    session: Session,
    Path(org_id): Path<String>,
    Json(req): Json<CheckRequest>,
) -> ApiResult<Json<CheckResponse>> {
    validate::id("organization id", &org_id)?;
    let issuer = {
        let mut conn = state.db.as_account(&session.account_id).await?;
        access::require_admin(&mut conn, &org_id, &session.account_id).await?;
        match req.issuer {
            Some(issuer) => issuer.trim().to_owned(),
            None => load_config(&mut conn, &org_id)
                .await?
                .map(|c| c.settings.issuer)
                .ok_or(ApiError::NotFound)?,
        }
    };
    if let Some(wait) = state.limiter.hit(
        &format!("sso-check:{org_id}"),
        30,
        std::time::Duration::from_secs(60),
    ) {
        return Err(ApiError::RateLimited(wait));
    }
    let mut result = CheckResponse {
        ok: false,
        discovery: None,
        keys: 0,
        algorithms: Vec::new(),
        problem: None,
        redirect_uri: redirect_uri(&state),
    };
    let fail = |error: FetchError| {
        Some(CheckProblem {
            code: error.code(),
            message: error.message(),
        })
    };
    match oidc::discover(&issuer).await {
        Err(error) => result.problem = fail(error),
        Ok(discovery) => {
            result.algorithms = discovery
                .id_token_signing_alg_values_supported
                .iter()
                .filter(|a| passbox_core::oidc::SUPPORTED_ALGORITHMS.contains(&a.as_str()))
                .cloned()
                .collect();
            match oidc::fetch_jwks(&discovery.jwks_uri).await {
                Err(error) => result.problem = fail(error),
                Ok((_, jwks)) => {
                    result.keys = jwks.keys.len();
                    result.ok = true;
                }
            }
            result.discovery = Some(DiscoverySummary::from(&discovery));
        }
    }
    if result.ok && result.redirect_uri.is_none() {
        result.ok = false;
        result.problem = Some(CheckProblem {
            code: "sso_public_url_missing",
            message: "set PASSBOX_PUBLIC_URL so the server knows its redirect URI".into(),
        });
    }
    Ok(Json(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> SsoSettings {
        serde_json::from_value(serde_json::json!({
            "enabled": true,
            "displayName": " Acme  ",
            "issuer": "https://idp.example.com",
            "clientId": "passbox",
            "scopes": "openid  email",
            "allowedDomains": ["@Acme.Example", "acme.example", "sub.acme.example"],
        }))
        .unwrap()
    }

    #[test]
    fn validates_and_normalizes_settings() {
        let mut s = settings();
        validate_settings(&mut s).unwrap();
        assert_eq!(s.display_name, "Acme");
        assert_eq!(s.scopes, "openid email");
        assert_eq!(s.allowed_domains, vec!["acme.example", "sub.acme.example"]);
        assert_eq!(s.token_auth_method, "client_secret_basic");
        assert!(s.require_verified_email);

        for change in [
            serde_json::json!({ "scopes": "email" }),
            serde_json::json!({ "issuer": "http://idp.example.com" }),
            serde_json::json!({ "provider": "saml" }),
            serde_json::json!({ "allowedDomains": [] }),
            serde_json::json!({ "allowedDomains": ["not a domain"] }),
            serde_json::json!({ "emailClaim": "e mail" }),
            serde_json::json!({ "reauthHours": 0 }),
            serde_json::json!({ "tokenAuthMethod": "private_key_jwt" }),
            serde_json::json!({ "displayName": "  " }),
        ] {
            let mut value = serde_json::to_value(settings()).unwrap();
            for (k, v) in change.as_object().unwrap() {
                value[k] = v.clone();
            }
            let mut s: SsoSettings = serde_json::from_value(value).unwrap();
            assert!(validate_settings(&mut s).is_err(), "{change}");
        }
        // Disabled configurations cannot require SSO.
        let mut s = settings();
        s.enabled = false;
        s.required = true;
        s.allowed_domains.clear();
        validate_settings(&mut s).unwrap();
        assert!(!s.required);
    }
}
