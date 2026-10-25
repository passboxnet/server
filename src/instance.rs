//! Instance-wide settings and instance administration.
//!
//! - **Instance admins** are the first account created on the server (on
//!   servers upgraded from a version without admins: the oldest account) and
//!   the accounts whose email is listed in `PASSBOX_ADMIN_EMAILS`.
//! - **Registration** is `open`, `invite_only` (only with an invitation from
//!   an admin) or `domains` (only emails of the allowed domains, plus
//!   invitations). The very first account can always be created, so a fresh
//!   server can be set up.
//! - **Disabled accounts** cannot sign in (`account_disabled`) and lose all
//!   sessions when they are disabled.

use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::db::{Conn, Db, Public, Tx, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::mail::Locale;
use crate::state::AppState;

/// Who may create an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationMode {
    #[default]
    Open,
    InviteOnly,
    Domains,
}

impl RegistrationMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::InviteOnly => "invite_only",
            Self::Domains => "domains",
        }
    }
}

/// Minimum strength of new master passwords. Clients enforce it (the server
/// never sees the password); it is published in `/api/v1/meta`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PasswordPolicy {
    /// Lowest strength score (3 = strong, 4 = very strong). Never below 3,
    /// the clients' own minimum.
    pub min_score: u8,
    /// Lowest number of characters. Never below 12.
    pub min_length: u32,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_score: 3,
            min_length: 12,
        }
    }
}

/// Settings an instance admin can change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct InstanceSettings {
    /// Shown in mails and the web app.
    pub instance_name: String,
    pub registration: RegistrationMode,
    /// Email domains that may register in `domains` mode, lower case.
    pub allowed_domains: Vec<String>,
    /// Where users get help, shown by the web app ('' = none).
    pub support_url: String,
    /// Language of mails to accounts without a language preference.
    pub default_locale: Locale,
    pub password_policy: PasswordPolicy,
    /// AI agents and service accounts per member (fair use). `None` uses
    /// `PASSBOX_AGENT_LIMIT_PER_MEMBER`; `Some(0)` is unlimited.
    pub agent_limit_per_member: Option<u32>,
}

/// Highest agent limit an admin can set (per member).
pub const MAX_AGENT_LIMIT_PER_MEMBER: u32 = 10_000;

impl Default for InstanceSettings {
    fn default() -> Self {
        Self {
            instance_name: "Passbox".to_owned(),
            registration: RegistrationMode::Open,
            allowed_domains: Vec::new(),
            support_url: String::new(),
            default_locale: Locale::En,
            password_policy: PasswordPolicy::default(),
            agent_limit_per_member: None,
        }
    }
}

const MAX_DOMAINS: usize = 100;

impl InstanceSettings {
    /// Checks and normalizes settings sent by an admin.
    pub fn validated(mut self) -> ApiResult<Self> {
        self.instance_name = self.instance_name.trim().to_owned();
        if self.instance_name.is_empty() || self.instance_name.chars().count() > 60 {
            return Err(ApiError::bad_request(
                "instanceName must have 1 to 60 characters",
            ));
        }
        if self.instance_name.chars().any(char::is_control) {
            return Err(ApiError::bad_request(
                "instanceName contains control characters",
            ));
        }
        let mut domains = Vec::new();
        for domain in &self.allowed_domains {
            let domain = domain.trim().trim_start_matches('@').to_ascii_lowercase();
            if domain.is_empty() {
                continue;
            }
            if !is_domain(&domain) {
                return Err(ApiError::bad_request(format!("invalid domain: {domain}")));
            }
            if !domains.contains(&domain) {
                domains.push(domain);
            }
        }
        if domains.len() > MAX_DOMAINS {
            return Err(ApiError::bad_request("too many allowed domains"));
        }
        if self.registration == RegistrationMode::Domains && domains.is_empty() {
            return Err(ApiError::bad_request(
                "registration mode domains needs at least one allowed domain",
            ));
        }
        self.allowed_domains = domains;
        self.support_url = self.support_url.trim().to_owned();
        if !self.support_url.is_empty()
            && (!(self.support_url.starts_with("https://")
                || self.support_url.starts_with("http://")
                || self.support_url.starts_with("mailto:"))
                || self.support_url.len() > 500
                || self.support_url.chars().any(|c| c.is_control() || c == ' '))
        {
            return Err(ApiError::bad_request(
                "supportUrl must be an https://, http:// or mailto: address",
            ));
        }
        if !(3..=4).contains(&self.password_policy.min_score) {
            return Err(ApiError::bad_request(
                "passwordPolicy.minScore must be 3 or 4",
            ));
        }
        if !(12..=128).contains(&self.password_policy.min_length) {
            return Err(ApiError::bad_request(
                "passwordPolicy.minLength must be between 12 and 128",
            ));
        }
        if self
            .agent_limit_per_member
            .is_some_and(|limit| limit > MAX_AGENT_LIMIT_PER_MEMBER)
        {
            return Err(ApiError::bad_request(format!(
                "agentLimitPerMember must be between 0 (unlimited) and {MAX_AGENT_LIMIT_PER_MEMBER}"
            )));
        }
        Ok(self)
    }
}

fn is_domain(domain: &str) -> bool {
    domain.len() <= 253
        && domain.contains('.')
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// Loads the instance settings (defaults if none were saved). Every
/// context may read them.
pub async fn load_settings(conn: &mut Conn) -> anyhow::Result<InstanceSettings> {
    let value = sqlx::query_scalar!("SELECT value FROM instance_state WHERE name = 'settings'")
        .fetch_optional(conn)
        .await?;
    Ok(match value {
        Some(json) => serde_json::from_value(json).unwrap_or_else(|err| {
            tracing::error!(error = %err, "stored instance settings are invalid; using defaults");
            InstanceSettings::default()
        }),
        None => InstanceSettings::default(),
    })
}

/// Loads the instance settings in a context of its own (instance
/// information is public).
pub async fn load_settings_from(db: &Db) -> anyhow::Result<InstanceSettings> {
    let mut tx = db.public(Public::Meta).await?;
    load_settings(&mut tx).await
}

/// Saves the instance settings inside an instance admin's transaction.
pub async fn save_settings(conn: &mut Conn, settings: &InstanceSettings) -> anyhow::Result<()> {
    let json = serde_json::to_value(settings)?;
    sqlx::query!(
        "INSERT INTO instance_state (name, value, updated_at) VALUES ('settings', $1, $2) \
         ON CONFLICT (name) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        json,
        now_ms(),
    )
    .execute(conn)
    .await?;
    Ok(())
}

/// Whether `email` is listed in `PASSBOX_ADMIN_EMAILS`.
pub fn is_env_admin(state: &AppState, email: &str) -> bool {
    state
        .admin_emails
        .iter()
        .any(|admin| admin.eq_ignore_ascii_case(email))
}

/// Whether the account is an instance admin. Runs in the account's own
/// context.
pub async fn is_admin(state: &AppState, conn: &mut Conn, account_id: &str) -> ApiResult<bool> {
    let row = sqlx::query!(
        "SELECT email, instance_admin FROM accounts WHERE id = $1",
        account_id
    )
    .fetch_optional(conn)
    .await?;
    Ok(match row {
        Some(row) => row.instance_admin || is_env_admin(state, &row.email),
        None => false,
    })
}

/// Fails with `account_disabled` if an admin disabled the account. Called
/// after the password was verified, so it reveals nothing to strangers.
pub async fn ensure_active(conn: &mut Conn, account_id: &str) -> ApiResult<()> {
    let disabled_at =
        sqlx::query_scalar!("SELECT disabled_at FROM accounts WHERE id = $1", account_id)
            .fetch_optional(conn)
            .await?;
    if disabled_at.unwrap_or(0) != 0 {
        return Err(ApiError::forbidden(
            "account_disabled",
            "this account has been disabled by an administrator",
        ));
    }
    Ok(())
}

/// Invitations to the instance are valid for 7 days.
pub const INVITE_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;

pub fn hash_invite_token(token: &str) -> String {
    HEXLOWER.encode(&Sha256::digest(token.as_bytes()))
}

/// What allowed a registration.
#[derive(Debug, Default)]
pub struct RegistrationGrant {
    /// The invitation used, to be marked as used with the new account.
    pub invite_id: Option<String>,
}

/// Decides whether `email` may create an account now. Fails with
/// `registration_closed`, `domain_not_allowed` or `invitation_invalid`.
pub async fn check_registration(
    state: &AppState,
    conn: &mut Conn,
    email: &str,
    invite_token: Option<&str>,
) -> ApiResult<RegistrationGrant> {
    let invite_token = invite_token.map(str::trim).filter(|t| !t.is_empty());
    let mut grant = RegistrationGrant::default();
    if let Some(token) = invite_token {
        if token.len() > 128 {
            return Err(invitation_invalid());
        }
        let token_hash = hash_invite_token(token);
        let invite = sqlx::query_scalar!(
            "SELECT id FROM instance_invites WHERE token_hash = $1 AND email = $2 \
             AND used_at = 0 AND expires_at > $3",
            token_hash,
            email,
            now_ms(),
        )
        .fetch_optional(&mut *conn)
        .await?;
        if let Some(id) = invite {
            grant.invite_id = Some(id);
            return Ok(grant);
        }
        // A pending invitation to an organization for this email allows
        // registering too; it is accepted after sign-in. The lookup goes
        // through a function: signed-out requests cannot read invitations.
        let org_invite = sqlx::query_scalar!(
            r#"SELECT passbox.org_invitation_pending($1, $2, $3) AS "pending!""#,
            token_hash,
            email,
            now_ms(),
        )
        .fetch_one(&mut *conn)
        .await?;
        return if org_invite {
            Ok(grant)
        } else {
            Err(invitation_invalid())
        };
    }
    if is_env_admin(state, email) {
        return Ok(grant);
    }
    let any_account = sqlx::query_scalar!(r#"SELECT 1 AS "one!" FROM accounts LIMIT 1"#)
        .fetch_optional(&mut *conn)
        .await?;
    if any_account.is_none() {
        // The first account sets up the server.
        return Ok(grant);
    }
    let settings = load_settings(conn).await?;
    match settings.registration {
        RegistrationMode::Open => Ok(grant),
        RegistrationMode::InviteOnly => Err(ApiError::forbidden(
            "registration_closed",
            "registration on this server requires an invitation",
        )),
        RegistrationMode::Domains => {
            let domain = email.rsplit_once('@').map(|(_, d)| d).unwrap_or_default();
            if settings.allowed_domains.iter().any(|d| d == domain) {
                Ok(grant)
            } else {
                Err(ApiError::forbidden(
                    "domain_not_allowed",
                    "accounts with this email domain cannot be created on this server",
                ))
            }
        }
    }
}

fn invitation_invalid() -> ApiError {
    ApiError::forbidden(
        "invitation_invalid",
        "this invitation is invalid, expired or already used",
    )
}

/// Runs inside the transaction that creates an account, after the
/// account row was inserted (still in the sign-up context): marks the
/// invitation as used, then switches the transaction to the new account,
/// stores the language and makes the first account of the server instance
/// admin. Returns whether the account became admin.
pub async fn on_account_created(
    tx: &mut Tx,
    account_id: &str,
    grant: &RegistrationGrant,
    locale: Option<Locale>,
    now: i64,
) -> ApiResult<bool> {
    if let Some(invite_id) = &grant.invite_id {
        let used = sqlx::query!(
            "UPDATE instance_invites SET used_at = $1 WHERE id = $2 AND used_at = 0",
            now,
            invite_id,
        )
        .execute(&mut **tx)
        .await?;
        if used.rows_affected() == 0 {
            return Err(invitation_invalid());
        }
    }
    crate::db::switch_to_account(tx, account_id).await?;
    if let Some(locale) = locale {
        sqlx::query!(
            "UPDATE accounts SET locale = $1 WHERE id = $2",
            locale.as_str(),
            account_id,
        )
        .execute(&mut **tx)
        .await?;
    }
    // Only one account can insert the marker; a concurrent registration
    // waits for this transaction and then inserts nothing. The function
    // is the only way to set `instance_admin` (the app role cannot update
    // that column).
    let first = sqlx::query_scalar!(r#"SELECT passbox.claim_first_admin($1) AS "first!""#, now)
        .fetch_one(&mut **tx)
        .await?;
    Ok(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_are_normalized_and_checked() {
        let settings = InstanceSettings {
            instance_name: "  ACME Vault ".to_owned(),
            registration: RegistrationMode::Domains,
            allowed_domains: vec!["@Example.com".into(), "example.com".into(), " ".into()],
            ..InstanceSettings::default()
        }
        .validated()
        .unwrap();
        assert_eq!(settings.instance_name, "ACME Vault");
        assert_eq!(settings.allowed_domains, ["example.com"]);

        let bad = |settings: InstanceSettings| settings.validated().is_err();
        assert!(bad(InstanceSettings {
            registration: RegistrationMode::Domains,
            ..InstanceSettings::default()
        }));
        assert!(bad(InstanceSettings {
            allowed_domains: vec!["not a domain".into()],
            ..InstanceSettings::default()
        }));
        assert!(bad(InstanceSettings {
            support_url: "javascript:alert(1)".into(),
            ..InstanceSettings::default()
        }));
        assert!(bad(InstanceSettings {
            password_policy: PasswordPolicy {
                min_score: 2,
                min_length: 12
            },
            ..InstanceSettings::default()
        }));
        assert!(bad(InstanceSettings {
            instance_name: String::new(),
            ..InstanceSettings::default()
        }));
    }

    #[test]
    fn settings_parse_with_missing_fields() {
        let settings: InstanceSettings =
            serde_json::from_str(r#"{"registration":"invite_only"}"#).unwrap();
        assert_eq!(settings.registration, RegistrationMode::InviteOnly);
        assert_eq!(settings.instance_name, "Passbox");
    }
}
