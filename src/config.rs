use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, ValueEnum};

/// Passbox server configuration. Every option can also be set through an
/// environment variable.
#[derive(Clone, Parser)]
#[command(name = "passbox-server", version, about)]
pub struct Config {
    /// Address to listen on.
    #[arg(long, env = "PASSBOX_BIND", default_value = "0.0.0.0:8080")]
    pub bind: SocketAddr,

    /// Database URL: `sqlite://path/to/passbox.db?mode=rwc` or `postgres://user:pass@host/db`.
    #[arg(
        long,
        env = "PASSBOX_DATABASE_URL",
        default_value = "sqlite://passbox.db?mode=rwc"
    )]
    pub database_url: String,

    /// Directory with the built web client. When set, the server also serves the web app.
    #[arg(long, env = "PASSBOX_WEB_DIR")]
    pub web_dir: Option<PathBuf>,

    /// Use the first address of `X-Forwarded-For` as the client IP. Enable
    /// only behind a reverse proxy that sets this header.
    #[arg(long, env = "PASSBOX_TRUST_PROXY", default_value_t = false)]
    pub trust_proxy: bool,

    /// Sign-in and registration requests allowed per client IP and minute.
    /// Raise it only for test servers that many clients share.
    #[arg(long, env = "PASSBOX_AUTH_RATE_LIMIT", default_value_t = 60)]
    pub auth_rate_limit: u32,

    /// SMTP server for outgoing mail, for example
    /// `smtps://user:password@mail.example.com:465` (implicit TLS) or
    /// `smtp://user:password@mail.example.com:587?tls=required` (STARTTLS).
    /// Without it, mails are written to the log instead of being sent.
    #[arg(long, env = "PASSBOX_SMTP_URL", hide_env_values = true)]
    pub smtp_url: Option<String>,

    /// Sender address of outgoing mail, for example `Passbox <passbox@example.com>`.
    #[arg(long, env = "PASSBOX_MAIL_FROM")]
    pub mail_from: Option<String>,

    /// Public address of this server, for example `https://passbox.example.com`.
    /// Used for links in mails.
    #[arg(long, env = "PASSBOX_PUBLIC_URL")]
    pub public_url: Option<String>,

    /// Emails of accounts that are always instance admins (comma-separated),
    /// in addition to the first account created on the server.
    #[arg(long, env = "PASSBOX_ADMIN_EMAILS", value_delimiter = ',')]
    pub admin_emails: Vec<String>,

    /// Website icons: `on` lets signed-in clients load icons through
    /// `/api/v1/icons/{domain}` (the server then learns which domains are in
    /// vaults), `off` disables the endpoint.
    #[arg(long, env = "PASSBOX_ICONS", value_enum, default_value_t = Switch::On)]
    pub icons: Switch,

    /// Log output format.
    #[arg(long, env = "PASSBOX_LOG_FORMAT", value_enum, default_value_t = LogFormat::Pretty)]
    pub log_format: LogFormat,

    /// Let organization webhooks (audit log push) reach private and local
    /// addresses, for a SIEM in the same network. Off by default, so that
    /// organization admins cannot make the server call internal services.
    #[arg(long, env = "PASSBOX_WEBHOOK_ALLOW_PRIVATE", default_value_t = false)]
    pub webhook_allow_private: bool,

    /// Directory for encrypted file attachments. Back it up together with
    /// the database.
    #[arg(long, env = "PASSBOX_BLOB_DIR", default_value = "blobs")]
    pub blob_dir: PathBuf,

    /// Largest attachment in MiB.
    #[arg(long, env = "PASSBOX_ATTACHMENT_MAX_MB", default_value_t = 100)]
    pub attachment_max_mb: u64,

    /// Attachment storage per account (personal vaults) in MiB; 0 = unlimited.
    #[arg(long, env = "PASSBOX_ATTACHMENT_QUOTA_MB", default_value_t = 0)]
    pub attachment_quota_mb: u64,

    /// Attachment storage per organization (shared vaults) in MiB; 0 = unlimited.
    #[arg(long, env = "PASSBOX_ORG_ATTACHMENT_QUOTA_MB", default_value_t = 0)]
    pub org_attachment_quota_mb: u64,

    /// AI agents and service accounts per member (fair use; they never
    /// count as members). An account may own this many active service
    /// accounts; members of an organization share a pool of this number
    /// times the organization's members (guests do not count). 0 =
    /// unlimited, the default for self-hosting; the hosted service uses 10.
    /// Instance admins can override it in the admin console.
    #[arg(long, env = "PASSBOX_AGENT_LIMIT_PER_MEMBER", default_value_t = 0)]
    pub agent_limit_per_member: u32,
    /// Have I Been Pwned "Pwned Passwords" through this server: `on` lets
    /// signed-in clients check passwords via `/api/v1/breach/range/{prefix}`
    /// (k-anonymity; the server sees only 5-character hash prefixes and Have
    /// I Been Pwned sees the server's IP instead of the user's), `off`
    /// disables the endpoint.
    #[arg(long, env = "PASSBOX_BREACH_PROXY", value_enum, default_value_t = Switch::On)]
    pub breach_proxy: Switch,

    /// Have I Been Pwned API key for email breach monitoring. Without it,
    /// monitoring is off. Users opt in per confirmed address; the addresses
    /// are sent to Have I Been Pwned.
    #[arg(long, env = "PASSBOX_HIBP_API_KEY", hide_env_values = true)]
    pub hibp_api_key: Option<String>,

    /// Hours between checks of each monitored email address.
    #[arg(long, env = "PASSBOX_HIBP_CHECK_HOURS", default_value_t = 24)]
    pub hibp_check_hours: u64,

    /// Breached-account requests per minute your Have I Been Pwned
    /// subscription allows.
    #[arg(long, env = "PASSBOX_HIBP_RPM", default_value_t = 10)]
    pub hibp_rpm: u32,

    /// Pwned Passwords range endpoint (for mirrors and tests).
    #[arg(long, env = "PASSBOX_PWNED_PASSWORDS_URL", default_value = crate::api::breach::DEFAULT_RANGE_URL, hide = true)]
    pub pwned_passwords_url: String,

    /// Have I Been Pwned API base (for tests).
    #[arg(long, env = "PASSBOX_HIBP_API_URL", default_value = crate::api::breach::DEFAULT_API_URL, hide = true)]
    pub hibp_api_url: String,
}

/// Hides the database and SMTP credentials.
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("bind", &self.bind)
            .field("database_url", &"<redacted>")
            .field("web_dir", &self.web_dir)
            .field("trust_proxy", &self.trust_proxy)
            .field("auth_rate_limit", &self.auth_rate_limit)
            .field("smtp_url", &self.smtp_url.as_ref().map(|_| "<redacted>"))
            .field("mail_from", &self.mail_from)
            .field("public_url", &self.public_url)
            .field("admin_emails", &self.admin_emails)
            .field("icons", &self.icons)
            .field("log_format", &self.log_format)
            .field("webhook_allow_private", &self.webhook_allow_private)
            .field("blob_dir", &self.blob_dir)
            .field("attachment_max_mb", &self.attachment_max_mb)
            .field("attachment_quota_mb", &self.attachment_quota_mb)
            .field("org_attachment_quota_mb", &self.org_attachment_quota_mb)
            .field("agent_limit_per_member", &self.agent_limit_per_member)
            .field("breach_proxy", &self.breach_proxy)
            .field(
                "hibp_api_key",
                &self.hibp_api_key.as_ref().map(|_| "<redacted>"),
            )
            .field("hibp_check_hours", &self.hibp_check_hours)
            .field("hibp_rpm", &self.hibp_rpm)
            .field("pwned_passwords_url", &self.pwned_passwords_url)
            .field("hibp_api_url", &self.hibp_api_url)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Switch {
    On,
    Off,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    Pretty,
    Json,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 8080)),
            database_url: "sqlite::memory:".to_owned(),
            web_dir: None,
            trust_proxy: false,
            auth_rate_limit: 60,
            smtp_url: None,
            mail_from: None,
            public_url: None,
            admin_emails: Vec::new(),
            icons: Switch::On,
            log_format: LogFormat::Pretty,
            webhook_allow_private: false,
            blob_dir: PathBuf::from("blobs"),
            attachment_max_mb: 100,
            attachment_quota_mb: 0,
            org_attachment_quota_mb: 0,
            agent_limit_per_member: 0,
            breach_proxy: Switch::On,
            hibp_api_key: None,
            hibp_check_hours: 24,
            hibp_rpm: 10,
            pwned_passwords_url: crate::api::breach::DEFAULT_RANGE_URL.to_owned(),
            hibp_api_url: crate::api::breach::DEFAULT_API_URL.to_owned(),
        }
    }
}
