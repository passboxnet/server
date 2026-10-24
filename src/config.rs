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
        }
    }
}
