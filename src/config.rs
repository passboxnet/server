use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, ValueEnum};

/// Passbox server configuration. Every option can also be set through an
/// environment variable.
#[derive(Debug, Clone, Parser)]
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

    /// Log output format.
    #[arg(long, env = "PASSBOX_LOG_FORMAT", value_enum, default_value_t = LogFormat::Pretty)]
    pub log_format: LogFormat,
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
            log_format: LogFormat::Pretty,
        }
    }
}
