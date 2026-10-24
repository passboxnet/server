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

    /// Directory with the built web client. When set, the server also serves the web app.
    #[arg(long, env = "PASSBOX_WEB_DIR")]
    pub web_dir: Option<PathBuf>,

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
            web_dir: None,
            log_format: LogFormat::Pretty,
        }
    }
}
