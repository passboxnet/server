//! The Passbox headless server.
//!
//! The server stores and synchronizes encrypted data. It never receives
//! plaintext secrets or keys that could decrypt them.

pub mod api;
pub mod config;
pub mod db;
pub mod error;
pub mod instance;
pub mod mail;
pub mod routes;
pub mod security;
pub mod state;
pub mod telemetry;

use anyhow::Context;
use tokio::net::TcpListener;
use tracing::info;

use crate::config::Config;
use crate::state::AppState;

/// Starts the HTTP server and runs until it receives a shutdown signal.
pub async fn serve(config: Config) -> anyhow::Result<()> {
    let db = db::connect(&config.database_url).await?;
    let mut state = AppState::load(db).await?;
    state.trust_proxy = config.trust_proxy;
    state.auth_rate_limit = config.auth_rate_limit;
    state.admin_emails = std::sync::Arc::new(admin_emails(&config.admin_emails));
    if config.icons == config::Switch::Off {
        state.icons = std::sync::Arc::new(api::icons::IconService::new(
            false,
            std::sync::Arc::new(api::icons::HttpIconFetcher::new()),
        ));
    }
    state.mailer = mail::Mailer::new(
        state.db.clone(),
        &mail::MailConfig {
            smtp_url: config.smtp_url.clone(),
            from: config.mail_from.clone(),
            public_url: config.public_url.clone(),
        },
    )?;
    if state.mailer.is_configured() {
        info!("mail is sent over SMTP");
    } else {
        tracing::warn!(
            "PASSBOX_SMTP_URL is not set: mails are written to the log instead of being sent"
        );
    }
    state.mailer.spawn_worker();
    let app = routes::router(&config, state);
    let listener = TcpListener::bind(config.bind)
        .await
        .with_context(|| format!("failed to bind {}", config.bind))?;
    info!(address = %listener.local_addr()?, version = env!("CARGO_PKG_VERSION"), "passbox server listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("server error")
}

/// Normalizes `PASSBOX_ADMIN_EMAILS` entries like account emails.
fn admin_emails(raw: &[String]) -> Vec<String> {
    raw.iter()
        .map(|email| email.trim().to_lowercase())
        .filter(|email| !email.is_empty())
        .collect()
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    info!("shutdown signal received");
}
