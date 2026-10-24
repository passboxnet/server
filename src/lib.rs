//! The Passbox headless server.
//!
//! The server stores and synchronizes encrypted data. It never receives
//! plaintext secrets or keys that could decrypt them.

pub mod api;
pub mod config;
pub mod db;
pub mod error;
pub mod routes;
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
    let state = AppState::load(db).await?;
    let app = routes::router(&config, state);
    let listener = TcpListener::bind(config.bind)
        .await
        .with_context(|| format!("failed to bind {}", config.bind))?;
    info!(address = %listener.local_addr()?, version = env!("CARGO_PKG_VERSION"), "passbox server listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")
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
