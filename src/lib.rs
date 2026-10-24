//! The Passbox headless server.
//!
//! The server stores and synchronizes encrypted data. It never receives
//! plaintext secrets or keys that could decrypt them.

pub mod config;
pub mod routes;
pub mod telemetry;

use anyhow::Context;
use tokio::net::TcpListener;
use tracing::info;

use crate::config::Config;

/// Starts the HTTP server and runs until it receives a shutdown signal.
pub async fn serve(config: Config) -> anyhow::Result<()> {
    let app = routes::router(&config);
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
