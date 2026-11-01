//! The Passbox headless server.
//!
//! The server stores and synchronizes encrypted data. It never receives
//! plaintext secrets or keys that could decrypt them.

pub mod api;
pub mod blobs;
pub mod brand;
pub mod config;
pub mod db;
pub mod error;
pub mod instance;
pub mod mail;
pub mod metrics;
pub mod routes;
pub mod security;
pub mod state;
pub mod telemetry;
#[doc(hidden)]
pub mod testing;

use anyhow::Context;
use tokio::net::TcpListener;
use tracing::info;

use crate::config::{Command, Config};
use crate::state::AppState;

/// Runs the command of the configuration (`serve` by default).
pub async fn run(config: Config) -> anyhow::Result<()> {
    match config.command.unwrap_or(Command::Serve) {
        Command::Migrate => {
            db::migrate(config.migration_url()).await?;
            info!(version = db::expected_version(), "database migrated");
            Ok(())
        }
        Command::Serve => serve(config).await,
    }
}

/// Starts the HTTP server and runs until it receives a shutdown signal.
pub async fn serve(config: Config) -> anyhow::Result<()> {
    if config.auto_migrate {
        db::migrate(config.migration_url()).await?;
    }
    let db = db::Db::connect(&config.database_urls()).await?;
    db.warn_unless_rls_enforced().await;
    if let Err(err) = db.readiness().await {
        tracing::warn!(error = %err, "the database is not ready");
    }
    let mut state = AppState::load(db).await?;
    state.trust_proxy = config.trust_proxy;
    state.auth_rate_limit = config.auth_rate_limit;
    state.admin_emails = std::sync::Arc::new(admin_emails(&config.admin_emails));
    state.webhook_allow_private = config.webhook_allow_private;
    state.agent_limit_per_member = config.agent_limit_per_member;
    state.blobs = std::sync::Arc::new(blobs::DiskBlobStore::new(&config.blob_dir));
    state.attachment_limits = api::attachments::AttachmentLimits::from_mib(
        config.attachment_max_mb,
        config.attachment_quota_mb,
        config.org_attachment_quota_mb,
    );
    if config.icons == config::Switch::Off {
        state.icons = std::sync::Arc::new(api::icons::IconService::new(
            false,
            std::sync::Arc::new(api::icons::HttpIconFetcher::new()),
        ));
    }
    {
        let upstream = std::sync::Arc::new(api::breach::HttpUpstream::new(
            &config.pwned_passwords_url,
            &config.hibp_api_url,
            config
                .hibp_api_key
                .clone()
                .filter(|key| !key.trim().is_empty()),
        ));
        let mut breach = api::breach::BreachService::new(
            config.breach_proxy == config::Switch::On,
            config
                .hibp_api_key
                .as_ref()
                .is_some_and(|key| !key.trim().is_empty()),
            upstream,
        );
        breach.check_interval =
            std::time::Duration::from_secs(config.hibp_check_hours.max(1) * 60 * 60);
        breach.requests_per_minute = config.hibp_rpm.max(1);
        if breach.monitoring {
            info!("email breach monitoring is on (Have I Been Pwned)");
        }
        state.breach = std::sync::Arc::new(breach);
    }
    {
        let mut catalog = api::breach_catalog::CatalogService::new(
            config.breach_catalog == config::Switch::On,
            std::sync::Arc::new(api::breach_catalog::HttpCatalogUpstream::new(
                &config.breach_catalog_url,
            )),
        );
        catalog.interval =
            std::time::Duration::from_secs(config.breach_catalog_hours.max(1) * 60 * 60);
        if !catalog.enabled {
            info!("the breach catalogue is off (PASSBOX_BREACH_CATALOG=off)");
        }
        state.breach_catalog = std::sync::Arc::new(catalog);
    }
    state.mailer = mail::Mailer::new(
        state.db.clone(),
        &mail::MailConfig {
            smtp_url: config.smtp_url.clone(),
            camelmailer_api_key: config.camelmailer_api_key.clone(),
            camelmailer_url: config.camelmailer_url.clone(),
            from: config.mail_from.clone(),
            public_url: config.public_url.clone(),
        },
    )?;
    if state.mailer.is_configured() {
        info!("mail is sent over {}", state.mailer.transport_name());
    } else {
        tracing::warn!(
            "no mail transport is set (PASSBOX_SMTP_URL or PASSBOX_CAMELMAILER_API_KEY): mails are written to the log instead of being sent"
        );
    }
    state.mailer.spawn_worker();
    api::sso::oidc::init_from_env();
    api::org_events::spawn_worker(state.clone());
    api::attachments::spawn_sweeper(state.clone());
    api::breach::spawn_worker(state.clone());
    api::icons::spawn_refresher(state.clone());
    api::breach_catalog::spawn_worker(state.clone());
    if let Some(bind) = config.metrics_bind {
        let metrics_app = metrics::router(state.metrics.clone(), state.db.clone());
        let listener = TcpListener::bind(bind)
            .await
            .with_context(|| format!("failed to bind {bind} (PASSBOX_METRICS_BIND)"))?;
        info!(address = %listener.local_addr()?, "metrics listening");
        tokio::spawn(async move {
            if let Err(err) = axum::serve(listener, metrics_app).await {
                tracing::error!(error = %err, "metrics server error");
            }
        });
    }
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
