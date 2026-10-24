use std::time::Duration;

use axum::extract::State;
use axum::http::{Method, header};
use axum::routing::get;
use axum::{Json, Router};
use passbox_core::kdf::KdfParams;
use serde::Serialize;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

use crate::config::Config;
use crate::error::ApiResult;
use crate::instance::{PasswordPolicy, RegistrationMode};
use crate::mail::Locale;
use crate::state::AppState;

/// Builds the application router.
pub fn router(config: &Config, state: AppState) -> Router {
    let api = crate::api::router().route("/meta", get(meta));

    let mut app = Router::new()
        .route("/health", get(health))
        .nest("/api/v1", api)
        .with_state(state)
        .layer(cors());

    if let Some(dir) = &config.web_dir {
        // Unknown paths fall back to index.html so client-side routing works.
        let spa = ServeDir::new(dir).fallback(ServeFile::new(dir.join("index.html")));
        app = app.fallback_service(spa);
    }

    app.layer(axum::middleware::from_fn(crate::security::security_headers))
        .layer(TraceLayer::new_for_http())
}

/// Lets clients on other origins (the desktop app, a web client served
/// elsewhere) call the API.
///
/// The API authenticates with bearer tokens, never with cookies, so allowing
/// any origin is safe: a foreign page can only send requests with a token it
/// already has. Credentials (cookies, HTTP auth) are never allowed.
fn cors() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .max_age(Duration::from_secs(60 * 60))
}

#[derive(Debug, Serialize)]
struct Health {
    status: &'static str,
}

async fn health() -> Json<Health> {
    Json(Health { status: "ok" })
}

/// Public server information that clients need before signing in.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Meta {
    name: &'static str,
    version: &'static str,
    api_version: u32,
    /// Lowest KDF parameters the server accepts for new accounts. Clients
    /// enforce their own minimum as well.
    min_kdf_params: KdfParams,
    /// Name the admins gave this server.
    instance_name: String,
    /// Who may create an account: `open`, `invite_only` or `domains`.
    registration: RegistrationMode,
    /// In `domains` mode: the email domains that may register.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    allowed_domains: Vec<String>,
    /// Where users get help (`null` if not set).
    support_url: Option<String>,
    default_locale: Locale,
    /// Minimum strength of new master passwords; clients enforce it.
    password_policy: PasswordPolicy,
    /// Whether `/api/v1/icons/{domain}` serves website icons.
    icons: bool,
    /// Whether `/api/v1/breach/range/{prefix}` proxies Have I Been Pwned.
    breach_proxy: bool,
    /// Whether email breach monitoring is available (`/api/v1/breach/emails`).
    email_monitoring: bool,
}

async fn meta(State(state): State<AppState>) -> ApiResult<Json<Meta>> {
    let settings = crate::instance::load_settings(&state.db).await?;
    Ok(Json(Meta {
        name: "passbox",
        version: env!("CARGO_PKG_VERSION"),
        api_version: 1,
        min_kdf_params: KdfParams::MINIMUM,
        instance_name: settings.instance_name,
        allowed_domains: if settings.registration == RegistrationMode::Domains {
            settings.allowed_domains
        } else {
            Vec::new()
        },
        registration: settings.registration,
        support_url: Some(settings.support_url).filter(|url| !url.is_empty()),
        default_locale: settings.default_locale,
        password_policy: settings.password_policy,
        icons: state.icons.enabled,
        breach_proxy: state.breach.proxy,
        email_monitoring: state.breach.monitoring,
    }))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;

    async fn app() -> Router {
        let db = crate::db::connect("sqlite::memory:").await.unwrap();
        router(&Config::default(), AppState::load(db).await.unwrap())
    }

    async fn get_json(app: Router, uri: &str) -> (StatusCode, Value) {
        let response = app
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    #[tokio::test]
    async fn health_is_ok() {
        let (status, body) = get_json(app().await, "/health").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ok");
    }

    #[tokio::test]
    async fn meta_reports_version_and_kdf_minimum() {
        let (status, body) = get_json(app().await, "/api/v1/meta").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["apiVersion"], 1);
        assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(body["minKdfParams"]["memoryKib"], 65536);
        assert_eq!(body["registration"], "open");
        assert_eq!(body["instanceName"], "Passbox");
        assert_eq!(body["passwordPolicy"]["minScore"], 3);
        assert_eq!(body["supportUrl"], Value::Null);
        assert_eq!(body["icons"], true);
        assert_eq!(body["breachProxy"], true);
        assert_eq!(body["emailMonitoring"], false);
    }

    #[tokio::test]
    async fn unknown_route_is_not_found_without_web_dir() {
        let (status, _) = get_json(app().await, "/does-not-exist").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
