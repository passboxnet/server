use std::time::Duration;

use axum::extract::State;
use axum::http::{Method, StatusCode, header};
use axum::routing::get;
use axum::{Json, Router};
use passbox_core::kdf::KdfParams;
use serde::Serialize;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

use crate::config::Config;
use crate::error::ApiResult;
use crate::ext::Extensions;
use crate::instance::{PasswordPolicy, RegistrationMode};
use crate::mail::Locale;
use crate::state::AppState;

/// Builds the application router.
pub fn router(config: &Config, state: AppState) -> Router {
    router_with(config, state, &Extensions::default())
}

/// Builds the application router with the gate, meta hook and routes of
/// `ext`. Extension routes are merged at the root (give them their full
/// path, such as `/api/v1/billing/...`) before the state is attached.
pub fn router_with(config: &Config, mut state: AppState, ext: &Extensions) -> Router {
    ext.install(&mut state);
    let api = crate::api::router().route("/meta", get(meta));

    let metrics = state.metrics.clone();
    let mut app = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .nest("/api/v1", api)
        // Email logos and the typeface of the server's own pages.
        .merge(crate::brand::routes());
    if let Some(routes) = &ext.routes {
        app = app.merge(routes(&state));
    }
    if config.web_dir.is_none() {
        // Without a web vault the server answers browsers with its own pages.
        app = app.fallback(crate::brand::pages::fallback);
    }
    let mut app = app.with_state(state).layer(cors());

    if let Some(dir) = &config.web_dir {
        // Unknown paths fall back to index.html so client-side routing works.
        let spa = ServeDir::new(dir).fallback(ServeFile::new(dir.join("index.html")));
        app = app.fallback_service(spa);
    }

    app.layer(axum::middleware::from_fn(crate::security::security_headers))
        .layer(axum::middleware::from_fn_with_state(
            metrics,
            crate::metrics::track,
        ))
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &axum::extract::Request| {
                tracing::debug_span!(
                    "request",
                    method = %request.method(),
                    uri = %loggable_uri(request.uri()),
                    version = ?request.version(),
                )
            }),
        )
}

/// The request URI as it may appear in logs. Website icon requests show
/// the route instead of the domain: request logs can be tied to sessions
/// and IP addresses, and the domains are the sites someone keeps logins for.
pub fn loggable_uri(uri: &axum::http::Uri) -> std::borrow::Cow<'_, str> {
    let path = uri.path();
    if path.starts_with("/api/v1/icons/") {
        return std::borrow::Cow::Borrowed("/api/v1/icons/{domain}");
    }
    match uri.path_and_query() {
        Some(path_and_query) => std::borrow::Cow::Borrowed(path_and_query.as_str()),
        None => std::borrow::Cow::Borrowed(path),
    }
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
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::IF_NONE_MATCH,
        ])
        .expose_headers([header::ETAG])
        .max_age(Duration::from_secs(60 * 60))
}

#[derive(Debug, Serialize)]
struct Health {
    status: &'static str,
}

async fn health() -> Json<Health> {
    Json(Health { status: "ok" })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Readiness {
    status: &'static str,
    /// The applied migration version.
    #[serde(skip_serializing_if = "Option::is_none")]
    migration: Option<i64>,
    /// Why the server is not ready.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

/// Readiness: the database answers and has the migrations this binary
/// expects. Load balancers send traffic only while it returns 200.
async fn ready(State(state): State<AppState>) -> (StatusCode, Json<Readiness>) {
    match state.db.readiness().await {
        Ok(version) => (
            StatusCode::OK,
            Json(Readiness {
                status: "ready",
                migration: Some(version),
                reason: None,
            }),
        ),
        Err(err) => {
            tracing::warn!(error = %err, "not ready");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(Readiness {
                    status: "unavailable",
                    migration: None,
                    reason: Some(err.to_string()),
                }),
            )
        }
    }
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
    /// Whether `/api/v1/breaches/catalog` serves the breach catalogue.
    breach_catalog: bool,
    /// `PASSBOX_FAMILY_MEMBER_LIMIT`, if set: most owners, admins and members
    /// of a family including pending invitations (guests do not count).
    #[serde(skip_serializing_if = "Option::is_none")]
    family_member_limit: Option<u32>,
    /// Information from the extensions of an embedding program.
    #[serde(skip_serializing_if = "Option::is_none")]
    extensions: Option<serde_json::Value>,
}

async fn meta(State(state): State<AppState>) -> ApiResult<Json<Meta>> {
    let settings = crate::instance::load_settings_from(&state.db).await?;
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
        breach_catalog: state.breach_catalog.enabled,
        family_member_limit: Some(state.family_member_limit).filter(|limit| *limit > 0),
        extensions: state.ext_meta.as_ref().map(|meta| meta()),
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

    async fn app() -> (Router, crate::testing::TestDatabase) {
        let database = crate::testing::TestDatabase::create().await;
        let state = AppState::load(database.db.clone()).await.unwrap();
        (router(&Config::default(), state), database)
    }

    async fn get_json(
        (app, _database): (Router, crate::testing::TestDatabase),
        uri: &str,
    ) -> (StatusCode, Value) {
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
    async fn ready_reports_the_migration() {
        let (status, body) = get_json(app().await, "/ready").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ready");
        assert_eq!(body["migration"], crate::db::expected_version());
    }

    #[tokio::test]
    async fn unknown_route_is_not_found_without_web_dir() {
        let (status, _) = get_json(app().await, "/does-not-exist").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn browsers_get_branded_pages_without_web_dir() {
        let (app, _database) = app().await;
        let get = |uri: &str, accept: &str, language: &str| {
            Request::get(uri)
                .header("accept", accept)
                .header("accept-language", language)
                .header("host", "vault.example.com")
                .body(Body::empty())
                .unwrap()
        };
        let html = "text/html,application/xhtml+xml";
        let response = app
            .clone()
            .oneshot(get("/does-not-exist", html, "de-DE"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(
            response.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("Seite nicht gefunden"), "{body}");
        assert!(body.contains("lang=\"de\""));

        let response = app.clone().oneshot(get("/", html, "en")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("Passbox is running"), "{body}");
        assert!(body.contains("https://vault.example.com"));

        // API clients keep getting a plain 404.
        let response = app.oneshot(get("/api/v1/nope", html, "en")).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(response.headers().get("content-type").is_none());
    }

    #[tokio::test]
    async fn brand_assets_are_served() {
        let (app, _database) = app().await;
        for (uri, content_type) in [
            ("/assets/mail/logo-light.png", "image/png"),
            ("/assets/mail/logo-dark.png", "image/png"),
            ("/assets/brand/plus-jakarta-sans-latin.woff2", "font/woff2"),
            (
                "/assets/brand/plus-jakarta-sans-latin-ext.woff2",
                "font/woff2",
            ),
        ] {
            let response = app
                .clone()
                .oneshot(Request::get(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{uri}");
            assert_eq!(response.headers()["content-type"], content_type);
            assert!(
                response.headers()["cache-control"]
                    .to_str()
                    .unwrap()
                    .contains("max-age")
            );
        }
    }

    #[test]
    fn icon_domains_stay_out_of_request_logs() {
        let uri = |s: &str| s.parse::<axum::http::Uri>().unwrap();
        assert_eq!(
            loggable_uri(&uri("/api/v1/icons/netflix.com")),
            "/api/v1/icons/{domain}"
        );
        assert_eq!(
            loggable_uri(&uri("/api/v1/items/abc?x=1")),
            "/api/v1/items/abc?x=1"
        );
    }
}
