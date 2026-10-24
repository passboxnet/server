use std::time::Duration;

use axum::http::{Method, header};
use axum::routing::get;
use axum::{Json, Router};
use passbox_core::kdf::KdfParams;
use serde::Serialize;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

use crate::config::Config;
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
}

async fn meta() -> Json<Meta> {
    Json(Meta {
        name: "passbox",
        version: env!("CARGO_PKG_VERSION"),
        api_version: 1,
        min_kdf_params: KdfParams::MINIMUM,
    })
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
    }

    #[tokio::test]
    async fn unknown_route_is_not_found_without_web_dir() {
        let (status, _) = get_json(app().await, "/does-not-exist").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
