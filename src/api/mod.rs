//! The `/api/v1` HTTP API.

pub mod auth;
pub mod items;
pub mod sync;
pub mod validate;
pub mod vaults;

use axum::Router;
use axum::routing::{get, post, put};

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/prelogin", post(auth::prelogin))
        .route("/auth/register/start", post(auth::register_start))
        .route("/auth/register/finish", post(auth::register_finish))
        .route("/auth/login/start", post(auth::login_start))
        .route("/auth/login/finish", post(auth::login_finish))
        .route("/auth/logout", post(auth::logout))
        .route("/account", get(auth::account))
        .route("/sync", get(sync::sync))
        .route("/vaults", post(vaults::create))
        .route("/vaults/{id}", put(vaults::update))
        .route("/items/{id}", put(items::put).delete(items::delete))
}
