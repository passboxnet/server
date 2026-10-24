//! The `/api/v1` HTTP API.

pub mod account;
pub mod admin;
pub mod auth;
pub mod items;
pub mod notify;
pub mod preferences;
pub mod sessions;
pub mod sync;
pub mod two_factor;
pub mod validate;
pub mod vaults;

use axum::Router;
use axum::routing::{delete, get, post, put};

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/prelogin", post(auth::prelogin))
        .route("/auth/register/start", post(auth::register_start))
        .route("/auth/register/finish", post(auth::register_finish))
        .route("/auth/login/start", post(auth::login_start))
        .route("/auth/login/finish", post(auth::login_finish))
        .route("/auth/login/two-factor", post(two_factor::login_two_factor))
        .route("/auth/logout", post(auth::logout))
        .route("/account", get(auth::account))
        .route("/account/two-factor", get(two_factor::status))
        .route("/account/two-factor/totp", delete(two_factor::totp_remove))
        .route(
            "/account/two-factor/totp/start",
            post(two_factor::totp_start),
        )
        .route(
            "/account/two-factor/totp/confirm",
            post(two_factor::totp_confirm),
        )
        .route(
            "/account/two-factor/webauthn/register/start",
            post(two_factor::webauthn_register_start),
        )
        .route(
            "/account/two-factor/webauthn/register/finish",
            post(two_factor::webauthn_register_finish),
        )
        .route(
            "/account/two-factor/webauthn/{id}",
            delete(two_factor::webauthn_remove),
        )
        .route(
            "/account/two-factor/recovery-codes",
            post(two_factor::recovery_codes_regenerate),
        )
        .route(
            "/account/two-factor/challenge",
            post(two_factor::verify_start),
        )
        .route("/account/two-factor/disable", post(two_factor::disable))
        .route("/account/events", get(account::events))
        .route("/account/password/start", post(account::password_start))
        .route("/account/password/finish", post(account::password_finish))
        .route(
            "/account/preferences",
            get(preferences::get).put(preferences::put),
        )
        .route(
            "/admin/settings",
            get(admin::get_settings).put(admin::put_settings),
        )
        .route("/admin/users", get(admin::users))
        .route("/admin/users/{id}/disable", post(admin::disable_user))
        .route("/admin/users/{id}/enable", post(admin::enable_user))
        .route("/admin/mail/test", post(admin::test_mail))
        .route("/admin/events", get(admin::events))
        .route(
            "/admin/invites",
            get(admin::invites).post(admin::create_invite),
        )
        .route("/admin/invites/{id}", delete(admin::revoke_invite))
        .route("/sessions", get(sessions::list))
        .route("/sessions/revoke-others", post(sessions::revoke_others))
        .route("/sessions/{id}", delete(sessions::revoke))
        .route("/sync", get(sync::sync))
        .route("/vaults", post(vaults::create))
        .route("/vaults/{id}", put(vaults::update))
        .route("/items/{id}", put(items::put).delete(items::delete))
}
