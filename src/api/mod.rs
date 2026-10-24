//! The `/api/v1` HTTP API.

pub mod access;
pub mod account;
pub mod admin;
pub mod auth;
pub mod groups;
pub mod items;
pub mod keys;
pub mod notify;
pub mod orgs;
pub mod preferences;
pub mod sessions;
pub mod shared;
pub mod signed;
pub mod sync;
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
        .route("/auth/logout", post(auth::logout))
        .route("/account", get(auth::account))
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
        // Account key pairs and the key directory.
        .route("/account/keys", get(keys::own).put(keys::publish))
        .route("/keys/head", get(keys::head))
        .route("/keys/log", get(keys::log))
        .route("/keys/{account_id}", get(keys::lookup))
        // Organizations, members and invitations.
        .route("/orgs", get(orgs::list).post(orgs::create))
        .route(
            "/orgs/{org_id}",
            get(orgs::get).put(orgs::update).delete(orgs::delete),
        )
        .route("/orgs/{org_id}/rotate-key", post(orgs::rotate_key))
        .route(
            "/orgs/{org_id}/invitations",
            get(orgs::invitations).post(orgs::invite),
        )
        .route(
            "/orgs/{org_id}/invitations/{invitation_id}",
            delete(orgs::revoke_invitation),
        )
        .route(
            "/orgs/{org_id}/members/{account_id}",
            put(orgs::update_member).delete(orgs::remove_member),
        )
        .route(
            "/orgs/{org_id}/members/{account_id}/confirm",
            post(orgs::confirm),
        )
        .route(
            "/orgs/{org_id}/members/{account_id}/suspend",
            post(orgs::suspend),
        )
        .route(
            "/orgs/{org_id}/members/{account_id}/reactivate",
            post(orgs::reactivate),
        )
        .route("/invitations/accept", post(orgs::accept))
        .route("/invitations/{token}", get(orgs::preview))
        // Groups.
        .route(
            "/orgs/{org_id}/groups",
            get(groups::list).post(groups::create),
        )
        .route(
            "/orgs/{org_id}/groups/{group_id}",
            put(groups::update).delete(groups::delete),
        )
        .route(
            "/orgs/{org_id}/groups/{group_id}/members",
            post(groups::add_member),
        )
        .route(
            "/orgs/{org_id}/groups/{group_id}/rotate",
            post(groups::rotate),
        )
        // Shared vaults.
        .route("/orgs/{org_id}/vaults", post(shared::create))
        .route(
            "/vaults/{id}/members",
            get(shared::members).post(shared::put_member),
        )
        .route("/vaults/{id}/rotate", post(shared::rotate))
        .route(
            "/vaults/{id}/keys/{epoch}/wrapped",
            put(shared::put_wrapped_key),
        )
        .route("/vaults/{id}/items/batch", post(shared::batch_items))
}
