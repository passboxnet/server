//! The `/api/v1` HTTP API.

pub mod access;
pub mod account;
pub mod admin;
pub mod auth;
pub mod device_links;
pub mod emergency;
pub mod groups;
pub mod icons;
pub mod items;
pub mod keys;
pub mod notify;
pub mod org_recovery;
pub mod orgs;
pub mod preferences;
pub mod recovery;
pub mod sessions;
pub mod shared;
pub mod signed;
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
        .route("/items/{id}/versions", get(items::versions))
        .route("/icons/{domain}", get(icons::get))
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
        // Account recovery: recovery code (signed in and signed out).
        .route("/account/recovery", get(recovery::status))
        .route(
            "/account/recovery-code",
            post(recovery::code_finish).delete(recovery::code_delete),
        )
        .route("/account/recovery-code/start", post(recovery::code_start))
        .route("/recovery/code/start", post(recovery::login_start))
        .route("/recovery/code/finish", post(recovery::login_finish))
        .route("/recovery/two-factor", post(recovery::two_factor))
        .route("/recovery/complete/start", post(recovery::complete_start))
        .route("/recovery/complete/finish", post(recovery::complete_finish))
        // Organization recovery: the requesting device.
        .route("/recovery/org/request", post(recovery::org_request))
        .route("/recovery/org/status", post(recovery::org_status))
        .route("/recovery/org/cancel", post(recovery::org_cancel))
        // Organization recovery: the organization.
        .route("/orgs/{org_id}/recovery", get(org_recovery::get))
        .route(
            "/orgs/{org_id}/recovery/keys",
            post(org_recovery::create_key),
        )
        .route(
            "/orgs/{org_id}/recovery/grants",
            post(org_recovery::add_grant),
        )
        .route(
            "/orgs/{org_id}/recovery/escrow",
            put(org_recovery::put_escrow).delete(org_recovery::delete_escrow),
        )
        .route(
            "/orgs/{org_id}/recovery/requests",
            get(org_recovery::requests),
        )
        .route(
            "/orgs/{org_id}/recovery/requests/{request_id}/approve",
            post(org_recovery::approve),
        )
        .route(
            "/orgs/{org_id}/recovery/requests/{request_id}/deny",
            post(org_recovery::deny),
        )
        // Emergency access.
        .route("/emergency", get(emergency::list))
        .route("/emergency/grants", post(emergency::create))
        .route("/emergency/grants/{id}", delete(emergency::delete))
        .route("/emergency/grants/{id}/accept", post(emergency::accept))
        .route("/emergency/grants/{id}/confirm", post(emergency::confirm))
        .route("/emergency/grants/{id}/request", post(emergency::request))
        .route("/emergency/grants/{id}/approve", post(emergency::approve))
        .route("/emergency/grants/{id}/deny", post(emergency::deny))
        .route("/emergency/grants/{id}/access", get(emergency::access))
        // Adding a device by code.
        .route("/device-links", post(device_links::create))
        .route("/device-links/claim", post(device_links::claim))
        .route("/device-links/poll", post(device_links::poll))
        .route(
            "/device-links/{id}",
            get(device_links::get).delete(device_links::delete),
        )
        .route("/device-links/{id}/approve", post(device_links::approve))
}
