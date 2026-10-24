//! The `/api/v1` HTTP API.

pub mod access;
pub mod access_requests;
pub mod account;
pub mod admin;
pub mod agents;
pub mod attachments;
pub mod auth;
pub mod device_links;
pub mod emergency;
pub mod groups;
pub mod icons;
pub mod items;
pub mod keys;
pub mod moves;
pub mod notify;
pub mod org_admin;
pub mod org_audit;
pub mod org_events;
pub mod org_policy;
pub mod org_recovery;
pub mod orgs;
pub mod preferences;
pub mod recovery;
pub mod scim;
pub mod service_accounts;
pub mod sessions;
pub mod share_links;
pub mod shared;
pub mod signed;
pub mod sso;
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
        // Organization administration (wave D): policies, audit log,
        // reports, settings, offboarding, events API and webhooks.
        .route(
            "/orgs/{org_id}/policy",
            get(org_policy::get).put(org_policy::put),
        )
        .route("/orgs/{org_id}/audit", get(org_audit::list))
        .route("/orgs/{org_id}/audit/verify", get(org_audit::verify))
        .route("/orgs/{org_id}/audit/export", get(org_audit::export))
        .route(
            "/orgs/{org_id}/audit/client-events",
            post(org_audit::client_events),
        )
        .route("/orgs/{org_id}/reports", get(org_admin::reports))
        .route(
            "/orgs/{org_id}/security-report",
            put(org_admin::put_security_report),
        )
        .route(
            "/orgs/{org_id}/settings",
            get(org_admin::get_settings).put(org_admin::put_settings),
        )
        .route(
            "/orgs/{org_id}/members/{account_id}/end-sessions",
            post(org_admin::end_sessions),
        )
        .route(
            "/orgs/{org_id}/event-tokens",
            get(org_events::tokens).post(org_events::create_token),
        )
        .route(
            "/orgs/{org_id}/event-tokens/{token_id}",
            delete(org_events::revoke_token),
        )
        .route(
            "/orgs/{org_id}/webhooks",
            get(org_events::webhooks).post(org_events::create_webhook),
        )
        .route(
            "/orgs/{org_id}/webhooks/{webhook_id}",
            delete(org_events::delete_webhook),
        )
        .route("/org-events", get(org_events::pull))
        // Service accounts: the owner.
        .route(
            "/service-accounts",
            get(service_accounts::list).post(service_accounts::create),
        )
        .route(
            "/service-accounts/{id}",
            put(service_accounts::update).delete(service_accounts::delete),
        )
        .route(
            "/service-accounts/{id}/grants",
            put(service_accounts::put_grants),
        )
        .route(
            "/service-accounts/{id}/grants/{vault_id}",
            delete(service_accounts::delete_grant),
        )
        .route(
            "/service-accounts/{id}/revoke",
            post(service_accounts::revoke),
        )
        .route(
            "/service-accounts/{id}/events",
            get(service_accounts::events),
        )
        // Service accounts: the service account itself.
        .route("/service-account", get(service_accounts::state))
        .route(
            "/service-account/items/{id}",
            put(service_accounts::put_item).delete(service_accounts::delete_item),
        )
        .route("/service-account/agent-grants", post(agents::sa_create))
        .route("/service-account/agent-grants/{id}", get(agents::sa_get))
        .route("/service-account/agent-events", post(agents::sa_event))
        // AI agents: grant requests, decisions and audit.
        .route("/agent-grants", get(agents::list).post(agents::create))
        .route("/agent-grants/{id}", get(agents::get))
        .route("/agent-grants/{id}/decision", post(agents::decide))
        .route("/agent-grants/{id}/revoke", post(agents::revoke))
        .route("/agent-events", get(agents::events).post(agents::event))
        .merge(sso_routes())
        .merge(comfort_routes())
}

/// Single sign-on, trusted devices and SCIM provisioning (wave E).
fn sso_routes() -> Router<AppState> {
    Router::new()
        // OIDC configuration of an organization (owners and admins).
        .route(
            "/orgs/{org_id}/sso",
            get(sso::get).put(sso::put).delete(sso::delete),
        )
        .route("/orgs/{org_id}/sso/check", post(sso::check))
        .route(
            "/orgs/{org_id}/sso/test/start",
            post(sso::login::test_start),
        )
        .route(
            "/orgs/{org_id}/sso/test/result",
            post(sso::login::test_result),
        )
        // Signing in with SSO.
        .route("/sso/discover", post(sso::login::discover))
        .route("/sso/start", post(sso::login::start))
        .route("/sso/callback", get(sso::login::callback))
        .route("/sso/redeem", post(sso::login::redeem))
        // Unlocking with SSO on trusted devices.
        .route("/sso/unlock", post(sso::devices::unlock))
        .route("/sso/device-requests", post(sso::devices::create_request))
        .route(
            "/sso/device-requests/status",
            post(sso::devices::request_status),
        )
        .route(
            "/account/trusted-devices",
            get(sso::devices::list).post(sso::devices::enroll),
        )
        .route(
            "/account/trusted-devices/{id}",
            delete(sso::devices::remove),
        )
        .route(
            "/account/trusted-devices/requests/{id}/approve",
            post(sso::devices::approve),
        )
        .route(
            "/account/trusted-devices/requests/{id}/deny",
            post(sso::devices::deny),
        )
        // SCIM tokens and provisioned users (owners and admins).
        .route("/orgs/{org_id}/scim", get(scim::overview))
        .route("/orgs/{org_id}/scim/tokens", post(scim::create_token))
        .route(
            "/orgs/{org_id}/scim/tokens/{id}",
            delete(scim::revoke_token),
        )
        // SCIM 2.0 (bearer token of the organization).
        .route(
            "/scim/v2/ServiceProviderConfig",
            get(scim::service_provider_config),
        )
        .route("/scim/v2/ResourceTypes", get(scim::resource_types))
        .route("/scim/v2/Schemas", get(scim::schemas))
        .route(
            "/scim/v2/Users",
            get(scim::list_users).post(scim::create_user),
        )
        .route(
            "/scim/v2/Users/{id}",
            get(scim::get_user)
                .put(scim::replace_user)
                .patch(scim::patch_user)
                .delete(scim::delete_user),
        )
        .route(
            "/scim/v2/Groups",
            get(scim::list_groups).post(scim::create_group),
        )
        .route(
            "/scim/v2/Groups/{id}",
            get(scim::get_group)
                .put(scim::replace_group)
                .patch(scim::patch_group)
                .delete(scim::delete_group),
        )
}

/// Moving items, attachments, share links and access requests (B5, G2,
/// B7, B9).
fn comfort_routes() -> Router<AppState> {
    Router::new()
        .route("/items/move", post(moves::move_items))
        .route("/attachments/usage", get(attachments::usage))
        .route(
            "/attachments/{id}",
            put(attachments::upload)
                .get(attachments::download)
                .delete(attachments::delete),
        )
        .route(
            "/share-links",
            get(share_links::list).post(share_links::create),
        )
        .route("/share-links/{id}", delete(share_links::delete))
        .route("/public/share-links/{id}", get(share_links::public_info))
        .route("/public/share-links/{id}/open", post(share_links::open))
        .route(
            "/vaults/{id}/access-request",
            get(access_requests::state_for_vault),
        )
        .route(
            "/vaults/{id}/access-requests",
            post(access_requests::create),
        )
        .route("/access-requests", get(access_requests::list))
        .route("/access-requests/{id}", delete(access_requests::cancel))
        .route(
            "/access-requests/{id}/approve",
            post(access_requests::approve),
        )
        .route("/access-requests/{id}/deny", post(access_requests::deny))
}
