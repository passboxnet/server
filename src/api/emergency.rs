//! Emergency access (wave C3).
//!
//! 1. The grantor adds a trusted person by email (`invited`); the server
//!    mails them.
//! 2. The grantee (signed in with that email) accepts (`accepted`).
//! 3. The grantor's client looks the grantee up in the key directory, seals
//!    the chosen personal vault keys for them and signs the agreement
//!    (`confirmed`). It seals again when vault keys change.
//! 4. The grantee requests access; the grantor gets a mail and can decline
//!    or approve early. After the waiting period without a decline, the
//!    server releases the sealed keys and the vaults' ciphertexts.
//!
//! The server enforces the waiting period. A server that ignored it could
//! hand the sealed keys to the grantee early, but only to the person the
//! grantor chose and verified; it can never read them.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use passbox_core::emergency::{
    DAY_MS, EmergencyGrant, EmergencyGrantUpload, MAX_WAIT_DAYS, MIN_WAIT_DAYS, SCOPE_VAULTS,
};
use passbox_core::identity::sealed_hash;
use passbox_core::{encoding, id};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::auth::{Session, record_event};
use super::signed::{self, bad};
use super::validate;
use crate::db::now_ms;
use crate::error::{ApiError, ApiResult};
use crate::mail::Template;
use crate::security::ClientIp;
use crate::state::AppState;

/// New emergency contacts per account and hour.
const MAX_INVITES_PER_HOUR: u32 = 20;
/// Emergency contacts an account can have.
const MAX_GRANTS: i64 = 20;

fn internal(err: impl Into<anyhow::Error>) -> ApiError {
    ApiError::Internal(err.into())
}

async fn event(
    state: &AppState,
    account_id: &str,
    kind: &str,
    session: &Session,
    ip: &str,
) -> ApiResult<()> {
    record_event(
        state,
        account_id,
        kind,
        &session.device_name,
        &session.client_kind,
        ip,
    )
    .await
}

async fn notify(state: &AppState, account_id: &str, template: Template, params: serde_json::Value) {
    if let Err(err) = state
        .mailer
        .enqueue_for_account(account_id, template, params)
        .await
    {
        tracing::warn!(error = ?err, "could not queue an emergency access mail");
    }
}

fn link(state: &AppState) -> String {
    state
        .mailer
        .public_url()
        .map(|url| format!("{url}/#/settings/emergency"))
        .unwrap_or_default()
}

// --- Listing ------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantView {
    id: String,
    grantor_id: String,
    grantor_email: String,
    grantee_id: Option<String>,
    grantee_email: String,
    scope: String,
    wait_days: i64,
    /// `invited`, `accepted` or `confirmed`.
    status: String,
    vault_ids: Vec<String>,
    version: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    grant: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    grant_signature: String,
    requested_at: i64,
    approved_at: i64,
    denied_at: i64,
    accessed_at: i64,
    /// When the sealed keys are (or were) released for the current request.
    release_at: i64,
    /// Whether the grantee can open the vaults now.
    released: bool,
    created_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantList {
    /// People this account trusts.
    granted: Vec<GrantView>,
    /// People who trust this account.
    received: Vec<GrantView>,
}

type GrantRow = (
    String,
    String,
    String,
    Option<String>,
    String,
    i64,
    String,
    serde_json::Value,
    String,
    String,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
);

/// The columns of [`GrantRow`] (`g` = emergency_grants, `a` = the grantor's account).
macro_rules! grant_columns {
    () => {
        "g.id, g.grantor_id, a.email, g.grantee_id, g.grantee_email, g.wait_days, g.status, g.vault_ids, \
         g.grant_data, g.grant_signature, g.version, g.requested_at, g.approved_at, g.denied_at, \
         g.accessed_at, g.created_at"
    };
}

fn release_at(requested_at: i64, approved_at: i64, wait_days: i64) -> i64 {
    if requested_at == 0 {
        0
    } else if approved_at > 0 {
        approved_at
    } else {
        requested_at + wait_days * i64::try_from(DAY_MS).unwrap_or(i64::MAX)
    }
}

fn view(row: GrantRow, now: i64) -> GrantView {
    let (
        id,
        grantor_id,
        grantor_email,
        grantee_id,
        grantee_email,
        wait_days,
        status,
        vault_ids,
        grant,
        grant_signature,
        version,
        requested_at,
        approved_at,
        denied_at,
        accessed_at,
        created_at,
    ) = row;
    let release = release_at(requested_at, approved_at, wait_days);
    GrantView {
        released: status == "confirmed" && release > 0 && release <= now,
        id,
        grantor_id,
        grantor_email,
        grantee_id,
        grantee_email,
        scope: SCOPE_VAULTS.to_owned(),
        wait_days,
        status,
        vault_ids: serde_json::from_value(vault_ids).unwrap_or_default(),
        version,
        grant,
        grant_signature,
        requested_at,
        approved_at,
        denied_at,
        accessed_at,
        release_at: release,
        created_at,
    }
}

/// `GET /emergency`: both directions.
pub async fn list(State(state): State<AppState>, session: Session) -> ApiResult<Json<GrantList>> {
    let mut conn = state.db.as_account(&session.account_id).await?;
    let email: String = sqlx::query_scalar!(
        "SELECT email FROM accounts WHERE id = $1",
        &session.account_id,
    )
    .fetch_one(&mut *conn)
    .await?;
    // Grantors are other accounts: their email comes from the directory.
    let granted: Vec<GrantRow> = sqlx::query_as(concat!(
        "SELECT ",
        grant_columns!(),
        " FROM emergency_grants g JOIN account_directory a ON a.id = g.grantor_id \
         WHERE g.grantor_id = $1 ORDER BY g.created_at"
    ))
    .bind(&session.account_id)
    .fetch_all(&mut *conn)
    .await?;
    let received: Vec<GrantRow> = sqlx::query_as(concat!(
        "SELECT ",
        grant_columns!(),
        " FROM emergency_grants g JOIN account_directory a ON a.id = g.grantor_id \
         WHERE g.grantee_id = $1 OR (g.grantee_id IS NULL AND g.grantee_email = $2) ORDER BY g.created_at"
    ))
    .bind(&session.account_id)
    .bind(&email)
    .fetch_all(&mut *conn)
    .await?;
    let now = now_ms();
    Ok(Json(GrantList {
        granted: granted.into_iter().map(|r| view(r, now)).collect(),
        received: received
            .into_iter()
            .map(|r| {
                let mut v = view(r, now);
                // The grantee sees the agreement only once it is confirmed.
                if v.status != "confirmed" {
                    v.grant.clear();
                    v.grant_signature.clear();
                }
                v
            })
            .collect(),
    }))
}

// --- Grantor --------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRequest {
    grantee_email: String,
    wait_days: i64,
    /// Only `vaults` (read access to chosen vaults) so far.
    #[serde(default = "default_scope")]
    scope: String,
}

fn default_scope() -> String {
    SCOPE_VAULTS.to_owned()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateResponse {
    id: String,
}

fn check_wait(days: i64) -> ApiResult<()> {
    let min = i64::try_from(MIN_WAIT_DAYS).unwrap_or(1);
    let max = i64::try_from(MAX_WAIT_DAYS).unwrap_or(30);
    if (min..=max).contains(&days) {
        Ok(())
    } else {
        Err(bad("waitDays must be between 1 and 30"))
    }
}

/// `POST /emergency/grants`: adds an emergency contact by email.
pub async fn create(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Json(req): Json<CreateRequest>,
) -> ApiResult<(StatusCode, Json<CreateResponse>)> {
    let email = validate::email(&req.grantee_email)?;
    check_wait(req.wait_days)?;
    if req.scope != SCOPE_VAULTS {
        return Err(bad("scope must be vaults"));
    }
    if let Some(wait) = state.limiter.hit(
        &format!("emergency-invite:{}", session.account_id),
        MAX_INVITES_PER_HOUR,
        std::time::Duration::from_secs(60 * 60),
    ) {
        return Err(ApiError::RateLimited(wait));
    }
    let mut tx = state.db.as_account(&session.account_id).await?;
    let own_email: String = sqlx::query_scalar!(
        "SELECT email FROM accounts WHERE id = $1",
        &session.account_id,
    )
    .fetch_one(&mut *tx)
    .await?;
    if own_email == email {
        return Err(bad("you cannot be your own emergency contact"));
    }
    let count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"count!\" FROM emergency_grants WHERE grantor_id = $1",
        &session.account_id,
    )
    .fetch_one(&mut *tx)
    .await?;
    if count >= MAX_GRANTS {
        return Err(bad(
            "you have reached the maximum number of emergency contacts",
        ));
    }
    let existing: Option<i64> = sqlx::query_scalar!(
        "SELECT 1::BIGINT AS \"one!\" FROM emergency_grants WHERE grantor_id = $1 AND grantee_email = $2",
        &session.account_id,
        &email,
    )
    .fetch_optional(&mut *tx)
    .await?;
    if existing.is_some() {
        return Err(ApiError::conflict(
            "this person is already an emergency contact",
            serde_json::Value::Null,
        ));
    }
    let grant_id = id::new_id().map_err(internal)?;
    let now = now_ms();
    sqlx::query!(
        "INSERT INTO emergency_grants (id, grantor_id, grantee_email, grantee_id, scope, wait_days, status, \
         vault_ids, grant_data, grant_signature, sealed_keys, version, requested_at, approved_at, denied_at, \
         accessed_at, created_at, updated_at) VALUES ($1, $2, $3, NULL, $4, $5, 'invited', '[]', '', '', '', 0, \
         0, 0, 0, 0, $6, $7)",
        &grant_id,
        &session.account_id,
        &email,
        &req.scope,
        req.wait_days,
        now,
        now,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    event(
        &state,
        &session.account_id,
        "emergency_contact_added",
        &session,
        &ip,
    )
    .await?;
    let mut conn = state.db.as_account(&session.account_id).await?;
    let locale = crate::instance::load_settings(&mut conn)
        .await?
        .default_locale;
    // The recipient may not have an account yet; mail them in their
    // account's language if they do.
    let grantee: Option<String> = sqlx::query_scalar!(
        r#"SELECT id AS "id!" FROM passbox.account_by_email($1)"#,
        &email,
    )
    .fetch_optional(&mut *conn)
    .await?;
    drop(conn);
    let params = json!({ "inviter": own_email, "waitDays": req.wait_days, "link": link(&state) });
    let result = match grantee {
        Some(account_id) => state
            .mailer
            .enqueue_for_account(&account_id, Template::EmergencyAccessInvited, params)
            .await
            .map(|_| ()),
        None => state
            .mailer
            .enqueue(&email, Template::EmergencyAccessInvited, locale, params)
            .await
            .map(|_| ()),
    };
    if let Err(err) = result {
        tracing::warn!(error = ?err, "could not queue the emergency access invitation");
    }
    Ok((StatusCode::CREATED, Json(CreateResponse { id: grant_id })))
}

struct StoredGrant {
    grantor_id: String,
    grantee_id: Option<String>,
    grantee_email: String,
    wait_days: i64,
    status: String,
    version: i64,
    requested_at: i64,
    approved_at: i64,
    accessed_at: i64,
}

#[allow(clippy::type_complexity)]
async fn load(conn: &mut sqlx::PgConnection, grant_id: &str) -> ApiResult<StoredGrant> {
    let row: Option<(
        String,
        Option<String>,
        String,
        i64,
        String,
        i64,
        i64,
        i64,
        i64,
    )> = sqlx::query!(
        "SELECT grantor_id, grantee_id, grantee_email, wait_days, status, version, requested_at, \
             approved_at, accessed_at FROM emergency_grants WHERE id = $1",
        grant_id,
    )
    .map(|row| {
        (
            row.grantor_id,
            row.grantee_id,
            row.grantee_email,
            row.wait_days,
            row.status,
            row.version,
            row.requested_at,
            row.approved_at,
            row.accessed_at,
        )
    })
    .fetch_optional(&mut *conn)
    .await?;
    let (
        grantor_id,
        grantee_id,
        grantee_email,
        wait_days,
        status,
        version,
        requested_at,
        approved_at,
        accessed_at,
    ) = row.ok_or(ApiError::NotFound)?;
    Ok(StoredGrant {
        grantor_id,
        grantee_id,
        grantee_email,
        wait_days,
        status,
        version,
        requested_at,
        approved_at,
        accessed_at,
    })
}

/// `POST /emergency/grants/{id}/confirm`: the sealed keys and the signed
/// agreement (also to seal again after vault keys changed).
pub async fn confirm(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(grant_id): Path<String>,
    Json(req): Json<EmergencyGrantUpload>,
) -> ApiResult<StatusCode> {
    validate::id("grant id", &grant_id)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    let stored = load(&mut tx, &grant_id).await?;
    if stored.grantor_id != session.account_id {
        return Err(ApiError::NotFound);
    }
    let Some(grantee_id) = stored.grantee_id.clone() else {
        return Err(bad("the emergency contact has not accepted yet"));
    };
    if stored.status != "accepted" && stored.status != "confirmed" {
        return Err(bad("the emergency contact has not accepted yet"));
    }
    if i64::try_from(req.version).unwrap_or(i64::MAX) <= stored.version {
        return Err(ApiError::conflict(
            "a newer version of this grant exists",
            json!({ "version": stored.version }),
        ));
    }
    let me = signed::own_bundle(&mut tx, &session.account_id).await?;
    let grantee = signed::own_bundle(&mut tx, &grantee_id)
        .await
        .map_err(|_| bad("the emergency contact has no keys yet; ask them to sign in once"))?;
    let grant = signed::parse::<EmergencyGrant>("grant", &req.grant, &req.grant_signature, &me)?;
    let sealed = signed::sealed("sealedKeys", &req.sealed_keys)?;
    let g = &grant.value;
    let wait_ms = u64::try_from(stored.wait_days).unwrap_or(0) * DAY_MS;
    let mut vault_ids: Vec<String> = g.vaults.iter().map(|(v, _)| v.clone()).collect();
    vault_ids.dedup();
    let mut requested = req.vault_ids.clone();
    requested.sort();
    requested.dedup();
    if g.grant_id != grant_id
        || g.grantor_id != session.account_id
        || g.grantor_bundle_hash != me.hash()
        || g.grantee_id != grantee_id
        || g.grantee_bundle_hash != grantee.hash()
        || g.scope != SCOPE_VAULTS
        || g.wait_ms != wait_ms
        || g.version != req.version
        || g.sealed_hash != sealed_hash(&sealed)
        || vault_ids != requested
    {
        return Err(bad("the grant does not match the request"));
    }
    for vault_id in &vault_ids {
        validate::id("vault id", vault_id)?;
        let own: Option<i64> = sqlx::query_scalar!(
            "SELECT 1::BIGINT AS \"one!\" FROM vaults WHERE id = $1 AND account_id = $2 AND org_id IS NULL",
            vault_id,
            &session.account_id,
        )
        .fetch_optional(&mut *tx)
        .await?;
        if own.is_none() {
            return Err(bad(
                "only your own personal vaults can be shared for emergencies",
            ));
        }
    }
    sqlx::query!(
        "UPDATE emergency_grants SET status = 'confirmed', vault_ids = $1, grant_data = $2, grant_signature = $3, \
         sealed_keys = $4, version = $5, updated_at = $6 WHERE id = $7",
        serde_json::to_value(&vault_ids).map_err(internal)?,
        &req.grant,
        &req.grant_signature,
        &req.sealed_keys,
        i64::try_from(req.version).map_err(internal)?,
        now_ms(),
        &grant_id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    if stored.status != "confirmed" {
        event(
            &state,
            &session.account_id,
            "emergency_access_confirmed",
            &session,
            &ip,
        )
        .await?;
        record_event(
            &state,
            &grantee_id,
            "emergency_access_confirmed",
            "",
            "",
            &ip,
        )
        .await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /emergency/grants/{id}`: the grantor removes the contact, or the
/// grantee steps back.
pub async fn delete(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(grant_id): Path<String>,
) -> ApiResult<StatusCode> {
    validate::id("grant id", &grant_id)?;
    let mut conn = state.db.as_account(&session.account_id).await?;
    let stored = load(&mut conn, &grant_id).await?;
    let own_email: String = sqlx::query_scalar!(
        "SELECT email FROM accounts WHERE id = $1",
        &session.account_id,
    )
    .fetch_one(&mut *conn)
    .await?;
    let is_grantee = stored.grantee_id.as_deref() == Some(session.account_id.as_str())
        || (stored.grantee_id.is_none() && stored.grantee_email == own_email);
    if stored.grantor_id != session.account_id && !is_grantee {
        return Err(ApiError::NotFound);
    }
    sqlx::query!("DELETE FROM emergency_grants WHERE id = $1", &grant_id,)
        .execute(&mut *conn)
        .await?;
    conn.commit().await?;
    event(
        &state,
        &session.account_id,
        "emergency_contact_removed",
        &session,
        &ip,
    )
    .await?;
    let other = if is_grantee {
        Some(stored.grantor_id)
    } else {
        stored.grantee_id
    };
    if let Some(other) = other {
        record_event(&state, &other, "emergency_contact_removed", "", "", &ip).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /emergency/grants/{id}/deny`: declines (or ends) the current request.
pub async fn deny(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(grant_id): Path<String>,
) -> ApiResult<StatusCode> {
    validate::id("grant id", &grant_id)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    let stored = load(&mut tx, &grant_id).await?;
    if stored.grantor_id != session.account_id {
        return Err(ApiError::NotFound);
    }
    if stored.requested_at == 0 {
        return Err(bad("there is no request to decline"));
    }
    sqlx::query!(
        "UPDATE emergency_grants SET requested_at = 0, approved_at = 0, accessed_at = 0, denied_at = $1, \
         updated_at = $2 WHERE id = $3",
        now_ms(),
        now_ms(),
        &grant_id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    event(
        &state,
        &session.account_id,
        "emergency_access_denied",
        &session,
        &ip,
    )
    .await?;
    if let Some(grantee) = &stored.grantee_id {
        record_event(&state, grantee, "emergency_access_denied", "", "", &ip).await?;
        let email: String = sqlx::query_scalar!(
            "SELECT email FROM accounts WHERE id = $1",
            &session.account_id,
        )
        .fetch_one(&mut *state.db.as_account(&session.account_id).await?)
        .await?;
        notify(
            &state,
            grantee,
            Template::EmergencyAccessDenied,
            json!({ "grantor": email }),
        )
        .await;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /emergency/grants/{id}/approve`: releases access before the
/// waiting period ends.
pub async fn approve(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(grant_id): Path<String>,
) -> ApiResult<StatusCode> {
    validate::id("grant id", &grant_id)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    let stored = load(&mut tx, &grant_id).await?;
    if stored.grantor_id != session.account_id {
        return Err(ApiError::NotFound);
    }
    if stored.requested_at == 0 || stored.status != "confirmed" {
        return Err(bad("there is no request to approve"));
    }
    if stored.approved_at == 0 {
        sqlx::query!(
            "UPDATE emergency_grants SET approved_at = $1, updated_at = $2 WHERE id = $3",
            now_ms(),
            now_ms(),
            &grant_id,
        )
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    event(
        &state,
        &session.account_id,
        "emergency_access_approved",
        &session,
        &ip,
    )
    .await?;
    if let Some(grantee) = &stored.grantee_id {
        record_event(&state, grantee, "emergency_access_approved", "", "", &ip).await?;
        let email: String = sqlx::query_scalar!(
            "SELECT email FROM accounts WHERE id = $1",
            &session.account_id,
        )
        .fetch_one(&mut *state.db.as_account(&session.account_id).await?)
        .await?;
        notify(
            &state,
            grantee,
            Template::EmergencyAccessApproved,
            json!({ "grantor": email, "link": link(&state) }),
        )
        .await;
    }
    Ok(StatusCode::NO_CONTENT)
}

// --- Grantee --------------------------------------------------------------------------

/// `POST /emergency/grants/{id}/accept`: the invited person accepts.
pub async fn accept(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(grant_id): Path<String>,
) -> ApiResult<StatusCode> {
    validate::id("grant id", &grant_id)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    let stored = load(&mut tx, &grant_id).await?;
    let own_email: String = sqlx::query_scalar!(
        "SELECT email FROM accounts WHERE id = $1",
        &session.account_id,
    )
    .fetch_one(&mut *tx)
    .await?;
    if stored.grantee_email != own_email || stored.grantee_id.is_some() {
        return Err(ApiError::NotFound);
    }
    sqlx::query!(
        "UPDATE emergency_grants SET grantee_id = $1, status = 'accepted', updated_at = $2 WHERE id = $3",
        &session.account_id,
        now_ms(),
        &grant_id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    event(
        &state,
        &session.account_id,
        "emergency_invitation_accepted",
        &session,
        &ip,
    )
    .await?;
    record_event(
        &state,
        &stored.grantor_id,
        "emergency_invitation_accepted",
        "",
        "",
        &ip,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn require_grantee(stored: &StoredGrant, session: &Session) -> ApiResult<()> {
    if stored.grantee_id.as_deref() != Some(session.account_id.as_str()) {
        return Err(ApiError::NotFound);
    }
    if stored.status != "confirmed" {
        return Err(bad("the emergency access is not set up yet"));
    }
    Ok(())
}

/// `POST /emergency/grants/{id}/request`: starts the waiting period.
pub async fn request(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(grant_id): Path<String>,
) -> ApiResult<StatusCode> {
    validate::id("grant id", &grant_id)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    let stored = load(&mut tx, &grant_id).await?;
    require_grantee(&stored, &session)?;
    if stored.requested_at > 0 {
        return Err(ApiError::conflict(
            "access was already requested",
            serde_json::Value::Null,
        ));
    }
    let now = now_ms();
    sqlx::query!(
        "UPDATE emergency_grants SET requested_at = $1, approved_at = 0, denied_at = 0, accessed_at = 0, \
         updated_at = $2 WHERE id = $3",
        now,
        now,
        &grant_id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    event(
        &state,
        &session.account_id,
        "emergency_access_requested",
        &session,
        &ip,
    )
    .await?;
    record_event(
        &state,
        &stored.grantor_id,
        "emergency_access_requested",
        "",
        "",
        &ip,
    )
    .await?;
    let requester: String = sqlx::query_scalar!(
        "SELECT email FROM accounts WHERE id = $1",
        &session.account_id,
    )
    .fetch_one(&mut *state.db.as_account(&session.account_id).await?)
    .await?;
    notify(
        &state,
        &stored.grantor_id,
        Template::EmergencyAccess,
        json!({
            "requester": requester,
            "waitDays": stored.wait_days,
            "releaseAt": release_at(now, 0, stored.wait_days),
            "link": link(&state),
        }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessVault {
    id: String,
    encrypted_meta: String,
    revision: i64,
    key_epoch: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessItem {
    id: String,
    vault_id: String,
    revision: i64,
    encrypted_data: String,
    updated_at: i64,
    key_epoch: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessResponse {
    grantor_id: String,
    grant: String,
    grant_signature: String,
    sealed_keys: String,
    vaults: Vec<AccessVault>,
    items: Vec<AccessItem>,
}

/// `GET /emergency/grants/{id}/access`: the sealed keys and the vaults'
/// ciphertexts, once released.
pub async fn access(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(grant_id): Path<String>,
) -> ApiResult<Json<AccessResponse>> {
    validate::id("grant id", &grant_id)?;
    let mut conn = state.db.as_account(&session.account_id).await?;
    let stored = load(&mut conn, &grant_id).await?;
    require_grantee(&stored, &session)?;
    let release = release_at(stored.requested_at, stored.approved_at, stored.wait_days);
    let now = now_ms();
    if release == 0 || release > now {
        return Err(ApiError::forbidden(
            "emergency_access_waiting",
            "the waiting period has not ended yet",
        ));
    }
    let (vault_ids, grant, grant_signature, sealed_keys): (serde_json::Value, String, String, String) =
        sqlx::query!(
            "SELECT vault_ids, grant_data, grant_signature, sealed_keys FROM emergency_grants WHERE id = $1",
            &grant_id,
        ).map(|row| (row.vault_ids, row.grant_data, row.grant_signature, row.sealed_keys))
        .fetch_one(&mut *conn)
        .await?;
    let vault_ids: Vec<String> = serde_json::from_value(vault_ids).unwrap_or_default();
    let mut vaults = Vec::new();
    let mut items = Vec::new();
    for vault_id in &vault_ids {
        let vault: Option<(Vec<u8>, i64, i64)> = sqlx::query!(
            "SELECT encrypted_meta, revision, key_epoch FROM vaults WHERE id = $1 AND account_id = $2 \
             AND org_id IS NULL",
            vault_id,
            &stored.grantor_id,
        ).map(|row| (row.encrypted_meta, row.revision, row.key_epoch))
        .fetch_optional(&mut *conn)
        .await?;
        let Some((encrypted_meta, revision, key_epoch)) = vault else {
            continue;
        };
        vaults.push(AccessVault {
            id: vault_id.clone(),
            encrypted_meta: encoding::encode(&encrypted_meta),
            revision,
            key_epoch,
        });
        let rows = sqlx::query!(
            "SELECT id, revision, encrypted_data, updated_at, key_epoch FROM items \
             WHERE vault_id = $1 AND deleted = false ORDER BY id",
            vault_id,
        )
        .map(|row| {
            (
                row.id,
                row.revision,
                row.encrypted_data,
                row.updated_at,
                row.key_epoch,
            )
        })
        .fetch_all(&mut *conn)
        .await?;
        items.extend(
            rows.into_iter()
                .filter_map(|(id, revision, data, updated_at, key_epoch)| {
                    data.map(|encrypted_data| AccessItem {
                        id,
                        vault_id: vault_id.clone(),
                        revision,
                        encrypted_data: encoding::encode(&encrypted_data),
                        updated_at,
                        key_epoch,
                    })
                }),
        );
    }
    if stored.accessed_at == 0 {
        sqlx::query!(
            "UPDATE emergency_grants SET accessed_at = $1 WHERE id = $2",
            now,
            &grant_id,
        )
        .execute(&mut *conn)
        .await?;
        conn.commit().await?;
        event(
            &state,
            &session.account_id,
            "emergency_access_used",
            &session,
            &ip,
        )
        .await?;
        record_event(
            &state,
            &stored.grantor_id,
            "emergency_access_used",
            "",
            "",
            &ip,
        )
        .await?;
        let grantee: String = sqlx::query_scalar!(
            "SELECT email FROM accounts WHERE id = $1",
            &session.account_id,
        )
        .fetch_one(&mut *state.db.as_account(&session.account_id).await?)
        .await?;
        notify(
            &state,
            &stored.grantor_id,
            Template::EmergencyAccessUsed,
            json!({ "grantee": grantee, "device": session.device_name, "ip": ip, "time": now }),
        )
        .await;
    }
    Ok(Json(AccessResponse {
        grantor_id: stored.grantor_id,
        grant,
        grant_signature,
        sealed_keys,
        vaults,
        items,
    }))
}
