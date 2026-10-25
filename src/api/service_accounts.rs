//! Service accounts (F2): machine identities owned by an account.
//!
//! The owner's client creates the key pair and token, seals vault keys to
//! the service account and signs each grant (`passbox_core::service_account`).
//! The server stores ciphertext, public keys and the hash of the token's
//! authentication key. It enforces revocation, expiry, the grant's
//! permission and, on every request, that the owner still has the access the
//! service account uses: a service account never has more access than its
//! owner.
//!
//! Owner endpoints (session): `/service-accounts...`.
//! Service account endpoints (`Authorization: Bearer sa.{id}.{auth_key}`):
//! `/service-account...`.

use axum::Json;
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use passbox_core::identity::SignedBundle;
use passbox_core::service_account::{self as sa, Grant, Permission, PublicKey};
use passbox_core::{encoding, id, identity};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgConnection;

use super::access::{self, VaultAccess};
use super::auth::{Session, record_event};
use super::validate;
use super::vaults::WriteResponse;
use crate::db::{self, Public, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::security::ClientIp;
use crate::state::AppState;

/// Error code when the fair-use limit for agents is reached.
pub const AGENT_LIMIT_REACHED: &str = "agent_limit_reached";
/// Vault grants per service account (all epochs).
const MAX_GRANTS: i64 = 200;
const MAX_NAME_LEN: usize = 100;
/// `last_used_at` is updated at most this often.
const LAST_USED_RESOLUTION_MS: i64 = 60_000;
/// Requests per service account and minute.
const MAX_REQUESTS_PER_MINUTE: u32 = 600;

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::Internal(anyhow::anyhow!("{e}"))
}

fn check_name(name: &str) -> ApiResult<String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME_LEN || name.chars().any(char::is_control)
    {
        return Err(ApiError::bad_request(format!(
            "the name must be 1 to {MAX_NAME_LEN} characters"
        )));
    }
    Ok(name.to_owned())
}

fn check_expiry(expires_at: i64) -> ApiResult<()> {
    if expires_at != 0 && expires_at <= now_ms() {
        return Err(ApiError::bad_request("expiresAt must be in the future"));
    }
    Ok(())
}

/// The owner's published signing key.
async fn owner_sig_pk(conn: &mut PgConnection, account_id: &str) -> ApiResult<[u8; 32]> {
    let row: Option<(String, String)> = sqlx::query!(
        r#"SELECT bundle AS "bundle!", bundle_signature AS "bundle_signature!" FROM public_keys
           WHERE account_id = $1 ORDER BY key_version DESC LIMIT 1"#,
        account_id,
    )
    .map(|row| (row.bundle, row.bundle_signature))
    .fetch_optional(&mut *conn)
    .await?;
    let (bundle, signature) = row.ok_or_else(|| {
        ApiError::bad_request("publish your account keys first (unlock once in an updated app)")
    })?;
    Ok(SignedBundle::parse(&bundle, &signature)
        .map_err(internal)?
        .bundle
        .sig_pk)
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GrantUploadJson {
    vault_id: String,
    key_epoch: i64,
    permission: String,
    sealed_key: String,
    grant: String,
    grant_signature: String,
}

/// Checks an uploaded grant against the service account, the owner's
/// signature and the owner's current access to the vault.
async fn check_grant(
    conn: &mut PgConnection,
    owner_id: &str,
    sig_pk: &[u8; 32],
    sa_id: &str,
    public_key: &str,
    upload: &GrantUploadJson,
) -> ApiResult<()> {
    validate::id("vaultId", &upload.vault_id)?;
    let permission = Permission::parse(&upload.permission)
        .map_err(|_| ApiError::bad_request("permission must be read or write"))?;
    let sealed = validate::base64("sealedKey", &upload.sealed_key, validate::MAX_SMALL_LEN)?;
    let grant_bytes = validate::base64("grant", &upload.grant, validate::MAX_SMALL_LEN)?;
    let signature = validate::base64("grantSignature", &upload.grant_signature, 256)?;
    identity::verify(sig_pk, &grant_bytes, &signature)
        .map_err(|_| ApiError::bad_request("the grant is not signed by your account key"))?;
    let grant = Grant::from_canonical(&grant_bytes)
        .map_err(|e| ApiError::bad_request(format!("invalid grant: {e}")))?;
    let key_hash = identity::object_hash(&encoding::decode(public_key).map_err(internal)?);
    if grant.service_account_id != sa_id
        || grant.owner_id != owner_id
        || grant.vault_id != upload.vault_id
        || i64::from(grant.key_epoch) != upload.key_epoch
        || grant.permission != permission
        || grant.key_hash != key_hash
        || grant.sealed_hash != identity::sealed_hash(&sealed)
    {
        return Err(ApiError::bad_request(
            "the grant does not match the request",
        ));
    }
    let access = access::vault_access(conn, &upload.vault_id, owner_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let current = match &access {
        VaultAccess::Personal => 0,
        VaultAccess::Shared {
            key_epoch, org_id, ..
        } => {
            // Guests are view-only (B8): no machine access to the vaults
            // shared with them.
            if access::is_guest(conn, org_id, owner_id).await? {
                return Err(access::guest_view_only());
            }
            *key_epoch
        }
    };
    if upload.key_epoch != current {
        return Err(ApiError::conflict(
            "the vault's key was rotated; grant the current key epoch",
            json!({ "currentKeyEpoch": current }),
        ));
    }
    if permission == Permission::Write && !access.can_write() {
        return Err(ApiError::forbidden(
            "forbidden",
            "you can only view this vault, so a service account cannot write to it",
        ));
    }
    Ok(())
}

async fn insert_grant(
    conn: &mut PgConnection,
    sa_id: &str,
    upload: &GrantUploadJson,
) -> ApiResult<()> {
    sqlx::query!(
        "DELETE FROM service_account_grants WHERE service_account_id = $1 AND vault_id = $2 \
         AND key_epoch = $3",
        sa_id,
        &upload.vault_id,
        upload.key_epoch,
    )
    .execute(&mut *conn)
    .await?;
    // A changed permission applies to every epoch of the vault.
    sqlx::query!(
        "UPDATE service_account_grants SET permission = $1 WHERE service_account_id = $2 \
         AND vault_id = $3",
        &upload.permission,
        sa_id,
        &upload.vault_id,
    )
    .execute(&mut *conn)
    .await?;
    sqlx::query!(
        "INSERT INTO service_account_grants (service_account_id, vault_id, key_epoch, permission, \
         sealed_key, grant_data, grant_signature, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        sa_id,
        &upload.vault_id,
        upload.key_epoch,
        &upload.permission,
        super::vaults::decode(&upload.sealed_key)?,
        &upload.grant,
        &upload.grant_signature,
        now_ms(),
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

async fn sa_event(conn: &mut PgConnection, sa_id: &str, kind: &str, detail: &str, ip: &str) {
    let result = sqlx::query!(
        "INSERT INTO service_account_events (id, service_account_id, kind, detail, ip, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
        id::new_id().unwrap_or_default(),
        sa_id,
        kind,
        detail,
        ip,
        now_ms(),
    )
    .execute(&mut *conn)
    .await;
    if let Err(e) = result {
        tracing::warn!(error = %e, "could not record a service account event");
    }
}

// --- Owner endpoints ---------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRequest {
    id: String,
    name: String,
    public_key: String,
    public_key_signature: String,
    encrypted_private: String,
    auth_hash: String,
    /// Unix ms; 0 for no expiry.
    #[serde(default)]
    expires_at: i64,
    #[serde(default)]
    grants: Vec<GrantUploadJson>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantInfo {
    vault_id: String,
    key_epoch: i64,
    permission: String,
    /// The vault's current key epoch; a lower `keyEpoch` means the grant
    /// must be renewed to read items changed since the rotation.
    current_key_epoch: i64,
    created_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountInfo {
    id: String,
    name: String,
    public_key: String,
    public_key_signature: String,
    expires_at: i64,
    revoked_at: i64,
    last_used_at: i64,
    last_used_ip: String,
    created_at: i64,
    grants: Vec<GrantInfo>,
}

type SaRow = (String, String, String, String, i64, i64, i64, String, i64);

async fn info(conn: &mut PgConnection, row: SaRow) -> ApiResult<ServiceAccountInfo> {
    let (
        id,
        name,
        public_key,
        public_key_signature,
        expires_at,
        revoked_at,
        last_used_at,
        ip,
        created_at,
    ) = row;
    let rows: Vec<(String, i64, String, i64, i64)> = sqlx::query_as(
        "SELECT g.vault_id, g.key_epoch, g.permission, v.key_epoch, g.created_at \
         FROM service_account_grants g JOIN vaults v ON v.id = g.vault_id \
         WHERE g.service_account_id = $1 ORDER BY g.vault_id, g.key_epoch",
    )
    .bind(&id)
    .fetch_all(&mut *conn)
    .await?;
    // One entry per vault: its newest grant.
    let mut grants: Vec<GrantInfo> = Vec::new();
    for (vault_id, key_epoch, permission, current_key_epoch, created_at) in rows {
        if let Some(last) = grants.last_mut()
            && last.vault_id == vault_id
        {
            *last = GrantInfo {
                vault_id,
                key_epoch,
                permission,
                current_key_epoch,
                created_at,
            };
            continue;
        }
        grants.push(GrantInfo {
            vault_id,
            key_epoch,
            permission,
            current_key_epoch,
            created_at,
        });
    }
    Ok(ServiceAccountInfo {
        id,
        name,
        public_key,
        public_key_signature,
        expires_at,
        revoked_at,
        last_used_at,
        last_used_ip: ip,
        created_at,
        grants,
    })
}

/// The fair-use limit for AI agents and service accounts as it applies to
/// one account. They never count as members; guests add no allowance.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentUsage {
    /// Per member; 0 = unlimited.
    pub limit_per_member: u32,
    /// Active (neither revoked nor expired) service accounts in the pool.
    pub used: i64,
    /// Size of the pool; 0 = unlimited.
    pub allowed: i64,
    /// `personal` (the account's own) or `organization` (shared by the
    /// organization's members).
    pub pool: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    /// Members the organization's pool is based on (not guests).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub members: Option<i64>,
}

impl AgentUsage {
    pub fn has_room(&self) -> bool {
        self.allowed == 0 || self.used < self.allowed
    }
}

/// The limit in force: the instance setting, else
/// `PASSBOX_AGENT_LIMIT_PER_MEMBER`.
pub async fn agent_limit_per_member(state: &AppState, conn: &mut PgConnection) -> ApiResult<u32> {
    let setting = crate::instance::load_settings(conn)
        .await?
        .agent_limit_per_member;
    Ok(setting.unwrap_or(state.agent_limit_per_member))
}

/// How many service accounts the account may still create. Members of
/// organizations draw from their organization's pool (`limit` times the
/// confirmed members who are not guests; the organization with the most
/// room counts), everyone else from their own allowance of `limit`.
pub async fn agent_usage(
    conn: &mut PgConnection,
    limit: u32,
    account_id: &str,
) -> ApiResult<AgentUsage> {
    let now = now_ms();
    let own: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"count!\" FROM service_accounts sa WHERE sa.account_id = $1 \
         AND sa.revoked_at = 0 AND (sa.expires_at = 0 OR sa.expires_at > $2)",
        account_id,
        now,
    )
    .fetch_one(&mut *conn)
    .await?;
    let personal = AgentUsage {
        limit_per_member: limit,
        used: own,
        allowed: i64::from(limit),
        pool: "personal",
        org_id: None,
        members: None,
    };
    if limit == 0 {
        return Ok(personal);
    }
    let orgs: Vec<String> = sqlx::query_scalar!(
        "SELECT org_id FROM org_members WHERE account_id = $1 AND status = 'confirmed' \
         AND role <> 'guest' ORDER BY org_id",
        account_id,
    )
    .fetch_all(&mut *conn)
    .await?;
    let mut best: Option<AgentUsage> = None;
    for org_id in orgs {
        let members: i64 = sqlx::query_scalar!(
            "SELECT COUNT(*) AS \"count!\" FROM org_members WHERE org_id = $1 AND status = 'confirmed' \
             AND role <> 'guest'",
            &org_id,
        )
        .fetch_one(&mut *conn)
        .await?;
        // Other members' service accounts are not readable: a function
        // counts them.
        let used: i64 = sqlx::query_scalar!(
            r#"SELECT passbox.org_service_account_count($1, $2) AS "count!""#,
            &org_id,
            now,
        )
        .fetch_one(&mut *conn)
        .await?;
        let usage = AgentUsage {
            limit_per_member: limit,
            used,
            allowed: i64::from(limit) * members.max(1),
            pool: "organization",
            org_id: Some(org_id),
            members: Some(members),
        };
        if best
            .as_ref()
            .is_none_or(|b| usage.allowed - usage.used > b.allowed - b.used)
        {
            best = Some(usage);
        }
    }
    Ok(best.unwrap_or(personal))
}

/// `GET /agent-limit`: the fair-use limit for agents and service accounts.
pub async fn limit(State(state): State<AppState>, session: Session) -> ApiResult<Json<AgentUsage>> {
    let mut conn = state.db.as_account(&session.account_id).await?;
    let limit = agent_limit_per_member(&state, &mut conn).await?;
    Ok(Json(
        agent_usage(&mut conn, limit, &session.account_id).await?,
    ))
}

/// `GET /service-accounts`: the account's service accounts, newest first.
pub async fn list(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<Json<Vec<ServiceAccountInfo>>> {
    let mut conn = state.db.as_account(&session.account_id).await?;
    let rows: Vec<SaRow> = sqlx::query!(
        "SELECT id, name, public_key, public_key_signature, expires_at, revoked_at, last_used_at, \
         last_used_ip, created_at FROM service_accounts WHERE account_id = $1 ORDER BY created_at DESC",
        &session.account_id,
    ).map(|row| (row.id, row.name, row.public_key, row.public_key_signature, row.expires_at, row.revoked_at, row.last_used_at, row.last_used_ip, row.created_at))
    .fetch_all(&mut *conn)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(info(&mut conn, row).await?);
    }
    Ok(Json(out))
}

async fn owned(conn: &mut PgConnection, sa_id: &str, account_id: &str) -> ApiResult<SaRow> {
    sqlx::query!(
        "SELECT id, name, public_key, public_key_signature, expires_at, revoked_at, last_used_at, \
         last_used_ip, created_at FROM service_accounts WHERE id = $1 AND account_id = $2",
        sa_id,
        account_id,
    )
    .map(|row| {
        (
            row.id,
            row.name,
            row.public_key,
            row.public_key_signature,
            row.expires_at,
            row.revoked_at,
            row.last_used_at,
            row.last_used_ip,
            row.created_at,
        )
    })
    .fetch_optional(&mut *conn)
    .await?
    .ok_or(ApiError::NotFound)
}

/// `POST /service-accounts`: registers a new service account with its first
/// vault grants.
pub async fn create(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Json(req): Json<CreateRequest>,
) -> ApiResult<(StatusCode, Json<ServiceAccountInfo>)> {
    validate::id("id", &req.id)?;
    let name = check_name(&req.name)?;
    check_expiry(req.expires_at)?;
    validate::base64("publicKey", &req.public_key, validate::MAX_SMALL_LEN)?;
    validate::base64("publicKeySignature", &req.public_key_signature, 256)?;
    validate::base64(
        "encryptedPrivate",
        &req.encrypted_private,
        validate::MAX_SMALL_LEN,
    )?;
    if req.auth_hash.len() != 64 || !req.auth_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::bad_request("authHash must be 64 hex characters"));
    }
    if req.grants.len() > 100 {
        return Err(ApiError::bad_request("too many vault grants"));
    }
    let mut tx = state.db.as_account(&session.account_id).await?;
    let sig_pk = owner_sig_pk(&mut tx, &session.account_id).await?;
    let public = PublicKey::verify(&req.public_key, &req.public_key_signature, &sig_pk)
        .map_err(|_| ApiError::bad_request("the public key is not signed by your account key"))?;
    if public.id != req.id || public.owner_id != session.account_id {
        return Err(ApiError::bad_request(
            "the public key does not match the request",
        ));
    }
    let limit = agent_limit_per_member(&state, &mut tx).await?;
    let usage = agent_usage(&mut tx, limit, &session.account_id).await?;
    if !usage.has_room() {
        let message = match usage.members {
            Some(members) => format!(
                "your organization has reached its fair-use limit of {} AI agents and service accounts \
                 ({limit} per member, {members} members); revoke one you no longer need, or ask an \
                 administrator of this server to raise the limit",
                usage.allowed
            ),
            None => format!(
                "you have reached the fair-use limit of {limit} AI agents and service accounts; \
                 revoke one you no longer need, or ask an administrator of this server to raise the limit"
            ),
        };
        return Err(ApiError::forbidden(AGENT_LIMIT_REACHED, message));
    }
    for grant in &req.grants {
        check_grant(
            &mut tx,
            &session.account_id,
            &sig_pk,
            &req.id,
            &req.public_key,
            grant,
        )
        .await?;
    }
    let now = now_ms();
    let inserted = sqlx::query!(
        "INSERT INTO service_accounts (id, account_id, name, public_key, public_key_signature, \
         encrypted_private, auth_hash, expires_at, revoked_at, last_used_at, last_used_ip, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, 0, '', $9)",
        &req.id,
        &session.account_id,
        &name,
        &req.public_key,
        &req.public_key_signature,
        super::vaults::decode(&req.encrypted_private)?,
        req.auth_hash.to_ascii_lowercase(),
        req.expires_at,
        now,
    )
    .execute(&mut *tx)
    .await;
    if inserted.is_err() {
        return Err(ApiError::conflict(
            "a service account with this ID already exists",
            json!({}),
        ));
    }
    for grant in &req.grants {
        insert_grant(&mut tx, &req.id, grant).await?;
    }
    sa_event(&mut tx, &req.id, "created", "", &ip).await;
    let row = owned(&mut tx, &req.id, &session.account_id).await?;
    let info = info(&mut tx, row).await?;
    tx.commit().await?;
    record_event(
        &state,
        &session.account_id,
        "service_account_created",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(info)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRequest {
    name: Option<String>,
    expires_at: Option<i64>,
}

/// `PUT /service-accounts/{id}`: renames or changes the expiry.
pub async fn update(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(sa_id): Path<String>,
    Json(req): Json<UpdateRequest>,
) -> ApiResult<Json<ServiceAccountInfo>> {
    let mut tx = state.db.as_account(&session.account_id).await?;
    owned(&mut tx, &sa_id, &session.account_id).await?;
    if let Some(name) = &req.name {
        sqlx::query!(
            "UPDATE service_accounts SET name = $1 WHERE id = $2",
            check_name(name)?,
            &sa_id,
        )
        .execute(&mut *tx)
        .await?;
    }
    if let Some(expires_at) = req.expires_at {
        check_expiry(expires_at)?;
        sqlx::query!(
            "UPDATE service_accounts SET expires_at = $1 WHERE id = $2",
            expires_at,
            &sa_id,
        )
        .execute(&mut *tx)
        .await?;
    }
    sa_event(&mut tx, &sa_id, "updated", "", &ip).await;
    let row = owned(&mut tx, &sa_id, &session.account_id).await?;
    let info = info(&mut tx, row).await?;
    tx.commit().await?;
    Ok(Json(info))
}

#[derive(Deserialize)]
pub struct GrantsRequest {
    grants: Vec<GrantUploadJson>,
}

/// `PUT /service-accounts/{id}/grants`: adds or renews vault grants.
pub async fn put_grants(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(sa_id): Path<String>,
    Json(req): Json<GrantsRequest>,
) -> ApiResult<Json<ServiceAccountInfo>> {
    if req.grants.is_empty() || req.grants.len() > 100 {
        return Err(ApiError::bad_request("send 1 to 100 grants"));
    }
    let mut tx = state.db.as_account(&session.account_id).await?;
    let row = owned(&mut tx, &sa_id, &session.account_id).await?;
    if row.5 != 0 {
        return Err(ApiError::bad_request(
            "the service account was revoked; create a new one",
        ));
    }
    let sig_pk = owner_sig_pk(&mut tx, &session.account_id).await?;
    for grant in &req.grants {
        check_grant(&mut tx, &session.account_id, &sig_pk, &sa_id, &row.2, grant).await?;
    }
    for grant in &req.grants {
        insert_grant(&mut tx, &sa_id, grant).await?;
    }
    let count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"count!\" FROM service_account_grants WHERE service_account_id = $1",
        &sa_id,
    )
    .fetch_one(&mut *tx)
    .await?;
    if count > MAX_GRANTS {
        return Err(ApiError::bad_request("too many vault grants"));
    }
    let vaults: Vec<&str> = req.grants.iter().map(|g| g.vault_id.as_str()).collect();
    sa_event(&mut tx, &sa_id, "access_granted", &vaults.join(","), &ip).await;
    let row = owned(&mut tx, &sa_id, &session.account_id).await?;
    let info = info(&mut tx, row).await?;
    tx.commit().await?;
    record_event(
        &state,
        &session.account_id,
        "service_account_access_changed",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    Ok(Json(info))
}

/// `DELETE /service-accounts/{id}/grants/{vault_id}`: removes a vault.
pub async fn delete_grant(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path((sa_id, vault_id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let mut tx = state.db.as_account(&session.account_id).await?;
    owned(&mut tx, &sa_id, &session.account_id).await?;
    let deleted = sqlx::query!(
        "DELETE FROM service_account_grants WHERE service_account_id = $1 AND vault_id = $2",
        &sa_id,
        &vault_id,
    )
    .execute(&mut *tx)
    .await?;
    if deleted.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    sa_event(&mut tx, &sa_id, "access_removed", &vault_id, &ip).await;
    tx.commit().await?;
    record_event(
        &state,
        &session.account_id,
        "service_account_access_changed",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /service-accounts/{id}/revoke`: the token stops working at once.
/// The service account stays listed with its activity.
pub async fn revoke(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(sa_id): Path<String>,
) -> ApiResult<StatusCode> {
    let mut tx = state.db.as_account(&session.account_id).await?;
    owned(&mut tx, &sa_id, &session.account_id).await?;
    sqlx::query!(
        "UPDATE service_accounts SET revoked_at = $1 WHERE id = $2 AND revoked_at = 0",
        now_ms(),
        &sa_id,
    )
    .execute(&mut *tx)
    .await?;
    // Sealed keys are useless without the token, but there is no reason to
    // keep them.
    sqlx::query!(
        "DELETE FROM service_account_grants WHERE service_account_id = $1",
        &sa_id,
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!(
        "UPDATE agent_grants SET status = 'revoked' WHERE principal_kind = 'service' \
         AND principal_id = $1 AND status IN ('pending', 'approved')",
        &sa_id,
    )
    .execute(&mut *tx)
    .await?;
    sa_event(&mut tx, &sa_id, "revoked", "", &ip).await;
    tx.commit().await?;
    record_event(
        &state,
        &session.account_id,
        "service_account_revoked",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /service-accounts/{id}`: removes the service account and its
/// activity.
pub async fn delete(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(sa_id): Path<String>,
) -> ApiResult<StatusCode> {
    let mut tx = state.db.as_account(&session.account_id).await?;
    owned(&mut tx, &sa_id, &session.account_id).await?;
    for table in [
        "DELETE FROM service_account_grants WHERE service_account_id = $1",
        "DELETE FROM service_account_events WHERE service_account_id = $1",
        "DELETE FROM service_accounts WHERE id = $1",
    ] {
        sqlx::query(table).bind(&sa_id).execute(&mut *tx).await?;
    }
    sqlx::query!(
        "UPDATE agent_grants SET status = 'revoked' WHERE principal_kind = 'service' \
         AND principal_id = $1 AND status IN ('pending', 'approved')",
        &sa_id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    record_event(
        &state,
        &session.account_id,
        "service_account_deleted",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct EventsQuery {
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountEvent {
    id: String,
    kind: String,
    detail: String,
    ip: String,
    created_at: i64,
}

/// `GET /service-accounts/{id}/events`: what the service account did.
pub async fn events(
    State(state): State<AppState>,
    session: Session,
    Path(sa_id): Path<String>,
    Query(query): Query<EventsQuery>,
) -> ApiResult<Json<Vec<ServiceAccountEvent>>> {
    let mut conn = state.db.as_account(&session.account_id).await?;
    owned(&mut conn, &sa_id, &session.account_id).await?;
    let rows: Vec<(String, String, String, String, i64)> = sqlx::query!(
        "SELECT id, kind, detail, ip, created_at FROM service_account_events \
         WHERE service_account_id = $1 ORDER BY created_at DESC LIMIT $2",
        &sa_id,
        query.limit.unwrap_or(50).clamp(1, 200),
    )
    .map(|row| (row.id, row.kind, row.detail, row.ip, row.created_at))
    .fetch_all(&mut *conn)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(id, kind, detail, ip, created_at)| ServiceAccountEvent {
                id,
                kind,
                detail,
                ip,
                created_at,
            })
            .collect(),
    ))
}

// --- Service account authentication -------------------------------------------------

/// A request authenticated as a service account:
/// `Authorization: Bearer sa.{id}.{auth_key}`.
pub struct ServiceAuth {
    pub id: String,
    pub owner_id: String,
    pub name: String,
    pub ip: String,
}

impl FromRequestParts<AppState> for ServiceAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let ClientIp(ip) = ClientIp::from_request_parts(parts, state)
            .await
            .unwrap_or_else(|e| match e {});
        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(ApiError::Unauthorized)?;
        let (sa_id, auth_key) = header
            .strip_prefix("Bearer sa.")
            .and_then(|v| v.split_once('.'))
            .ok_or(ApiError::Unauthorized)?;
        if !id::is_valid_id(sa_id) || auth_key.is_empty() || auth_key.len() > 64 {
            return Err(ApiError::Unauthorized);
        }
        if let Some(wait) = state.limiter.hit(
            &format!("sa:{sa_id}"),
            MAX_REQUESTS_PER_MINUTE,
            std::time::Duration::from_secs(60),
        ) {
            return Err(ApiError::RateLimited(wait));
        }
        let now = now_ms();
        // Signed-out requests cannot read service accounts: the function
        // resolves this one ID.
        let row: Option<(String, String, String, i64, i64, i64)> = sqlx::query!(
            r#"SELECT account_id AS "account_id!", name AS "name!", auth_hash AS "auth_hash!",
                      expires_at AS "expires_at!", revoked_at AS "revoked_at!",
                      last_used_at AS "last_used_at!"
               FROM passbox.service_account_by_id($1)"#,
            sa_id,
        )
        .map(|row| {
            (
                row.account_id,
                row.name,
                row.auth_hash,
                row.expires_at,
                row.revoked_at,
                row.last_used_at,
            )
        })
        .fetch_optional(&mut *state.db.public(Public::Auth).await?)
        .await?;
        let (owner_id, name, auth_hash, expires_at, revoked_at, last_used_at) =
            row.ok_or(ApiError::Unauthorized)?;
        if sa::auth_hash(auth_key) != auth_hash {
            return Err(ApiError::Unauthorized);
        }
        if revoked_at != 0 {
            return Err(ApiError::forbidden(
                "service_account_revoked",
                "this service account was revoked; ask its owner for a new token",
            ));
        }
        if expires_at != 0 && expires_at <= now {
            return Err(ApiError::forbidden(
                "service_account_expired",
                "this service account expired; its owner can extend it in Passbox",
            ));
        }
        if now - last_used_at > LAST_USED_RESOLUTION_MS {
            // A service account acts with its owner's rights.
            let mut tx = state.db.as_account(&owner_id).await?;
            sqlx::query!(
                "UPDATE service_accounts SET last_used_at = $1, last_used_ip = $2 WHERE id = $3",
                now,
                &ip,
                sa_id,
            )
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
        }
        Ok(Self {
            id: sa_id.to_owned(),
            owner_id,
            name,
            ip,
        })
    }
}

/// What the service account may currently do with a vault: the lower of
/// its grant and the owner's live access. `None` without access.
async fn effective(
    conn: &mut PgConnection,
    auth: &ServiceAuth,
    vault_id: &str,
) -> ApiResult<Option<(Permission, i64)>> {
    let permission: Option<String> = sqlx::query_scalar!(
        "SELECT permission FROM service_account_grants WHERE service_account_id = $1 \
         AND vault_id = $2 LIMIT 1",
        &auth.id,
        vault_id,
    )
    .fetch_optional(&mut *conn)
    .await?;
    let Some(permission) = permission.and_then(|p| Permission::parse(&p).ok()) else {
        return Ok(None);
    };
    let Some(access) = access::vault_access(conn, vault_id, &auth.owner_id).await? else {
        return Ok(None);
    };
    let epoch = match &access {
        VaultAccess::Personal => 0,
        VaultAccess::Shared { key_epoch, .. } => *key_epoch,
    };
    let permission = if access.can_write() {
        permission
    } else {
        Permission::Read
    };
    Ok(Some((permission, epoch)))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SaGrantRecord {
    vault_id: String,
    key_epoch: i64,
    permission: String,
    sealed_key: String,
    grant: String,
    grant_signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SaVault {
    id: String,
    encrypted_meta: String,
    key_epoch: i64,
    revision: i64,
    /// Effective permission: `read` or `write`.
    permission: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    org_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SaItem {
    id: String,
    vault_id: String,
    revision: i64,
    encrypted_data: String,
    key_epoch: i64,
    updated_at: i64,
    created_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SaState {
    id: String,
    name: String,
    owner_id: String,
    expires_at: i64,
    public_key: String,
    encrypted_private: String,
    grants: Vec<SaGrantRecord>,
    vaults: Vec<SaVault>,
    items: Vec<SaItem>,
}

/// `GET /service-account`: everything the service account can read.
pub async fn state(State(state): State<AppState>, auth: ServiceAuth) -> ApiResult<Json<SaState>> {
    let mut conn = state.db.as_account(&auth.owner_id).await?;
    let (public_key, encrypted_private, expires_at): (String, Vec<u8>, i64) = sqlx::query!(
        "SELECT public_key, encrypted_private, expires_at FROM service_accounts WHERE id = $1",
        &auth.id,
    )
    .map(|row| (row.public_key, row.encrypted_private, row.expires_at))
    .fetch_one(&mut *conn)
    .await?;
    let rows: Vec<(String, i64, String, Vec<u8>, String, String)> = sqlx::query!(
        "SELECT vault_id, key_epoch, permission, sealed_key, grant_data, grant_signature \
         FROM service_account_grants WHERE service_account_id = $1 ORDER BY vault_id, key_epoch",
        &auth.id,
    )
    .map(|row| {
        (
            row.vault_id,
            row.key_epoch,
            row.permission,
            row.sealed_key,
            row.grant_data,
            row.grant_signature,
        )
    })
    .fetch_all(&mut *conn)
    .await?;
    let mut grants = Vec::new();
    let mut vaults = Vec::new();
    let mut items = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (vault_id, key_epoch, permission, sealed_key, grant, grant_signature) in rows {
        let Some((effective, _)) = effective(&mut conn, &auth, &vault_id).await? else {
            continue;
        };
        grants.push(SaGrantRecord {
            vault_id: vault_id.clone(),
            key_epoch,
            permission,
            sealed_key: encoding::encode(&sealed_key),
            grant,
            grant_signature,
        });
        if !seen.insert(vault_id.clone()) {
            continue;
        }
        let (encrypted_meta, epoch, revision, org_id): (Vec<u8>, i64, i64, Option<String>) =
            sqlx::query!(
                "SELECT encrypted_meta, key_epoch, revision, org_id FROM vaults WHERE id = $1",
                &vault_id,
            )
            .map(|row| (row.encrypted_meta, row.key_epoch, row.revision, row.org_id))
            .fetch_one(&mut *conn)
            .await?;
        vaults.push(SaVault {
            id: vault_id.clone(),
            encrypted_meta: encoding::encode(&encrypted_meta),
            key_epoch: epoch,
            revision,
            permission: effective.as_str().to_owned(),
            org_id,
        });
        let rows = sqlx::query!(
            "SELECT id, revision, encrypted_data, key_epoch, updated_at, created_at FROM items \
             WHERE vault_id = $1 AND deleted = false",
            &vault_id,
        )
        .map(|row| {
            (
                row.id,
                row.revision,
                row.encrypted_data,
                row.key_epoch,
                row.updated_at,
                row.created_at,
            )
        })
        .fetch_all(&mut *conn)
        .await?;
        items.extend(rows.into_iter().filter_map(
            |(id, revision, data, key_epoch, updated_at, created_at)| {
                Some(SaItem {
                    id,
                    vault_id: vault_id.clone(),
                    revision,
                    encrypted_data: encoding::encode(&data?),
                    key_epoch,
                    updated_at,
                    created_at,
                })
            },
        ));
    }
    sa_event(
        &mut conn,
        &auth.id,
        "read",
        &format!("{} vaults, {} items", vaults.len(), items.len()),
        &auth.ip,
    )
    .await;
    Ok(Json(SaState {
        id: auth.id,
        name: auth.name,
        owner_id: auth.owner_id,
        expires_at,
        public_key,
        encrypted_private: encoding::encode(&encrypted_private),
        grants,
        vaults,
        items,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutItemRequest {
    vault_id: String,
    revision: i64,
    encrypted_data: String,
    #[serde(default)]
    key_epoch: i64,
}

async fn require_write(
    conn: &mut PgConnection,
    auth: &ServiceAuth,
    vault_id: &str,
    key_epoch: i64,
) -> ApiResult<()> {
    match effective(conn, auth, vault_id).await? {
        None => Err(ApiError::NotFound),
        Some((Permission::Read, _)) => Err(ApiError::forbidden(
            "forbidden",
            "this service account can only read this vault",
        )),
        Some((Permission::Write, current)) if current != key_epoch => Err(ApiError::conflict(
            "the vault's key was rotated; its owner has to renew the service account's access",
            json!({ "currentKeyEpoch": current }),
        )),
        Some(_) => Ok(()),
    }
}

fn revision_conflict(current: i64) -> ApiError {
    ApiError::conflict(
        "item was changed by another device",
        json!({ "currentRevision": current }),
    )
}

/// `PUT /service-account/items/{id}`: creates or updates an item in a vault
/// the service account may write to.
pub async fn put_item(
    State(state): State<AppState>,
    auth: ServiceAuth,
    Path(item_id): Path<String>,
    Json(req): Json<PutItemRequest>,
) -> ApiResult<Json<WriteResponse>> {
    validate::id("item id", &item_id)?;
    validate::id("vaultId", &req.vault_id)?;
    validate::revision(req.revision)?;
    validate::base64("encryptedData", &req.encrypted_data, validate::MAX_ITEM_LEN)?;
    let encrypted_data = super::vaults::decode(&req.encrypted_data)?;
    let mut tx = state.db.as_account(&auth.owner_id).await?;
    require_write(&mut tx, &auth, &req.vault_id, req.key_epoch).await?;
    let current: Option<(String, i64)> = sqlx::query!(
        "SELECT vault_id, revision FROM items WHERE id = $1",
        &item_id,
    )
    .map(|row| (row.vault_id, row.revision))
    .fetch_optional(&mut *tx)
    .await?;
    let now = now_ms();
    let seq = match current {
        None => {
            if req.revision != 1 {
                return Err(revision_conflict(0));
            }
            let seq = db::next_seq(&mut tx).await?;
            sqlx::query!(
                "INSERT INTO items (id, vault_id, encrypted_data, revision, deleted, seq, created_at, updated_at, \
                 key_epoch) VALUES ($1, $2, $3, 1, false, $4, $5, $6, $7)",
                &item_id,
                &req.vault_id,
                &encrypted_data,
                seq,
                now,
                now,
                req.key_epoch,
            )
            .execute(&mut *tx)
            .await?;
            seq
        }
        Some((vault_id, current)) => {
            if vault_id != req.vault_id {
                return Err(ApiError::NotFound);
            }
            if req.revision != current + 1 {
                return Err(revision_conflict(current));
            }
            let seq = db::next_seq(&mut tx).await?;
            sqlx::query!(
                "UPDATE items SET encrypted_data = $1, revision = $2, deleted = false, seq = $3, updated_at = $4, \
                 key_epoch = $5 WHERE id = $6",
                &encrypted_data,
                req.revision,
                seq,
                now,
                req.key_epoch,
                &item_id,
            )
            .execute(&mut *tx)
            .await?;
            seq
        }
    };
    sa_event(&mut tx, &auth.id, "item_written", &item_id, &auth.ip).await;
    tx.commit().await?;
    Ok(Json(WriteResponse {
        revision: req.revision,
        seq,
    }))
}

#[derive(Deserialize)]
pub struct DeleteQuery {
    revision: i64,
}

/// `DELETE /service-account/items/{id}?revision=n`.
pub async fn delete_item(
    State(state): State<AppState>,
    auth: ServiceAuth,
    Path(item_id): Path<String>,
    Query(query): Query<DeleteQuery>,
) -> ApiResult<Json<WriteResponse>> {
    validate::id("item id", &item_id)?;
    validate::revision(query.revision)?;
    let mut tx = state.db.as_account(&auth.owner_id).await?;
    let (vault_id, current): (String, i64) = sqlx::query!(
        "SELECT vault_id, revision FROM items WHERE id = $1",
        &item_id,
    )
    .map(|row| (row.vault_id, row.revision))
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    match effective(&mut tx, &auth, &vault_id).await? {
        None => return Err(ApiError::NotFound),
        Some((Permission::Read, _)) => {
            return Err(ApiError::forbidden(
                "forbidden",
                "this service account can only read this vault",
            ));
        }
        Some(_) => {}
    }
    if query.revision != current + 1 {
        return Err(revision_conflict(current));
    }
    let seq = db::next_seq(&mut tx).await?;
    sqlx::query!(
        "UPDATE items SET encrypted_data = NULL, revision = $1, deleted = true, seq = $2, updated_at = $3 WHERE id = $4",
        query.revision,
        seq,
        now_ms(),
        &item_id,
    )
    .execute(&mut *tx)
    .await?;
    sa_event(&mut tx, &auth.id, "item_deleted", &item_id, &auth.ip).await;
    tx.commit().await?;
    Ok(Json(WriteResponse {
        revision: query.revision,
        seq,
    }))
}
