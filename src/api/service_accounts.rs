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
use sqlx::AnyConnection;

use super::access::{self, VaultAccess};
use super::auth::{Session, record_event};
use super::validate;
use super::vaults::WriteResponse;
use crate::db::{self, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::security::ClientIp;
use crate::state::AppState;

/// Service accounts per account.
const MAX_PER_ACCOUNT: i64 = 50;
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
async fn owner_sig_pk(conn: &mut AnyConnection, account_id: &str) -> ApiResult<[u8; 32]> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT bundle, bundle_signature FROM account_keys WHERE account_id = $1 \
         ORDER BY key_version DESC LIMIT 1",
    )
    .bind(account_id)
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
    conn: &mut AnyConnection,
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
        VaultAccess::Shared { key_epoch, .. } => *key_epoch,
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
    conn: &mut AnyConnection,
    sa_id: &str,
    upload: &GrantUploadJson,
) -> ApiResult<()> {
    sqlx::query(
        "DELETE FROM service_account_grants WHERE service_account_id = $1 AND vault_id = $2 \
         AND key_epoch = $3",
    )
    .bind(sa_id)
    .bind(&upload.vault_id)
    .bind(upload.key_epoch)
    .execute(&mut *conn)
    .await?;
    // A changed permission applies to every epoch of the vault.
    sqlx::query(
        "UPDATE service_account_grants SET permission = $1 WHERE service_account_id = $2 \
         AND vault_id = $3",
    )
    .bind(&upload.permission)
    .bind(sa_id)
    .bind(&upload.vault_id)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO service_account_grants (service_account_id, vault_id, key_epoch, permission, \
         sealed_key, grant_data, grant_signature, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(sa_id)
    .bind(&upload.vault_id)
    .bind(upload.key_epoch)
    .bind(&upload.permission)
    .bind(&upload.sealed_key)
    .bind(&upload.grant)
    .bind(&upload.grant_signature)
    .bind(now_ms())
    .execute(&mut *conn)
    .await?;
    Ok(())
}

async fn sa_event(conn: &mut AnyConnection, sa_id: &str, kind: &str, detail: &str, ip: &str) {
    let result = sqlx::query(
        "INSERT INTO service_account_events (id, service_account_id, kind, detail, ip, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id::new_id().unwrap_or_default())
    .bind(sa_id)
    .bind(kind)
    .bind(detail)
    .bind(ip)
    .bind(now_ms())
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

async fn info(conn: &mut AnyConnection, row: SaRow) -> ApiResult<ServiceAccountInfo> {
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

/// `GET /service-accounts`: the account's service accounts, newest first.
pub async fn list(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<Json<Vec<ServiceAccountInfo>>> {
    let mut conn = state.db.acquire().await?;
    let rows: Vec<SaRow> = sqlx::query_as(
        "SELECT id, name, public_key, public_key_signature, expires_at, revoked_at, last_used_at, \
         last_used_ip, created_at FROM service_accounts WHERE account_id = $1 ORDER BY created_at DESC",
    )
    .bind(&session.account_id)
    .fetch_all(&mut *conn)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(info(&mut conn, row).await?);
    }
    Ok(Json(out))
}

async fn owned(conn: &mut AnyConnection, sa_id: &str, account_id: &str) -> ApiResult<SaRow> {
    sqlx::query_as(
        "SELECT id, name, public_key, public_key_signature, expires_at, revoked_at, last_used_at, \
         last_used_ip, created_at FROM service_accounts WHERE id = $1 AND account_id = $2",
    )
    .bind(sa_id)
    .bind(account_id)
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
    let mut tx = db::begin_write(&state.db).await?;
    let sig_pk = owner_sig_pk(&mut tx, &session.account_id).await?;
    let public = PublicKey::verify(&req.public_key, &req.public_key_signature, &sig_pk)
        .map_err(|_| ApiError::bad_request("the public key is not signed by your account key"))?;
    if public.id != req.id || public.owner_id != session.account_id {
        return Err(ApiError::bad_request(
            "the public key does not match the request",
        ));
    }
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM service_accounts WHERE account_id = $1")
            .bind(&session.account_id)
            .fetch_one(&mut *tx)
            .await?;
    if count >= MAX_PER_ACCOUNT {
        return Err(ApiError::bad_request(format!(
            "an account can have at most {MAX_PER_ACCOUNT} service accounts; delete one first"
        )));
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
    let inserted = sqlx::query(
        "INSERT INTO service_accounts (id, account_id, name, public_key, public_key_signature, \
         encrypted_private, auth_hash, expires_at, revoked_at, last_used_at, last_used_ip, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, 0, '', $9)",
    )
    .bind(&req.id)
    .bind(&session.account_id)
    .bind(&name)
    .bind(&req.public_key)
    .bind(&req.public_key_signature)
    .bind(&req.encrypted_private)
    .bind(req.auth_hash.to_ascii_lowercase())
    .bind(req.expires_at)
    .bind(now)
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
    let mut tx = db::begin_write(&state.db).await?;
    owned(&mut tx, &sa_id, &session.account_id).await?;
    if let Some(name) = &req.name {
        sqlx::query("UPDATE service_accounts SET name = $1 WHERE id = $2")
            .bind(check_name(name)?)
            .bind(&sa_id)
            .execute(&mut *tx)
            .await?;
    }
    if let Some(expires_at) = req.expires_at {
        check_expiry(expires_at)?;
        sqlx::query("UPDATE service_accounts SET expires_at = $1 WHERE id = $2")
            .bind(expires_at)
            .bind(&sa_id)
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
    let mut tx = db::begin_write(&state.db).await?;
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
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM service_account_grants WHERE service_account_id = $1",
    )
    .bind(&sa_id)
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
    let mut tx = db::begin_write(&state.db).await?;
    owned(&mut tx, &sa_id, &session.account_id).await?;
    let deleted = sqlx::query(
        "DELETE FROM service_account_grants WHERE service_account_id = $1 AND vault_id = $2",
    )
    .bind(&sa_id)
    .bind(&vault_id)
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
    let mut tx = db::begin_write(&state.db).await?;
    owned(&mut tx, &sa_id, &session.account_id).await?;
    sqlx::query("UPDATE service_accounts SET revoked_at = $1 WHERE id = $2 AND revoked_at = 0")
        .bind(now_ms())
        .bind(&sa_id)
        .execute(&mut *tx)
        .await?;
    // Sealed keys are useless without the token, but there is no reason to
    // keep them.
    sqlx::query("DELETE FROM service_account_grants WHERE service_account_id = $1")
        .bind(&sa_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE agent_grants SET status = 'revoked' WHERE principal_kind = 'service' \
         AND principal_id = $1 AND status IN ('pending', 'approved')",
    )
    .bind(&sa_id)
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
    let mut tx = db::begin_write(&state.db).await?;
    owned(&mut tx, &sa_id, &session.account_id).await?;
    for table in [
        "DELETE FROM service_account_grants WHERE service_account_id = $1",
        "DELETE FROM service_account_events WHERE service_account_id = $1",
        "DELETE FROM service_accounts WHERE id = $1",
    ] {
        sqlx::query(table).bind(&sa_id).execute(&mut *tx).await?;
    }
    sqlx::query(
        "UPDATE agent_grants SET status = 'revoked' WHERE principal_kind = 'service' \
         AND principal_id = $1 AND status IN ('pending', 'approved')",
    )
    .bind(&sa_id)
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
    let mut conn = state.db.acquire().await?;
    owned(&mut conn, &sa_id, &session.account_id).await?;
    let rows: Vec<(String, String, String, String, i64)> = sqlx::query_as(
        "SELECT id, kind, detail, ip, created_at FROM service_account_events \
         WHERE service_account_id = $1 ORDER BY created_at DESC LIMIT $2",
    )
    .bind(&sa_id)
    .bind(query.limit.unwrap_or(50).clamp(1, 200))
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
        let row: Option<(String, String, String, i64, i64, i64)> = sqlx::query_as(
            "SELECT s.account_id, s.name, s.auth_hash, s.expires_at, s.revoked_at, s.last_used_at \
             FROM service_accounts s JOIN accounts a ON a.id = s.account_id \
             WHERE s.id = $1 AND a.disabled_at = 0",
        )
        .bind(sa_id)
        .fetch_optional(&state.db)
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
            sqlx::query(
                "UPDATE service_accounts SET last_used_at = $1, last_used_ip = $2 WHERE id = $3",
            )
            .bind(now)
            .bind(&ip)
            .bind(sa_id)
            .execute(&state.db)
            .await?;
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
    conn: &mut AnyConnection,
    auth: &ServiceAuth,
    vault_id: &str,
) -> ApiResult<Option<(Permission, i64)>> {
    let permission: Option<String> = sqlx::query_scalar(
        "SELECT permission FROM service_account_grants WHERE service_account_id = $1 \
         AND vault_id = $2 LIMIT 1",
    )
    .bind(&auth.id)
    .bind(vault_id)
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
    let mut conn = state.db.acquire().await?;
    let (public_key, encrypted_private, expires_at): (String, String, i64) = sqlx::query_as(
        "SELECT public_key, encrypted_private, expires_at FROM service_accounts WHERE id = $1",
    )
    .bind(&auth.id)
    .fetch_one(&mut *conn)
    .await?;
    let rows: Vec<(String, i64, String, String, String, String)> = sqlx::query_as(
        "SELECT vault_id, key_epoch, permission, sealed_key, grant_data, grant_signature \
         FROM service_account_grants WHERE service_account_id = $1 ORDER BY vault_id, key_epoch",
    )
    .bind(&auth.id)
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
            sealed_key,
            grant,
            grant_signature,
        });
        if !seen.insert(vault_id.clone()) {
            continue;
        }
        let (encrypted_meta, epoch, revision, org_id): (String, i64, i64, Option<String>) =
            sqlx::query_as(
                "SELECT encrypted_meta, key_epoch, revision, org_id FROM vaults WHERE id = $1",
            )
            .bind(&vault_id)
            .fetch_one(&mut *conn)
            .await?;
        vaults.push(SaVault {
            id: vault_id.clone(),
            encrypted_meta,
            key_epoch: epoch,
            revision,
            permission: effective.as_str().to_owned(),
            org_id,
        });
        let rows: Vec<(String, i64, Option<String>, i64, i64)> = sqlx::query_as(
            "SELECT id, revision, encrypted_data, key_epoch, updated_at FROM items \
             WHERE vault_id = $1 AND deleted = 0",
        )
        .bind(&vault_id)
        .fetch_all(&mut *conn)
        .await?;
        items.extend(
            rows.into_iter()
                .filter_map(|(id, revision, data, key_epoch, updated_at)| {
                    Some(SaItem {
                        id,
                        vault_id: vault_id.clone(),
                        revision,
                        encrypted_data: data?,
                        key_epoch,
                        updated_at,
                    })
                }),
        );
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
        encrypted_private,
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
    conn: &mut AnyConnection,
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
    let mut tx = db::begin_write(&state.db).await?;
    require_write(&mut tx, &auth, &req.vault_id, req.key_epoch).await?;
    let current: Option<(String, i64)> =
        sqlx::query_as("SELECT vault_id, revision FROM items WHERE id = $1")
            .bind(&item_id)
            .fetch_optional(&mut *tx)
            .await?;
    let now = now_ms();
    let seq = match current {
        None => {
            if req.revision != 1 {
                return Err(revision_conflict(0));
            }
            let seq = db::next_seq(&mut tx).await?;
            sqlx::query(
                "INSERT INTO items (id, vault_id, encrypted_data, revision, deleted, seq, created_at, updated_at, \
                 key_epoch) VALUES ($1, $2, $3, 1, 0, $4, $5, $6, $7)",
            )
            .bind(&item_id)
            .bind(&req.vault_id)
            .bind(&req.encrypted_data)
            .bind(seq)
            .bind(now)
            .bind(now)
            .bind(req.key_epoch)
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
            sqlx::query(
                "UPDATE items SET encrypted_data = $1, revision = $2, deleted = 0, seq = $3, updated_at = $4, \
                 key_epoch = $5 WHERE id = $6",
            )
            .bind(&req.encrypted_data)
            .bind(req.revision)
            .bind(seq)
            .bind(now)
            .bind(req.key_epoch)
            .bind(&item_id)
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
    let mut tx = db::begin_write(&state.db).await?;
    let (vault_id, current): (String, i64) =
        sqlx::query_as("SELECT vault_id, revision FROM items WHERE id = $1")
            .bind(&item_id)
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
    sqlx::query(
        "UPDATE items SET encrypted_data = NULL, revision = $1, deleted = 1, seq = $2, updated_at = $3 WHERE id = $4",
    )
    .bind(query.revision)
    .bind(seq)
    .bind(now_ms())
    .bind(&item_id)
    .execute(&mut *tx)
    .await?;
    sa_event(&mut tx, &auth.id, "item_deleted", &item_id, &auth.ip).await;
    tx.commit().await?;
    Ok(Json(WriteResponse {
        revision: query.revision,
        seq,
    }))
}
