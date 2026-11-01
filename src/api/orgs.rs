//! Organizations (family and team), members, roles and invitations.
//!
//! Flow: an admin invites by email (the server stores a token hash and
//! returns the link) → the invitee signs in, publishes keys and accepts
//! (`accepted`) → an admin's client verifies the invitee's key, signs an
//! attestation and seals the organization key (`confirmed`).

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use data_encoding::HEXLOWER;
use passbox_core::identity::{SignedBundle, sealed_hash};
use passbox_core::sharing::build::{
    ConfirmMember, MemberAttestationUpload, NewOrg, OrgKeyUpload, RotateOrgKey,
};
use passbox_core::sharing::data::{OrgRecord, RosterMember, RosterRecord};
use passbox_core::sharing::objects::{
    MemberAttestation, OrgGenesis, OrgKeyGrant, OrgKind, OrgRole, Signed,
};
use passbox_core::{encoding, id, random};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::PgConnection;

use super::access::{self, Membership};
use super::auth::{Session, record_event};
use super::signed::{self, bad};
use super::validate;
use super::vaults::decode;
use crate::db::{self, Public, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::ext::{Joining, OrgLock};
use crate::mail::{Mailer, Template};
use crate::security::ClientIp;
use crate::state::AppState;

/// Invitations are valid for 7 days.
const INVITATION_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// Invitations an account may create per hour, and pending invitations
/// per organization.
const INVITATIONS_PER_HOUR: u32 = 50;
const MAX_PENDING_INVITATIONS: i64 = 500;
/// Invitation lookups and acceptances per IP and minute.
const INVITATION_REQUESTS_PER_MINUTE: u32 = 30;

fn hash_token(token: &str) -> String {
    HEXLOWER.encode(&Sha256::digest(token.as_bytes()))
}

fn limit(state: &AppState, key: String, max: u32, window_secs: u64) -> ApiResult<()> {
    match state
        .limiter
        .hit(&key, max, std::time::Duration::from_secs(window_secs))
    {
        Some(wait) => Err(ApiError::RateLimited(wait)),
        None => Ok(()),
    }
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

/// Checks an organization key upload for `account_bundle`.
fn check_org_key(
    key: &OrgKeyUpload,
    org_id: &str,
    epoch: u32,
    account_bundle: &SignedBundle,
    me: &SignedBundle,
) -> ApiResult<()> {
    let grant = signed::parse::<OrgKeyGrant>("grant", &key.grant, &key.grant_signature, me)?;
    let sealed = signed::sealed("sealedKey", &key.sealed_key)?;
    let g = &grant.value;
    if g.org_id != org_id
        || g.epoch != epoch
        || key.epoch != epoch
        || g.account_id != account_bundle.bundle.account_id
        || key.account_id != g.account_id
        || g.account_bundle_hash != account_bundle.hash()
        || g.sealed_hash != sealed_hash(&sealed)
        || g.granter_id != me.bundle.account_id
    {
        return Err(bad("the organization key grant does not match"));
    }
    Ok(())
}

async fn insert_org_key(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: &str,
    key: &OrgKeyUpload,
    seq: i64,
    now: i64,
) -> ApiResult<()> {
    sqlx::query!(
        "DELETE FROM org_keys WHERE org_id = $1 AND epoch = $2 AND account_id = $3",
        org_id,
        i64::from(key.epoch),
        &key.account_id,
    )
    .execute(&mut **tx)
    .await?;
    sqlx::query!(
        "INSERT INTO org_keys (org_id, epoch, account_id, sealed_key, grant_data, grant_signature, seq, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        org_id,
        i64::from(key.epoch),
        &key.account_id,
        decode(&key.sealed_key)?,
        &key.grant,
        &key.grant_signature,
        seq,
        now,
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedOrg {
    id: String,
    seq: i64,
    default_vault_id: Option<String>,
}

/// Creates an organization owned by the caller. Family organizations come
/// with their shared family vault.
pub async fn create(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Json(req): Json<NewOrg>,
) -> ApiResult<(StatusCode, Json<CreatedOrg>)> {
    validate::id("organization id", &req.id)?;
    validate::base64(
        "encryptedMeta",
        &req.encrypted_meta,
        validate::MAX_SMALL_LEN,
    )?;
    let kind = OrgKind::parse(&req.kind).map_err(|_| bad("kind must be family or team"))?;
    if req.meta_epoch != 1 {
        return Err(bad("a new organization starts at key epoch 1"));
    }
    if kind == OrgKind::Family && req.vault.is_none() {
        return Err(bad("a family organization needs its family vault"));
    }
    limit(
        &state,
        format!("org-create:{}", session.account_id),
        20,
        3600,
    )?;

    let mut tx = state.db.as_account(&session.account_id).await?;
    let me = signed::own_bundle(&mut tx, &session.account_id).await?;
    let genesis =
        signed::parse::<OrgGenesis>("genesis", &req.genesis, &req.genesis_signature, &me)?;
    let g = &genesis.value;
    if g.org_id != req.id
        || g.kind != kind
        || g.owner_id != session.account_id
        || g.owner_bundle_hash != me.hash()
    {
        return Err(bad("the genesis does not match the organization"));
    }
    check_org_key(&req.org_key, &req.id, 1, &me, &me)?;

    let now = now_ms();
    let seq = db::next_seq(&mut tx).await?;
    let inserted = sqlx::query!(
        "INSERT INTO organizations (id, kind, owner_id, genesis, genesis_signature, encrypted_meta, meta_epoch, \
         default_vault_id, revision, seq, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 1, $7, 1, $8, $9, $10) ON CONFLICT DO NOTHING",
        &req.id,
        kind.as_str(),
        &session.account_id,
        &req.genesis,
        &req.genesis_signature,
        decode(&req.encrypted_meta)?,
        req.vault.as_ref().map(|v| v.id.clone()),
        seq,
        now,
        now,
    )
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::conflict(
            "organization already exists",
            serde_json::Value::Null,
        ));
    }
    sqlx::query!(
        "INSERT INTO org_members (org_id, account_id, role, status, attestation, attestation_signature, \
         invited_by, seq, created_at, updated_at) VALUES ($1, $2, 'owner', 'confirmed', NULL, NULL, $3, $4, $5, $6)",
        &req.id,
        &session.account_id,
        &session.account_id,
        seq,
        now,
        now,
    )
    .execute(&mut *tx)
    .await?;
    insert_org_key(&mut tx, &req.id, &req.org_key, seq, now).await?;
    if let Some(vault) = &req.vault {
        super::shared::insert_shared_vault(&mut tx, &req.id, &me, vault, now).await?;
    }
    super::org_audit::record_in(
        &mut tx,
        &req.id,
        &super::org_audit::Actor::of(&session, &ip),
        "org_created",
        super::org_audit::Target::org(&req.id),
        json!({ "kind": kind.as_str() }),
    )
    .await?;
    tx.commit().await?;
    crate::ext::emit(
        &state,
        crate::ext::OrgEvent::Created {
            org_id: req.id.clone(),
            kind,
            owner_id: session.account_id.clone(),
        },
    );
    event(&state, &session.account_id, "org_created", &session, &ip).await?;
    Ok((
        StatusCode::CREATED,
        Json(CreatedOrg {
            id: req.id,
            seq,
            default_vault_id: req.vault.map(|v| v.id),
        }),
    ))
}

/// An organization as clients get it: the record and whether it is
/// read-only (`lock`, `null` otherwise).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgView {
    #[serde(flatten)]
    org: OrgRecord,
    lock: Option<OrgLock>,
}

/// The organizations an account belongs to, with its own role and status,
/// the change sequence and the lock.
pub async fn org_records(
    conn: &mut PgConnection,
    account_id: &str,
) -> ApiResult<Vec<(OrgRecord, i64, Option<OrgLock>)>> {
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        String,
        String,
        String,
        String,
        String,
        String,
        db::B64,
        i64,
        i64,
        Option<String>,
        i64,
        i64,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT organizations.id, organizations.kind, org_members.role, org_members.status, \
             organizations.genesis, organizations.genesis_signature, organizations.encrypted_meta, \
             organizations.meta_epoch, organizations.revision, organizations.default_vault_id, \
             organizations.seq, org_members.seq, org_locks.reason, org_locks.source FROM org_members \
             JOIN organizations ON organizations.id = org_members.org_id \
             LEFT JOIN org_locks ON org_locks.org_id = org_members.org_id \
             WHERE org_members.account_id = $1 ORDER BY organizations.created_at",
    )
    .bind(account_id)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                kind,
                role,
                status,
                genesis,
                genesis_signature,
                encrypted_meta,
                meta_epoch,
                revision,
                default_vault_id,
                org_seq,
                member_seq,
                lock_reason,
                lock_source,
            )| {
                (
                    OrgRecord {
                        id,
                        kind,
                        role,
                        status,
                        genesis,
                        genesis_signature,
                        encrypted_meta: encrypted_meta.0,
                        meta_epoch: u32::try_from(meta_epoch).unwrap_or_default(),
                        revision: u64::try_from(revision).unwrap_or_default(),
                        default_vault_id,
                    },
                    org_seq.max(member_seq),
                    lock_reason
                        .zip(lock_source)
                        .map(|(reason, source)| OrgLock { reason, source }),
                )
            },
        )
        .collect())
}

/// The member list of an organization with keys and attestations, and the
/// highest change sequence among its members.
pub async fn roster(conn: &mut PgConnection, org_id: &str) -> ApiResult<(RosterRecord, i64)> {
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        i64,
    )> = sqlx::query!(
        r#"SELECT org_members.account_id, org_members.role, org_members.status,
                  accounts.email AS "email!", public_keys.bundle AS "bundle?",
                  public_keys.bundle_signature AS "bundle_signature?", org_members.attestation,
                  org_members.attestation_signature, org_members.seq FROM org_members
             JOIN account_directory accounts ON accounts.id = org_members.account_id
             LEFT JOIN public_keys ON public_keys.account_id = org_members.account_id
             WHERE org_members.org_id = $1 ORDER BY org_members.created_at"#,
        org_id,
    )
    .map(|row| {
        (
            row.account_id,
            row.role,
            row.status,
            row.email,
            row.bundle,
            row.bundle_signature,
            row.attestation,
            row.attestation_signature,
            row.seq,
        )
    })
    .fetch_all(&mut *conn)
    .await?;
    let max_seq = rows.iter().map(|r| r.8).max().unwrap_or(0);
    Ok((
        RosterRecord {
            org_id: org_id.to_owned(),
            members: rows
                .into_iter()
                .map(
                    |(
                        account_id,
                        role,
                        status,
                        email,
                        bundle,
                        bundle_signature,
                        attestation,
                        attestation_signature,
                        _,
                    )| {
                        RosterMember {
                            account_id,
                            role,
                            status,
                            email: Some(email),
                            bundle,
                            bundle_signature,
                            attestation,
                            attestation_signature,
                        }
                    },
                )
                .collect(),
        },
        max_seq,
    ))
}

/// The caller's organizations.
pub async fn list(
    State(state): State<AppState>,
    session: Session,
) -> ApiResult<Json<Vec<OrgView>>> {
    let mut conn = state.db.as_account(&session.account_id).await?;
    Ok(Json(
        org_records(&mut conn, &session.account_id)
            .await?
            .into_iter()
            .map(|(org, _, lock)| OrgView { org, lock })
            .collect(),
    ))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgDetail {
    #[serde(flatten)]
    org: OrgView,
    members: Vec<RosterMember>,
}

/// An organization with its members (members only; 404 for others).
pub async fn get(
    State(state): State<AppState>,
    session: Session,
    Path(org_id): Path<String>,
) -> ApiResult<Json<OrgDetail>> {
    validate::id("organization id", &org_id)?;
    let mut conn = state.db.as_account(&session.account_id).await?;
    let membership = access::require_member(&mut conn, &org_id, &session.account_id).await?;
    let org = org_records(&mut conn, &session.account_id)
        .await?
        .into_iter()
        .find(|(o, _, _)| o.id == org_id)
        .map(|(org, _, lock)| OrgView { org, lock })
        .ok_or(ApiError::NotFound)?;
    // Guests and unconfirmed members only see themselves and the admins.
    let (roster, _) = roster(&mut conn, &org_id).await?;
    let members = if membership.is_confirmed() && membership.role != OrgRole::Guest {
        roster.members
    } else {
        roster
            .members
            .into_iter()
            .filter(|m| {
                m.account_id == session.account_id || m.role == "owner" || m.role == "admin"
            })
            .collect()
    };
    Ok(Json(OrgDetail { org, members }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateOrgRequest {
    revision: i64,
    meta_epoch: u32,
    encrypted_meta: String,
}

/// Renames an organization (admins).
pub async fn update(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(org_id): Path<String>,
    Json(req): Json<UpdateOrgRequest>,
) -> ApiResult<StatusCode> {
    validate::id("organization id", &org_id)?;
    validate::base64(
        "encryptedMeta",
        &req.encrypted_meta,
        validate::MAX_SMALL_LEN,
    )?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    access::require_admin(&mut tx, &org_id, &session.account_id).await?;
    access::require_unlocked(&mut tx, &org_id).await?;
    let (revision, epoch): (i64, i64) = sqlx::query!(
        "SELECT revision, meta_epoch FROM organizations WHERE id = $1",
        &org_id,
    )
    .map(|row| (row.revision, row.meta_epoch))
    .fetch_one(&mut *tx)
    .await?;
    if req.revision != revision + 1 || i64::from(req.meta_epoch) != epoch {
        return Err(ApiError::conflict(
            "the organization was changed meanwhile",
            json!({ "currentRevision": revision, "currentMetaEpoch": epoch }),
        ));
    }
    let seq = db::next_seq(&mut tx).await?;
    sqlx::query!(
        "UPDATE organizations SET encrypted_meta = $1, revision = $2, seq = $3, updated_at = $4 WHERE id = $5",
        decode(&req.encrypted_meta)?,
        req.revision,
        seq,
        now_ms(),
        &org_id,
    )
        .execute(&mut *tx)
        .await?;
    super::org_audit::record_in(
        &mut tx,
        &org_id,
        &super::org_audit::Actor::of(&session, &ip),
        "org_renamed",
        super::org_audit::Target::org(&org_id),
        serde_json::json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Deletes an organization with its vaults (owner only).
pub async fn delete(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(org_id): Path<String>,
) -> ApiResult<StatusCode> {
    validate::id("organization id", &org_id)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    let m = access::require_member(&mut tx, &org_id, &session.account_id).await?;
    if m.role != OrgRole::Owner {
        return Err(ApiError::forbidden(
            "forbidden",
            "only the owner can delete the organization",
        ));
    }
    sqlx::query!("DELETE FROM vaults WHERE org_id = $1", &org_id,)
        .execute(&mut *tx)
        .await?;
    sqlx::query!("DELETE FROM organizations WHERE id = $1", &org_id,)
        .execute(&mut *tx)
        .await?;
    // Every member's sync must notice; bump the counter so cursors move.
    db::next_seq(&mut tx).await?;
    tx.commit().await?;
    crate::ext::emit(
        &state,
        crate::ext::OrgEvent::Deleted {
            org_id: org_id.clone(),
        },
    );
    event(&state, &session.account_id, "org_deleted", &session, &ip).await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Invitations ---------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteRequest {
    email: String,
    role: String,
    /// Fragment for the mailed link, `org=<organization root hash>`.
    #[serde(default)]
    link_fragment: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteResponse {
    id: String,
    token: String,
    /// `/invite/{token}`, relative to the server's public URL.
    path: String,
    expires_at: i64,
}

/// Invites someone by email (admins; only the owner invites admins).
/// Returns the token for the link; only its hash is stored.
pub async fn invite(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(org_id): Path<String>,
    Json(req): Json<InviteRequest>,
) -> ApiResult<(StatusCode, Json<InviteResponse>)> {
    validate::id("organization id", &org_id)?;
    let email = validate::email(&req.email)?;
    let role = OrgRole::parse(&req.role).map_err(|_| bad("invalid role"))?;
    if role == OrgRole::Owner {
        return Err(bad("an organization has exactly one owner"));
    }
    if let Some(fragment) = &req.link_fragment
        && (fragment.len() > 128
            || !fragment
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "=-_&".contains(c)))
    {
        return Err(bad("invalid linkFragment"));
    }
    limit(
        &state,
        format!("invite-ip:{ip}"),
        INVITATIONS_PER_HOUR,
        3600,
    )?;
    limit(
        &state,
        format!("invite:{}", session.account_id),
        INVITATIONS_PER_HOUR,
        3600,
    )?;

    let mut tx = state.db.as_account(&session.account_id).await?;
    let locale = crate::instance::load_settings(&mut tx)
        .await?
        .default_locale;
    let me = access::require_admin(&mut tx, &org_id, &session.account_id).await?;
    if role == OrgRole::Admin && me.role != OrgRole::Owner {
        return Err(ApiError::forbidden(
            "forbidden",
            "only the owner can invite admins",
        ));
    }
    let existing: Option<i64> = sqlx::query_scalar!(
        "SELECT 1::BIGINT AS \"one!\" FROM org_members JOIN account_directory accounts ON accounts.id = org_members.account_id \
         WHERE org_members.org_id = $1 AND accounts.email = $2",
        &org_id,
        &email,
    )
    .fetch_optional(&mut *tx)
    .await?;
    if existing.is_some() {
        return Err(ApiError::conflict(
            "this person is already a member",
            serde_json::Value::Null,
        ));
    }
    crate::ext::check_add_member(&state, &mut tx, &org_id, role, Joining::Invite).await?;
    let now = now_ms();
    let pending: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"count!\" FROM org_invitations WHERE org_id = $1 AND status = 'pending' AND expires_at > $2",
        &org_id,
        now,
    )
    .fetch_one(&mut *tx)
    .await?;
    if pending >= MAX_PENDING_INVITATIONS {
        return Err(bad("too many pending invitations"));
    }
    let (kind, inviter_email): (String, String) = sqlx::query!(
        "SELECT organizations.kind, accounts.email FROM organizations, accounts \
         WHERE organizations.id = $1 AND accounts.id = $2",
        &org_id,
        &session.account_id,
    )
    .map(|row| (row.kind, row.email))
    .fetch_one(&mut *tx)
    .await?;
    let invitation_id = id::new_id().map_err(|e| ApiError::Internal(e.into()))?;
    let token = encoding::encode(&random::bytes::<32>().map_err(|e| ApiError::Internal(e.into()))?);
    let expires_at = now + INVITATION_TTL_MS;
    sqlx::query!(
        "INSERT INTO org_invitations (id, org_id, email, role, token_hash, status, created_by, created_at, \
         expires_at, accepted_by, accepted_at) VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7, $8, NULL, NULL)",
        &invitation_id,
        &org_id,
        &email,
        role.as_str(),
        hash_token(&token),
        &session.account_id,
        now,
        expires_at,
    )
    .execute(&mut *tx)
    .await?;
    let path = format!("/invite/{token}");
    let mail_path = match &req.link_fragment {
        Some(fragment) => format!("{path}#{fragment}"),
        None => path.clone(),
    };
    // The organization's name is encrypted, so the mail names the inviter
    // only. Without a public URL the mail goes out without a link and the
    // inviter passes on the link the client shows.
    let link = state
        .mailer
        .public_url()
        .map(|base| format!("{base}{mail_path}"))
        .unwrap_or_default();
    Mailer::enqueue_in(
        &mut tx,
        &email,
        Template::Invitation,
        locale,
        &json!({
            "inviter": inviter_email,
            "organizationKind": kind,
            "link": link,
            "expiresAt": expires_at,
        }),
    )
    .await?;
    super::org_audit::record_in(
        &mut tx,
        &org_id,
        &super::org_audit::Actor::of(&session, &ip),
        "member_invited",
        super::org_audit::Target {
            kind: "invitation",
            id: &invitation_id,
        },
        json!({ "email": email, "role": role.as_str() }),
    )
    .await?;
    tx.commit().await?;
    state.mailer.wake();
    crate::ext::members_changed(&state, &org_id);
    event(
        &state,
        &session.account_id,
        "org_invitation_created",
        &session,
        &ip,
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(InviteResponse {
            id: invitation_id,
            token,
            path,
            expires_at,
        }),
    ))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitationInfo {
    id: String,
    email: String,
    role: String,
    status: String,
    created_by: String,
    created_at: i64,
    expires_at: i64,
}

/// Pending invitations of an organization (admins). Tokens are not stored
/// and cannot be shown again.
pub async fn invitations(
    State(state): State<AppState>,
    session: Session,
    Path(org_id): Path<String>,
) -> ApiResult<Json<Vec<InvitationInfo>>> {
    validate::id("organization id", &org_id)?;
    let mut conn = state.db.as_account(&session.account_id).await?;
    access::require_admin(&mut conn, &org_id, &session.account_id).await?;
    let rows: Vec<(String, String, String, String, String, i64, i64)> = sqlx::query!(
        "SELECT id, email, role, status, created_by, created_at, expires_at FROM org_invitations \
         WHERE org_id = $1 AND status = 'pending' AND expires_at > $2 ORDER BY created_at DESC",
        &org_id,
        now_ms(),
    )
    .map(|row| {
        (
            row.id,
            row.email,
            row.role,
            row.status,
            row.created_by,
            row.created_at,
            row.expires_at,
        )
    })
    .fetch_all(&mut *conn)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(
                |(id, email, role, status, created_by, created_at, expires_at)| InvitationInfo {
                    id,
                    email,
                    role,
                    status,
                    created_by,
                    created_at,
                    expires_at,
                },
            )
            .collect(),
    ))
}

/// Revokes a pending invitation (admins).
pub async fn revoke_invitation(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path((org_id, invitation_id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    validate::id("organization id", &org_id)?;
    validate::id("invitation id", &invitation_id)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    access::require_admin(&mut tx, &org_id, &session.account_id).await?;
    let updated = sqlx::query!(
        "UPDATE org_invitations SET status = 'revoked' WHERE id = $1 AND org_id = $2 AND status = 'pending'",
        &invitation_id,
        &org_id,
    )
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    super::org_audit::record_in(
        &mut tx,
        &org_id,
        &super::org_audit::Actor::of(&session, &ip),
        "invitation_revoked",
        super::org_audit::Target {
            kind: "invitation",
            id: &invitation_id,
        },
        serde_json::json!({}),
    )
    .await?;
    tx.commit().await?;
    crate::ext::members_changed(&state, &org_id);
    Ok(StatusCode::NO_CONTENT)
}

fn valid_token(token: &str) -> ApiResult<()> {
    if token.len() == 43 && encoding::decode(token).is_ok() {
        Ok(())
    } else {
        Err(ApiError::NotFound)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitationPreview {
    org_id: String,
    org_kind: String,
    email: String,
    role: String,
    expires_at: i64,
    /// Email of the admin who invited (also named in the invitation mail).
    inviter_email: String,
    /// The organization's admins can restore the invitee's access once they
    /// joined: organization recovery is set up and its policy requires
    /// enrollment.
    /// Never for guests. The app says so before the invitee accepts.
    recovery: bool,
}

/// What an invitation link is for, before signing in. Unknown, used,
/// revoked and expired tokens all answer 404. Rate limited per IP.
pub async fn preview(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(token): Path<String>,
) -> ApiResult<Json<InvitationPreview>> {
    limit(
        &state,
        format!("invitation-ip:{ip}"),
        INVITATION_REQUESTS_PER_MINUTE,
        60,
    )?;
    valid_token(&token)?;
    // Signed out: the function answers for this one token and nothing else.
    let mut tx = state.db.public(Public::Auth).await?;
    let row = sqlx::query!(
        r#"SELECT org_id AS "org_id!", org_kind AS "org_kind!", email AS "email!", role AS "role!",
                  expires_at AS "expires_at!", inviter_email AS "inviter_email!",
                  recovery AS "recovery!", rules
           FROM passbox.invitation_preview($1, $2)"#,
        hash_token(&token),
        now_ms(),
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    let (org_id, org_kind, email, role, expires_at, inviter_email) = (
        row.org_id,
        row.org_kind,
        row.email,
        row.role,
        row.expires_at,
        row.inviter_email,
    );
    let recovery = role != "guest"
        && row.recovery
        && row
            .rules
            .and_then(|rules| {
                serde_json::from_value::<passbox_core::policy::PolicyRules>(rules).ok()
            })
            .is_some_and(|r| r.require_recovery_enrollment);
    Ok(Json(InvitationPreview {
        org_id,
        org_kind,
        email,
        role,
        expires_at,
        inviter_email,
        recovery,
    }))
}

#[derive(Deserialize)]
pub struct AcceptRequest {
    token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceptResponse {
    org_id: String,
    role: String,
}

/// Accepts an invitation for the signed-in account, which must have the
/// invited email address and published keys. The membership is `accepted`
/// until an admin confirms the account's key.
pub async fn accept(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Json(req): Json<AcceptRequest>,
) -> ApiResult<Json<AcceptResponse>> {
    limit(
        &state,
        format!("invitation-ip:{ip}"),
        INVITATION_REQUESTS_PER_MINUTE,
        60,
    )?;
    limit(
        &state,
        format!("invitation-accept:{}", session.account_id),
        20,
        3600,
    )?;
    valid_token(&req.token)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    let now = now_ms();
    // The token is the capability: the function finds its invitation even
    // when it is addressed to another email (answered with 403 below).
    let row: Option<(String, String, String, String, String)> = sqlx::query!(
        r#"SELECT id AS "id!", org_id AS "org_id!", email AS "email!", role AS "role!",
                  created_by AS "created_by!"
           FROM passbox.invitation_by_token($1, $2)"#,
        hash_token(&req.token),
        now,
    )
    .map(|row| (row.id, row.org_id, row.email, row.role, row.created_by))
    .fetch_optional(&mut *tx)
    .await?;
    let (invitation_id, org_id, email, role, created_by) = row.ok_or(ApiError::NotFound)?;
    let account_email: String = sqlx::query_scalar!(
        "SELECT email FROM accounts WHERE id = $1",
        &session.account_id,
    )
    .fetch_one(&mut *tx)
    .await?;
    if account_email != email {
        return Err(ApiError::forbidden(
            "forbidden",
            "this invitation is for another email address",
        ));
    }
    signed::own_bundle(&mut tx, &session.account_id).await?;
    if access::membership(&mut tx, &org_id, &session.account_id)
        .await?
        .is_some()
    {
        return Err(ApiError::conflict(
            "you are already a member",
            serde_json::Value::Null,
        ));
    }
    let joining_role = OrgRole::parse(&role).map_err(|e| ApiError::Internal(e.into()))?;
    crate::ext::check_add_member(&state, &mut tx, &org_id, joining_role, Joining::Accept).await?;
    let seq = db::next_seq(&mut tx).await?;
    sqlx::query!(
        "INSERT INTO org_members (org_id, account_id, role, status, attestation, attestation_signature, \
         invited_by, seq, created_at, updated_at) VALUES ($1, $2, $3, 'accepted', NULL, NULL, $4, $5, $6, $7)",
        &org_id,
        &session.account_id,
        &role,
        &created_by,
        seq,
        now,
        now,
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!(
        "UPDATE org_invitations SET status = 'accepted', accepted_by = $1, accepted_at = $2 WHERE id = $3",
        &session.account_id,
        now,
        &invitation_id,
    )
    .execute(&mut *tx)
    .await?;
    super::org_audit::record_in(
        &mut tx,
        &org_id,
        &super::org_audit::Actor::of(&session, &ip),
        "member_joined",
        super::org_audit::Target::account(&session.account_id),
        json!({ "role": role, "invitationId": invitation_id }),
    )
    .await?;
    tx.commit().await?;
    crate::ext::members_changed(&state, &org_id);
    event(
        &state,
        &session.account_id,
        "org_invitation_accepted",
        &session,
        &ip,
    )
    .await?;
    Ok(Json(AcceptResponse { org_id, role }))
}

// --- Members ----------------------------------------------------------------------------

async fn target_member(
    conn: &mut PgConnection,
    org_id: &str,
    account_id: &str,
) -> ApiResult<Membership> {
    access::membership(conn, org_id, account_id)
        .await?
        .ok_or(ApiError::NotFound)
}

fn check_attestation(
    signed_attestation: &Signed<MemberAttestation>,
    org_id: &str,
    member: &SignedBundle,
    role: OrgRole,
    me: &SignedBundle,
) -> ApiResult<()> {
    let a = &signed_attestation.value;
    if a.org_id != org_id
        || a.account_id != member.bundle.account_id
        || a.key_version != member.bundle.key_version
        || a.bundle_hash != member.hash()
        || a.role != role
        || a.attester_id != me.bundle.account_id
    {
        return Err(bad("the attestation does not match the member"));
    }
    Ok(())
}

async fn current_epoch(conn: &mut PgConnection, org_id: &str) -> ApiResult<u32> {
    let epoch: i64 =
        sqlx::query_scalar!("SELECT meta_epoch FROM organizations WHERE id = $1", org_id,)
            .fetch_one(&mut *conn)
            .await?;
    u32::try_from(epoch).map_err(|_| ApiError::Internal(anyhow::anyhow!("invalid epoch")))
}

/// Confirms an accepted member: stores the admin's attestation of the
/// member's key and the organization key sealed for them.
pub async fn confirm(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path((org_id, account_id)): Path<(String, String)>,
    Json(req): Json<ConfirmMember>,
) -> ApiResult<StatusCode> {
    validate::id("organization id", &org_id)?;
    validate::id("account id", &account_id)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    let me_membership = access::require_admin(&mut tx, &org_id, &session.account_id).await?;
    access::require_unlocked(&mut tx, &org_id).await?;
    let target = target_member(&mut tx, &org_id, &account_id).await?;
    if target.status != "accepted" {
        return Err(ApiError::conflict(
            "the member is not waiting for confirmation",
            serde_json::Value::Null,
        ));
    }
    if req.role != target.role.as_str() {
        return Err(bad("the role does not match the invitation"));
    }
    if target.role == OrgRole::Admin && me_membership.role != OrgRole::Owner {
        return Err(ApiError::forbidden(
            "forbidden",
            "only the owner can confirm admins",
        ));
    }
    let me = signed::own_bundle(&mut tx, &session.account_id).await?;
    let member = signed::own_bundle(&mut tx, &account_id).await?;
    let attestation = signed::parse::<MemberAttestation>(
        "attestation",
        &req.attestation,
        &req.attestation_signature,
        &me,
    )?;
    check_attestation(&attestation, &org_id, &member, target.role, &me)?;
    let epoch = current_epoch(&mut tx, &org_id).await?;
    check_org_key(&req.org_key, &org_id, epoch, &member, &me)?;
    let now = now_ms();
    let seq = db::next_seq(&mut tx).await?;
    sqlx::query!(
        "UPDATE org_members SET status = 'confirmed', attestation = $1, attestation_signature = $2, \
         seq = $3, updated_at = $4 WHERE org_id = $5 AND account_id = $6",
        &req.attestation,
        &req.attestation_signature,
        seq,
        now,
        &org_id,
        &account_id,
    )
    .execute(&mut *tx)
    .await?;
    insert_org_key(&mut tx, &org_id, &req.org_key, seq, now).await?;
    super::org_audit::record_in(
        &mut tx,
        &org_id,
        &super::org_audit::Actor::of(&session, &ip),
        "member_confirmed",
        super::org_audit::Target::account(&account_id),
        json!({ "role": target.role.as_str() }),
    )
    .await?;
    tx.commit().await?;
    crate::ext::members_changed(&state, &org_id);
    event(
        &state,
        &account_id,
        "org_membership_confirmed",
        &session,
        &ip,
    )
    .await?;
    event(
        &state,
        &session.account_id,
        "org_member_confirmed",
        &session,
        &ip,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Changes a confirmed member's role (or re-attests it unchanged).
pub async fn update_member(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path((org_id, account_id)): Path<(String, String)>,
    Json(req): Json<MemberAttestationUpload>,
) -> ApiResult<StatusCode> {
    validate::id("organization id", &org_id)?;
    validate::id("account id", &account_id)?;
    let role = OrgRole::parse(&req.role).map_err(|_| bad("invalid role"))?;
    if req.account_id != account_id {
        return Err(bad("accountId does not match the path"));
    }
    let mut tx = state.db.as_account(&session.account_id).await?;
    let me_membership = access::require_admin(&mut tx, &org_id, &session.account_id).await?;
    let target = target_member(&mut tx, &org_id, &account_id).await?;
    if target.role == OrgRole::Owner || role == OrgRole::Owner {
        return Err(ApiError::forbidden(
            "forbidden",
            "the owner's role cannot be changed",
        ));
    }
    if target.status == "accepted" {
        return Err(bad("confirm the member first"));
    }
    if (role == OrgRole::Admin || target.role == OrgRole::Admin)
        && me_membership.role != OrgRole::Owner
    {
        return Err(ApiError::forbidden(
            "forbidden",
            "only the owner can grant or revoke admin rights",
        ));
    }
    if target.role == OrgRole::Guest && role != OrgRole::Guest {
        crate::ext::check_add_member(&state, &mut tx, &org_id, role, Joining::Promote).await?;
    } else {
        access::require_unlocked(&mut tx, &org_id).await?;
    }
    let me = signed::own_bundle(&mut tx, &session.account_id).await?;
    let member = signed::own_bundle(&mut tx, &account_id).await?;
    let attestation = signed::parse::<MemberAttestation>(
        "attestation",
        &req.attestation,
        &req.attestation_signature,
        &me,
    )?;
    check_attestation(&attestation, &org_id, &member, role, &me)?;
    let seq = db::next_seq(&mut tx).await?;
    sqlx::query!(
        "UPDATE org_members SET role = $1, attestation = $2, attestation_signature = $3, seq = $4, \
         updated_at = $5 WHERE org_id = $6 AND account_id = $7",
        role.as_str(),
        &req.attestation,
        &req.attestation_signature,
        seq,
        now_ms(),
        &org_id,
        &account_id,
    )
    .execute(&mut *tx)
    .await?;
    if !role.is_admin() {
        // Only admins hold the recovery key; this deletes the server's copy
        // (rotating the recovery key removes the former admin's access).
        sqlx::query!(
            "DELETE FROM org_recovery_grants WHERE org_id = $1 AND account_id = $2",
            &org_id,
            &account_id,
        )
        .execute(&mut *tx)
        .await?;
    }
    super::org_audit::record_in(
        &mut tx,
        &org_id,
        &super::org_audit::Actor::of(&session, &ip),
        if role == target.role {
            "member_reattested"
        } else {
            "member_role_changed"
        },
        super::org_audit::Target::account(&account_id),
        json!({ "from": target.role.as_str(), "to": role.as_str() }),
    )
    .await?;
    tx.commit().await?;
    crate::ext::members_changed(&state, &org_id);
    if role != target.role {
        event(&state, &account_id, "org_role_changed", &session, &ip).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn set_status(
    state: &AppState,
    session: &Session,
    ip: &str,
    org_id: &str,
    account_id: &str,
    status: &str,
) -> ApiResult<()> {
    validate::id("organization id", org_id)?;
    validate::id("account id", account_id)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    let me = access::require_admin(&mut tx, org_id, &session.account_id).await?;
    let target = target_member(&mut tx, org_id, account_id).await?;
    if target.role == OrgRole::Owner {
        return Err(ApiError::forbidden(
            "forbidden",
            "the owner cannot be suspended",
        ));
    }
    if target.role == OrgRole::Admin && me.role != OrgRole::Owner {
        return Err(ApiError::forbidden(
            "forbidden",
            "only the owner can suspend admins",
        ));
    }
    let from = if status == "suspended" {
        "confirmed"
    } else {
        "suspended"
    };
    if target.status != from {
        return Err(ApiError::conflict(
            format!("the member is not {from}"),
            serde_json::Value::Null,
        ));
    }
    if status != "suspended" {
        crate::ext::check_add_member(state, &mut tx, org_id, target.role, Joining::Reactivate)
            .await?;
    }
    let seq = db::next_seq(&mut tx).await?;
    sqlx::query!(
        "UPDATE org_members SET status = $1, seq = $2, updated_at = $3 WHERE org_id = $4 AND account_id = $5",
        status,
        seq,
        now_ms(),
        org_id,
        account_id,
    )
        .execute(&mut *tx)
        .await?;
    super::org_audit::record_in(
        &mut tx,
        org_id,
        &super::org_audit::Actor::of(session, ip),
        if status == "suspended" {
            "member_suspended"
        } else {
            "member_reactivated"
        },
        super::org_audit::Target::account(account_id),
        serde_json::json!({}),
    )
    .await?;
    tx.commit().await?;
    crate::ext::members_changed(state, org_id);
    Ok(())
}

/// Suspends a member: the server stops serving the organization's vaults
/// to them. Not cryptographic; remove the member to rotate keys.
pub async fn suspend(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path((org_id, account_id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    set_status(&state, &session, &ip, &org_id, &account_id, "suspended").await?;
    event(
        &state,
        &account_id,
        "org_membership_suspended",
        &session,
        &ip,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn reactivate(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path((org_id, account_id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    set_status(&state, &session, &ip, &org_id, &account_id, "confirmed").await?;
    event(
        &state,
        &account_id,
        "org_membership_reactivated",
        &session,
        &ip,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemovedMember {
    /// Vaults the member could open; their keys must be rotated.
    vaults: Vec<String>,
    /// Groups the member belonged to; their keys must be rotated.
    groups: Vec<String>,
}

/// Removes a member (admins; members may leave themselves; the owner
/// cannot be removed). Access ends immediately; the affected vaults are
/// marked for key rotation, which a manager's client performs.
pub async fn remove_member(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path((org_id, account_id)): Path<(String, String)>,
) -> ApiResult<Json<RemovedMember>> {
    validate::id("organization id", &org_id)?;
    validate::id("account id", &account_id)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    let me = access::require_member(&mut tx, &org_id, &session.account_id).await?;
    let target = target_member(&mut tx, &org_id, &account_id).await?;
    let leaving = account_id == session.account_id;
    if target.role == OrgRole::Owner {
        return Err(ApiError::forbidden(
            "forbidden",
            "the owner cannot be removed",
        ));
    }
    if !leaving {
        if !me.is_admin() {
            return Err(ApiError::forbidden(
                "forbidden",
                "only owners and admins can remove members",
            ));
        }
        if target.role == OrgRole::Admin && me.role != OrgRole::Owner {
            return Err(ApiError::forbidden(
                "forbidden",
                "only the owner can remove admins",
            ));
        }
    }
    let groups: Vec<String> = sqlx::query_scalar!(
        "SELECT DISTINCT group_members.group_id FROM group_members \
         JOIN org_groups ON org_groups.id = group_members.group_id \
         WHERE org_groups.org_id = $1 AND group_members.account_id = $2 \
         AND group_members.key_version = org_groups.key_version",
        &org_id,
        &account_id,
    )
    .fetch_all(&mut *tx)
    .await?;
    let seq = db::next_seq(&mut tx).await?;
    let vaults =
        super::shared::mark_rotation_pending(&mut tx, &org_id, &account_id, &groups, seq).await?;
    // Recorded while the member still belongs to the organization: the
    // audit chain is written under their membership.
    super::org_audit::record_in(
        &mut tx,
        &org_id,
        &super::org_audit::Actor::of(&session, &ip),
        if leaving {
            "member_left"
        } else {
            "member_removed"
        },
        super::org_audit::Target::account(&account_id),
        json!({ "role": target.role.as_str(), "vaults": vaults, "groups": groups }),
    )
    .await?;
    for statement in [
        "DELETE FROM vault_members WHERE principal_type = 'account' AND principal_id = $1 \
         AND vault_id IN (SELECT id FROM vaults WHERE org_id = $2)",
        "DELETE FROM vault_keys WHERE principal_type = 'account' AND principal_id = $1 \
         AND vault_id IN (SELECT id FROM vaults WHERE org_id = $2)",
        "DELETE FROM group_members WHERE account_id = $1 \
         AND group_id IN (SELECT id FROM org_groups WHERE org_id = $2)",
        "DELETE FROM org_keys WHERE account_id = $1 AND org_id = $2",
        "DELETE FROM org_recovery_escrows WHERE account_id = $1 AND org_id = $2",
        "DELETE FROM org_recovery_grants WHERE account_id = $1 AND org_id = $2",
        "DELETE FROM org_recovery_requests WHERE account_id = $1 AND org_id = $2",
        "DELETE FROM org_members WHERE account_id = $1 AND org_id = $2",
    ] {
        sqlx::query(statement)
            .bind(&account_id)
            .bind(&org_id)
            .execute(&mut *tx)
            .await?;
    }
    // Other members' rosters must update: bump the organization's sequence.
    sqlx::query!(
        "UPDATE organizations SET seq = $1 WHERE id = $2",
        seq,
        &org_id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    crate::ext::members_changed(&state, &org_id);
    event(&state, &account_id, "org_membership_removed", &session, &ip).await?;
    if !leaving {
        event(
            &state,
            &session.account_id,
            "org_member_removed",
            &session,
            &ip,
        )
        .await?;
    }
    Ok(Json(RemovedMember { vaults, groups }))
}

/// Rotates the organization key (admins): new epoch, metadata of the
/// organization and its groups re-encrypted, the key sealed for every
/// confirmed member.
pub async fn rotate_key(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(org_id): Path<String>,
    Json(req): Json<RotateOrgKey>,
) -> ApiResult<StatusCode> {
    validate::id("organization id", &org_id)?;
    validate::base64(
        "encryptedMeta",
        &req.encrypted_meta,
        validate::MAX_SMALL_LEN,
    )?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    access::require_admin(&mut tx, &org_id, &session.account_id).await?;
    let epoch = current_epoch(&mut tx, &org_id).await?;
    if req.epoch != epoch + 1 {
        return Err(ApiError::conflict(
            "the organization key was rotated meanwhile",
            json!({ "currentMetaEpoch": epoch }),
        ));
    }
    let me = signed::own_bundle(&mut tx, &session.account_id).await?;
    let confirmed: Vec<String> = sqlx::query_scalar!(
        "SELECT account_id FROM org_members WHERE org_id = $1 AND status = 'confirmed' ORDER BY account_id",
        &org_id,
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut covered: Vec<String> = req.keys.iter().map(|k| k.account_id.clone()).collect();
    covered.sort();
    covered.dedup();
    if covered.len() != req.keys.len() || !confirmed.iter().all(|a| covered.contains(a)) {
        return Err(bad("the new key must be sealed for every confirmed member"));
    }
    for key in &req.keys {
        let member = signed::own_bundle(&mut tx, &key.account_id).await?;
        check_org_key(key, &org_id, req.epoch, &member, &me)?;
    }
    let groups: Vec<String> = sqlx::query_scalar!(
        "SELECT id FROM org_groups WHERE org_id = $1 ORDER BY id",
        &org_id,
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut uploaded: Vec<String> = req.groups.iter().map(|g| g.group_id.clone()).collect();
    uploaded.sort();
    if uploaded != groups {
        return Err(bad("every group's metadata must be re-encrypted"));
    }
    let now = now_ms();
    let seq = db::next_seq(&mut tx).await?;
    for key in &req.keys {
        if confirmed.contains(&key.account_id) {
            insert_org_key(&mut tx, &org_id, key, seq, now).await?;
        }
    }
    for group in &req.groups {
        validate::base64(
            "encryptedMeta",
            &group.encrypted_meta,
            validate::MAX_SMALL_LEN,
        )?;
        sqlx::query!(
            "UPDATE org_groups SET encrypted_meta = $1, meta_epoch = $2, seq = $3, updated_at = $4 WHERE id = $5",
            decode(&group.encrypted_meta)?,
            i64::from(req.epoch),
            seq,
            now,
            &group.group_id,
        )
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query!(
        "UPDATE organizations SET encrypted_meta = $1, meta_epoch = $2, revision = revision + 1, seq = $3, \
         updated_at = $4 WHERE id = $5",
        decode(&req.encrypted_meta)?,
        i64::from(req.epoch),
        seq,
        now,
        &org_id,
    )
    .execute(&mut *tx)
    .await?;
    super::org_audit::record_in(
        &mut tx,
        &org_id,
        &super::org_audit::Actor::of(&session, &ip),
        "org_key_rotated",
        super::org_audit::Target::org(&org_id),
        json!({ "epoch": req.epoch }),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
