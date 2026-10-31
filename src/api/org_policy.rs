//! Organization policies.
//!
//! An owner or admin signs each policy version with their account key
//! (`passbox_core::policy`); members' clients verify and enforce it. The
//! server stores the versions, delivers the newest one in sync and
//! enforces what it can see itself: members of an organization that
//! requires two-factor sign-in cannot turn it off, and members of an
//! organization that does not allow personal vaults cannot create personal
//! vaults or new items in them.

use axum::Json;
use axum::extract::{Path, State};
use passbox_core::policy::{OrgPolicy, PolicyRecord, PolicyRules, PolicyUpload, parse_policy};
use passbox_core::sharing::objects::Signed;
use serde::Serialize;
use serde_json::json;
use sqlx::PgConnection;

use super::access;
use super::auth::Session;
use super::org_audit::{self, Actor, Target};
use super::signed::{self, bad};
use super::validate;
use crate::db::{self, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::security::ClientIp;
use crate::state::AppState;

/// The rules of an organization's newest policy, if it has one.
pub async fn current_rules(
    conn: &mut PgConnection,
    org_id: &str,
) -> ApiResult<Option<PolicyRules>> {
    let rules: Option<serde_json::Value> = sqlx::query_scalar!(
        "SELECT rules FROM org_policies WHERE org_id = $1 ORDER BY version DESC LIMIT 1",
        org_id,
    )
    .fetch_optional(&mut *conn)
    .await?;
    rules
        .map(|r| serde_json::from_value(r).map_err(|e| ApiError::Internal(e.into())))
        .transpose()
}

/// The newest policy rules of every organization the account is a
/// confirmed or suspended member of.
pub async fn rules_for_account(
    conn: &mut PgConnection,
    account_id: &str,
) -> ApiResult<Vec<(String, PolicyRules)>> {
    let rows: Vec<(String, serde_json::Value)> = sqlx::query!(
        "SELECT p.org_id, p.rules FROM org_policies p \
         JOIN org_members m ON m.org_id = p.org_id \
         WHERE m.account_id = $1 AND m.status IN ('confirmed', 'suspended') \
         AND p.version = (SELECT MAX(version) FROM org_policies WHERE org_id = p.org_id)",
        account_id,
    )
    .map(|row| (row.org_id, row.rules))
    .fetch_all(&mut *conn)
    .await?;
    rows.into_iter()
        .map(|(org, rules)| {
            serde_json::from_value(rules)
                .map(|r| (org, r))
                .map_err(|e| ApiError::Internal(e.into()))
        })
        .collect()
}

/// 403 `policy_violation` if an organization of the account requires
/// two-factor sign-in (called before turning it off).
pub async fn ensure_two_factor_optional(
    conn: &mut PgConnection,
    account_id: &str,
) -> ApiResult<()> {
    if rules_for_account(conn, account_id)
        .await?
        .iter()
        .any(|(_, r)| r.require_two_factor)
    {
        return Err(ApiError::forbidden(
            "policy_violation",
            "your organization requires two-factor sign-in, so it cannot be turned off",
        ));
    }
    Ok(())
}

/// 403 `policy_violation` if an organization of the account does not allow
/// personal vaults (called before creating a personal vault or a new item
/// in one).
pub async fn ensure_personal_vaults_allowed(
    conn: &mut PgConnection,
    account_id: &str,
) -> ApiResult<()> {
    if rules_for_account(conn, account_id)
        .await?
        .iter()
        .any(|(_, r)| !r.allow_personal_vault)
    {
        return Err(ApiError::forbidden(
            "policy_violation",
            "your organization does not allow personal vaults; save the item in a shared vault",
        ));
    }
    Ok(())
}

/// The newest policy of each organization in `org_ids` (for sync).
pub async fn records(conn: &mut PgConnection, org_ids: &[String]) -> ApiResult<Vec<PolicyRecord>> {
    let mut out = Vec::new();
    for org_id in org_ids {
        let row: Option<(i64, String, String)> = sqlx::query!(
            "SELECT version, policy, signature FROM org_policies WHERE org_id = $1 \
             ORDER BY version DESC LIMIT 1",
            org_id,
        )
        .map(|row| (row.version, row.policy, row.signature))
        .fetch_optional(&mut *conn)
        .await?;
        if let Some((version, policy, signature)) = row {
            out.push(PolicyRecord {
                org_id: org_id.clone(),
                version: u64::try_from(version).unwrap_or_default(),
                policy,
                signature,
            });
        }
    }
    Ok(out)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyResponse {
    /// The newest version, if any.
    current: Option<PolicyRecord>,
    /// Every version, oldest first (admins only).
    history: Vec<PolicyRecord>,
}

/// `GET /orgs/{id}/policy`: the newest policy (members) and its history
/// (admins).
pub async fn get(
    State(state): State<AppState>,
    session: Session,
    Path(org_id): Path<String>,
) -> ApiResult<Json<PolicyResponse>> {
    validate::id("organization id", &org_id)?;
    let mut conn = state.db.as_account(&session.account_id).await?;
    let membership = access::require_member(&mut conn, &org_id, &session.account_id).await?;
    let rows: Vec<(i64, String, String)> = sqlx::query!(
        "SELECT version, policy, signature FROM org_policies WHERE org_id = $1 ORDER BY version",
        &org_id,
    )
    .map(|row| (row.version, row.policy, row.signature))
    .fetch_all(&mut *conn)
    .await?;
    let mut history: Vec<PolicyRecord> = rows
        .into_iter()
        .map(|(version, policy, signature)| PolicyRecord {
            org_id: org_id.clone(),
            version: u64::try_from(version).unwrap_or_default(),
            policy,
            signature,
        })
        .collect();
    let current = history.last().cloned();
    if !membership.is_admin() {
        history.clear();
    }
    Ok(Json(PolicyResponse { current, history }))
}

/// `PUT /orgs/{id}/policy`: stores the next policy version, signed by the
/// uploading owner or admin and linked to the current version.
pub async fn put(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(org_id): Path<String>,
    Json(req): Json<PolicyUpload>,
) -> ApiResult<Json<PolicyRecord>> {
    validate::id("organization id", &org_id)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    access::require_admin(&mut tx, &org_id, &session.account_id).await?;
    let me = signed::own_bundle(&mut tx, &session.account_id).await?;
    let signed = signed::parse::<OrgPolicy>("policy", &req.policy, &req.signature, &me)?;
    let (_, rules, _unknown) = parse_policy(&org_id, &req.policy, &req.signature)
        .map_err(|e| ApiError::bad_request(format!("invalid policy: {e}")))?;
    let p = &signed.value;
    if p.signer_id != session.account_id || p.version != req.version {
        return Err(bad("the policy does not match the request"));
    }
    let current: Option<(i64, String, String)> = sqlx::query!(
        "SELECT version, policy, signature FROM org_policies WHERE org_id = $1 \
         ORDER BY version DESC LIMIT 1",
        &org_id,
    )
    .map(|row| (row.version, row.policy, row.signature))
    .fetch_optional(&mut *tx)
    .await?;
    let (current_version, current_hash) = match &current {
        Some((version, policy, signature)) => {
            let previous = Signed::<OrgPolicy>::parse(policy, signature)
                .map_err(|e| ApiError::Internal(anyhow::anyhow!("stored policy: {e}")))?;
            (*version, previous.hash())
        }
        None => (0, [0u8; 32]),
    };
    let version = i64::try_from(p.version).map_err(|_| bad("invalid version"))?;
    if version != current_version + 1 || p.prev_hash != current_hash {
        return Err(ApiError::conflict(
            "the policy was changed meanwhile; sync and try again",
            json!({ "currentVersion": current_version }),
        ));
    }
    let seq = db::next_seq(&mut tx).await?;
    let rules_json = serde_json::to_value(&rules).map_err(|e| ApiError::Internal(e.into()))?;
    sqlx::query!(
        "INSERT INTO org_policies (org_id, version, policy, signature, signer_id, rules, seq, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        &org_id,
        version,
        &req.policy,
        &req.signature,
        &session.account_id,
        &rules_json,
        seq,
        now_ms(),
    )
    .execute(&mut *tx)
    .await?;
    // Members' sync picks the new policy up with the organization.
    sqlx::query!(
        "UPDATE organizations SET seq = $1 WHERE id = $2",
        seq,
        &org_id,
    )
    .execute(&mut *tx)
    .await?;
    org_audit::record_in(
        &mut tx,
        &org_id,
        &Actor::of(&session, &ip),
        "policy_updated",
        Target::org(&org_id),
        json!({ "version": version, "rules": rules }),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(PolicyRecord {
        org_id,
        version: p.version,
        policy: req.policy,
        signature: req.signature,
    }))
}
