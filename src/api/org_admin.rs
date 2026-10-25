//! Organization administration that is not cryptographic (waves D1, D4,
//! D6): reports for admins, security aggregates members' apps report,
//! server-side settings and ending a member's sessions during offboarding.
//!
//! The server only knows metadata: who belongs to which vault with which
//! role, when items changed, whether accounts have two-factor sign-in.
//! Vault names and items stay encrypted; the security score comes from the
//! members' apps as plain numbers, never items or passwords.

use std::collections::{BTreeMap, BTreeSet};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use passbox_core::sharing::objects::OrgRole;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::access;
use super::auth::{Session, record_event};
use super::org_audit::{self, Actor, Target};
use super::validate;
use crate::db::now_ms;
use crate::error::{ApiError, ApiResult};
use crate::security::ClientIp;
use crate::state::AppState;

/// Vaults without writes or reported use for this long count as unused.
pub const UNUSED_AFTER_DAYS: i64 = 90;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityAggregate {
    pub score: i64,
    pub total: i64,
    pub weak: i64,
    pub reused: i64,
    pub unsecured: i64,
    /// 1 met, 0 did not meet, -1 unknown.
    pub password_policy: i64,
    pub reported_at: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberReport {
    pub account_id: String,
    pub email: String,
    pub role: String,
    pub status: String,
    pub joined_at: i64,
    pub two_factor: bool,
    pub two_factor_methods: Vec<String>,
    pub recovery_enrolled: bool,
    /// Last sign-in (0 = never recorded).
    pub last_sign_in_at: i64,
    pub groups: Vec<String>,
    /// Vaults this member can open (directly or through groups).
    pub vault_count: usize,
    pub security: Option<SecurityAggregate>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultPrincipal {
    pub principal_type: String,
    pub principal_id: String,
    pub role: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultReport {
    pub vault_id: String,
    pub created_at: i64,
    pub key_epoch: i64,
    pub rotation_pending: bool,
    pub item_count: i64,
    /// Last write to an item or the vault (0 = none).
    pub last_write_at: i64,
    /// Last reported use (viewed, copied, filled; 0 = none reported).
    pub last_used_at: i64,
    pub unused: bool,
    pub members: Vec<VaultPrincipal>,
    /// Accounts with `manage` (directly).
    pub managers: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessEntry {
    pub account_id: String,
    pub vault_id: String,
    /// The strongest role over all paths.
    pub role: String,
    /// `direct`, or the IDs of the groups that grant access.
    pub via: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgReport {
    pub generated_at: i64,
    pub unused_after_days: i64,
    pub members: Vec<MemberReport>,
    pub vaults: Vec<VaultReport>,
    pub access: Vec<AccessEntry>,
    pub pending_invitations: i64,
    pub pending_recovery_requests: i64,
    pub recovery_set_up: bool,
    pub policy_version: i64,
    /// Confirmed members who are not guests: the billable members of the
    /// hosted service. Guests, AI agents and service accounts never count.
    pub member_count: i64,
    /// Confirmed guests (free, view-only).
    pub guest_count: i64,
    /// Active service accounts (and with them AI agents) of the members,
    /// with the fair-use limit that applies (`limit_per_member` 0 =
    /// unlimited).
    pub service_account_count: i64,
    pub agent_limit_per_member: u32,
}

fn role_rank(role: &str) -> u8 {
    match role {
        "manage" => 3,
        "edit" => 2,
        _ => 1,
    }
}

/// `GET /orgs/{id}/reports`: members, vaults and access (admins).
pub async fn reports(
    State(state): State<AppState>,
    session: Session,
    Path(org_id): Path<String>,
) -> ApiResult<Json<OrgReport>> {
    validate::id("organization id", &org_id)?;
    let mut conn = state.db.as_account(&session.account_id).await?;
    access::require_admin(&mut conn, &org_id, &session.account_id).await?;
    let now = now_ms();

    let members: Vec<(String, String, String, String, i64)> = sqlx::query!(
        r#"SELECT m.account_id, a.email AS "email!", m.role, m.status, m.created_at FROM org_members m
         JOIN account_directory a ON a.id = m.account_id WHERE m.org_id = $1 ORDER BY a.email"#,
        &org_id,
    ).map(|row| (row.account_id, row.email, row.role, row.status, row.created_at))
    .fetch_all(&mut *conn)
    .await?;
    let totp: BTreeSet<String> = sqlx::query_scalar!(
        "SELECT t.account_id FROM two_factor_totp t JOIN org_members m ON m.account_id = t.account_id \
         WHERE m.org_id = $1 AND t.confirmed = true",
        &org_id,
    )
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .collect();
    let webauthn: BTreeSet<String> = sqlx::query_scalar!(
        "SELECT DISTINCT w.account_id FROM webauthn_credentials w \
         JOIN org_members m ON m.account_id = w.account_id WHERE m.org_id = $1",
        &org_id,
    )
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .collect();
    let enrolled: BTreeSet<String> = sqlx::query_scalar!(
        "SELECT account_id FROM org_recovery_escrows WHERE org_id = $1 \
         AND key_version = (SELECT MAX(key_version) FROM org_recovery_keys WHERE org_id = $2)",
        &org_id,
        &org_id,
    )
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .collect();
    let sign_ins: BTreeMap<String, i64> = sqlx::query_as::<_, (String, i64)>(
        "SELECT e.account_id, MAX(e.created_at) FROM account_events e \
         JOIN org_members m ON m.account_id = e.account_id \
         WHERE m.org_id = $1 AND e.kind IN ('login', 'login_two_factor', 'login_recovered') \
         GROUP BY e.account_id",
    )
    .bind(&org_id)
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .collect();
    let security: BTreeMap<String, SecurityAggregate> = sqlx::query_as::<
        _,
        (String, i64, i64, i64, i64, i64, i64, i64),
    >(
        "SELECT account_id, score, total, weak, reused, unsecured, password_policy, reported_at \
             FROM org_security_reports WHERE org_id = $1",
    )
    .bind(&org_id)
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(
        |(account_id, score, total, weak, reused, unsecured, password_policy, reported_at)| {
            (
                account_id,
                SecurityAggregate {
                    score,
                    total,
                    weak,
                    reused,
                    unsecured,
                    password_policy,
                    reported_at,
                },
            )
        },
    )
    .collect();
    // Current group memberships.
    let group_members: Vec<(String, String)> = sqlx::query!(
        "SELECT gm.group_id, gm.account_id FROM group_members gm \
         JOIN org_groups g ON g.id = gm.group_id AND gm.key_version = g.key_version \
         WHERE g.org_id = $1",
        &org_id,
    )
    .map(|row| (row.group_id, row.account_id))
    .fetch_all(&mut *conn)
    .await?;
    let mut groups_of: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut members_of: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (group, account) in &group_members {
        groups_of
            .entry(account.clone())
            .or_default()
            .push(group.clone());
        members_of
            .entry(group.clone())
            .or_default()
            .push(account.clone());
    }

    let vault_rows: Vec<(String, i64, i64, i64, bool)> = sqlx::query!(
        "SELECT id, created_at, updated_at, key_epoch, rotation_pending FROM vaults \
         WHERE org_id = $1 ORDER BY created_at",
        &org_id,
    )
    .map(|row| {
        (
            row.id,
            row.created_at,
            row.updated_at,
            row.key_epoch,
            row.rotation_pending,
        )
    })
    .fetch_all(&mut *conn)
    .await?;
    let item_stats: BTreeMap<String, (i64, i64)> = sqlx::query_as::<_, (String, i64, i64)>(
        "SELECT i.vault_id, SUM(CASE WHEN i.deleted = false THEN 1 ELSE 0 END), MAX(i.updated_at) \
         FROM items i JOIN vaults v ON v.id = i.vault_id WHERE v.org_id = $1 GROUP BY i.vault_id",
    )
    .bind(&org_id)
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(|(vault, count, last)| (vault, (count, last)))
    .collect();
    let used: Vec<(String, i64)> = sqlx::query!(
        "SELECT details, created_at FROM org_audit_events WHERE org_id = $1 AND client_event <> '' \
         AND created_at > $2",
        &org_id,
        now - UNUSED_AFTER_DAYS * 24 * 60 * 60 * 1000,
    )
    .map(|row| (row.details, row.created_at))
    .fetch_all(&mut *conn)
    .await?;
    let mut last_used: BTreeMap<String, i64> = BTreeMap::new();
    for (details, at) in used {
        if let Some(vault) = serde_json::from_str::<serde_json::Value>(&details)
            .ok()
            .and_then(|d| d["vaultId"].as_str().map(str::to_owned))
        {
            let entry = last_used.entry(vault).or_default();
            *entry = (*entry).max(at);
        }
    }
    let vault_members: Vec<(String, String, String, String)> = sqlx::query!(
        "SELECT vm.vault_id, vm.principal_type, vm.principal_id, vm.role FROM vault_members vm \
         JOIN vaults v ON v.id = vm.vault_id WHERE v.org_id = $1",
        &org_id,
    )
    .map(|row| (row.vault_id, row.principal_type, row.principal_id, row.role))
    .fetch_all(&mut *conn)
    .await?;

    // Effective access per (account, vault).
    let mut access_map: BTreeMap<(String, String), (String, Vec<String>)> = BTreeMap::new();
    let mut grant = |account: &str, vault: &str, role: &str, via: &str| {
        let entry = access_map
            .entry((account.to_owned(), vault.to_owned()))
            .or_insert_with(|| (role.to_owned(), Vec::new()));
        if role_rank(role) > role_rank(&entry.0) {
            entry.0 = role.to_owned();
        }
        if !entry.1.iter().any(|v| v == via) {
            entry.1.push(via.to_owned());
        }
    };
    for (vault, kind, principal, role) in &vault_members {
        if kind == "account" {
            grant(principal, vault, role, "direct");
        } else if let Some(accounts) = members_of.get(principal) {
            for account in accounts {
                grant(account, vault, role, principal);
            }
        }
    }
    let unused_cutoff = now - UNUSED_AFTER_DAYS * 24 * 60 * 60 * 1000;
    let vaults = vault_rows
        .into_iter()
        .map(
            |(vault_id, created_at, updated_at, key_epoch, rotation_pending)| {
                let (item_count, last_item) = item_stats.get(&vault_id).copied().unwrap_or((0, 0));
                let last_write_at = last_item.max(updated_at);
                let last_used_at = last_used.get(&vault_id).copied().unwrap_or(0);
                let entries: Vec<VaultPrincipal> = vault_members
                    .iter()
                    .filter(|(v, ..)| *v == vault_id)
                    .map(|(_, t, id, role)| VaultPrincipal {
                        principal_type: t.clone(),
                        principal_id: id.clone(),
                        role: role.clone(),
                    })
                    .collect();
                let managers = entries
                    .iter()
                    .filter(|e| e.principal_type == "account" && e.role == "manage")
                    .map(|e| e.principal_id.clone())
                    .collect();
                VaultReport {
                    unused: last_write_at.max(last_used_at) < unused_cutoff
                        && created_at < unused_cutoff,
                    vault_id,
                    created_at,
                    key_epoch,
                    rotation_pending,
                    item_count,
                    last_write_at,
                    last_used_at,
                    members: entries,
                    managers,
                }
            },
        )
        .collect();
    let access: Vec<AccessEntry> = access_map
        .into_iter()
        .map(|((account_id, vault_id), (role, via))| AccessEntry {
            account_id,
            vault_id,
            role,
            via,
        })
        .collect();
    let members: Vec<MemberReport> = members
        .into_iter()
        .map(|(account_id, email, role, status, joined_at)| {
            let mut methods = Vec::new();
            if totp.contains(&account_id) {
                methods.push("totp".to_owned());
            }
            if webauthn.contains(&account_id) {
                methods.push("webauthn".to_owned());
            }
            MemberReport {
                two_factor: !methods.is_empty(),
                two_factor_methods: methods,
                recovery_enrolled: enrolled.contains(&account_id),
                last_sign_in_at: sign_ins.get(&account_id).copied().unwrap_or(0),
                groups: groups_of.get(&account_id).cloned().unwrap_or_default(),
                vault_count: access.iter().filter(|a| a.account_id == account_id).count(),
                security: None,
                account_id,
                email,
                role,
                status,
                joined_at,
            }
        })
        .map(|mut m| {
            m.security = security.get(&m.account_id).copied();
            m
        })
        .collect();
    let pending_invitations: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"count!\" FROM org_invitations WHERE org_id = $1 AND status = 'pending' AND expires_at > $2",
        &org_id,
        now,
    )
    .fetch_one(&mut *conn)
    .await?;
    let pending_recovery_requests: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"count!\" FROM org_recovery_requests WHERE org_id = $1 AND status = 'pending' AND expires_at > $2",
        &org_id,
        now,
    )
    .fetch_one(&mut *conn)
    .await?;
    let recovery_set_up: Option<i64> = sqlx::query_scalar!(
        "SELECT 1::BIGINT AS \"one!\" FROM org_recovery_keys WHERE org_id = $1 LIMIT 1",
        &org_id,
    )
    .fetch_optional(&mut *conn)
    .await?;
    let policy_version: Option<i64> = sqlx::query_scalar!(
        "SELECT MAX(version) FROM org_policies WHERE org_id = $1",
        &org_id,
    )
    .fetch_optional(&mut *conn)
    .await?
    .flatten();
    let count_role = |guest: bool| {
        members
            .iter()
            .filter(|m| m.status == "confirmed" && (m.role == "guest") == guest)
            .count() as i64
    };
    let member_count = count_role(false);
    let guest_count = count_role(true);
    let agent_limit_per_member =
        super::service_accounts::agent_limit_per_member(&state, &mut conn).await?;
    let service_account_count: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"count!\" FROM service_accounts sa WHERE sa.revoked_at = 0 \
         AND (sa.expires_at = 0 OR sa.expires_at > $2) AND sa.account_id IN \
         (SELECT account_id FROM org_members WHERE org_id = $1 AND status = 'confirmed' \
          AND role <> 'guest')",
        &org_id,
        now,
    )
    .fetch_one(&mut *conn)
    .await?;
    Ok(Json(OrgReport {
        member_count,
        guest_count,
        service_account_count,
        agent_limit_per_member,
        generated_at: now,
        unused_after_days: UNUSED_AFTER_DAYS,
        members,
        vaults,
        access,
        pending_invitations,
        pending_recovery_requests,
        recovery_set_up: recovery_set_up.is_some(),
        policy_version: policy_version.unwrap_or(0),
    }))
}

// --- Security aggregates ------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityReportRequest {
    score: i64,
    total: i64,
    weak: i64,
    reused: i64,
    unsecured: i64,
    /// `true`/`false` if known whether the master password met the policy.
    #[serde(default)]
    password_meets_policy: Option<bool>,
}

/// `PUT /orgs/{id}/security-report`: a member's app reports its security
/// aggregate for this organization (numbers only).
pub async fn put_security_report(
    State(state): State<AppState>,
    session: Session,
    Path(org_id): Path<String>,
    Json(req): Json<SecurityReportRequest>,
) -> ApiResult<StatusCode> {
    validate::id("organization id", &org_id)?;
    let max = 1_000_000;
    if !(0..=100).contains(&req.score)
        || [req.total, req.weak, req.reused, req.unsecured]
            .iter()
            .any(|n| !(0..=max).contains(n))
        || req.weak > req.total
        || req.reused > req.total
        || req.unsecured > req.total
    {
        return Err(ApiError::bad_request("the report numbers are out of range"));
    }
    if let Some(wait) = state.limiter.hit(
        &format!("security-report:{}", session.account_id),
        30,
        std::time::Duration::from_secs(3600),
    ) {
        return Err(ApiError::RateLimited(wait));
    }
    let mut tx = state.db.as_account(&session.account_id).await?;
    access::require_confirmed(&mut tx, &org_id, &session.account_id).await?;
    sqlx::query!(
        "DELETE FROM org_security_reports WHERE org_id = $1 AND account_id = $2",
        &org_id,
        &session.account_id,
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!(
        "INSERT INTO org_security_reports (org_id, account_id, score, total, weak, reused, unsecured, \
         password_policy, reported_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        &org_id,
        &session.account_id,
        req.score,
        req.total,
        req.weak,
        req.reused,
        req.unsecured,
        match req.password_meets_policy {
        Some(true) => 1i64,
        Some(false) => 0,
        None => -1,
    },
        now_ms(),
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Settings ------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgSettings {
    /// Days to keep audit log entries (0 = forever, otherwise 30–3650).
    pub audit_retention_days: i64,
}

async fn load_settings(conn: &mut sqlx::PgConnection, org_id: &str) -> ApiResult<OrgSettings> {
    let days: Option<i64> = sqlx::query_scalar!(
        "SELECT audit_retention_days FROM org_settings WHERE org_id = $1",
        org_id,
    )
    .fetch_optional(&mut *conn)
    .await?;
    Ok(OrgSettings {
        audit_retention_days: days.unwrap_or(0),
    })
}

/// `GET /orgs/{id}/settings` (admins).
pub async fn get_settings(
    State(state): State<AppState>,
    session: Session,
    Path(org_id): Path<String>,
) -> ApiResult<Json<OrgSettings>> {
    validate::id("organization id", &org_id)?;
    let mut conn = state.db.as_account(&session.account_id).await?;
    access::require_admin(&mut conn, &org_id, &session.account_id).await?;
    Ok(Json(load_settings(&mut conn, &org_id).await?))
}

/// `PUT /orgs/{id}/settings` (owner and admins).
pub async fn put_settings(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(org_id): Path<String>,
    Json(req): Json<OrgSettings>,
) -> ApiResult<Json<OrgSettings>> {
    validate::id("organization id", &org_id)?;
    if req.audit_retention_days != 0 && !(30..=3650).contains(&req.audit_retention_days) {
        return Err(ApiError::bad_request(
            "keep audit entries forever (0) or for 30 to 3650 days",
        ));
    }
    let mut tx = state.db.as_account(&session.account_id).await?;
    access::require_admin(&mut tx, &org_id, &session.account_id).await?;
    let before = load_settings(&mut tx, &org_id).await?;
    sqlx::query!("DELETE FROM org_settings WHERE org_id = $1", &org_id,)
        .execute(&mut *tx)
        .await?;
    sqlx::query!(
        "INSERT INTO org_settings (org_id, audit_retention_days, updated_by, updated_at) VALUES ($1, $2, $3, $4)",
        &org_id,
        req.audit_retention_days,
        &session.account_id,
        now_ms(),
    )
    .execute(&mut *tx)
    .await?;
    if before.audit_retention_days != req.audit_retention_days {
        org_audit::record_in(
            &mut tx,
            &org_id,
            &Actor::of(&session, &ip),
            "settings_updated",
            Target::org(&org_id),
            json!({ "auditRetentionDays": req.audit_retention_days }),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(Json(req))
}

// --- Offboarding ------------------------------------------------------------------------

/// `POST /orgs/{id}/members/{aid}/end-sessions`: signs a member out on
/// every device (team organizations; admins, and only the owner for
/// admins). Sessions belong to the whole account, so this also ends
/// access to the member's personal vaults until they sign in again;
/// nothing is deleted.
pub async fn end_sessions(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path((org_id, account_id)): Path<(String, String)>,
) -> ApiResult<Json<serde_json::Value>> {
    validate::id("organization id", &org_id)?;
    validate::id("account id", &account_id)?;
    let mut tx = state.db.as_account(&session.account_id).await?;
    let me = access::require_admin(&mut tx, &org_id, &session.account_id).await?;
    let kind: String =
        sqlx::query_scalar!("SELECT kind FROM organizations WHERE id = $1", &org_id,)
            .fetch_one(&mut *tx)
            .await?;
    if kind != "team" {
        return Err(ApiError::forbidden(
            "forbidden",
            "only team organizations can sign members out",
        ));
    }
    let target = access::membership(&mut tx, &org_id, &account_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if account_id == session.account_id {
        return Err(ApiError::bad_request(
            "sign yourself out in Settings › Devices",
        ));
    }
    if target.role == OrgRole::Owner || (target.role == OrgRole::Admin && me.role != OrgRole::Owner)
    {
        return Err(ApiError::forbidden(
            "forbidden",
            "only the owner can sign out admins, and nobody the owner",
        ));
    }
    let ended = sqlx::query!("DELETE FROM sessions WHERE account_id = $1", &account_id,)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    org_audit::record_in(
        &mut tx,
        &org_id,
        &Actor::of(&session, &ip),
        "member_sessions_ended",
        Target::account(&account_id),
        json!({ "sessions": ended }),
    )
    .await?;
    tx.commit().await?;
    record_event(
        &state,
        &account_id,
        "sessions_ended_by_org",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    Ok(Json(json!({ "sessions": ended })))
}
