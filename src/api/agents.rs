//! Approval relay and audit for AI agents.
//!
//! The agent broker (`pbx mcp`) asks for a grant; the server relays the
//! request to the account's other signed-in devices (web, desktop), where
//! the person approves or denies it. The decision is signed with the
//! account key on that device and verified by the broker, so the server can
//! neither approve on its own nor change what the person sees. The server
//! checks the signature as well, to keep garbage out, and records every
//! step in the account's activity.
//!
//! The broker reports what the agent did with a grant (`run`, `inject`,
//! `create`, ...) as agent events: tool, items, the command's first word
//! plus a hash, and the result. Never values.
//!
//! `reveal` (`passbox_reveal`, ADR 0006) is checked here too, as far as a
//! server can: a decision that allows revealing is refused when an item's
//! vault belongs to an organization whose policy does not allow agent
//! reveals, and a successful `reveal` event (which the broker must report
//! before it hands out the value) is refused unless it names an approved,
//! unexpired grant whose signed decision allows revealing those items.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use passbox_core::agent_grant::{Decision, GrantRequest, PrincipalKind, verify_decision};
use passbox_core::identity::SignedBundle;
use passbox_core::{encoding, id};
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;

use super::auth::{Session, record_event};
use super::service_accounts::ServiceAuth;
use super::validate;
use crate::db::now_ms;
use crate::error::{ApiError, ApiResult};
use crate::security::ClientIp;
use crate::state::AppState;

/// A request waits this long for a decision.
const PENDING_TTL_MS: i64 = 10 * 60 * 1000;
/// Pending requests per account.
const MAX_PENDING: i64 = 10;
/// Requests per principal and 10 minutes.
const MAX_REQUESTS: u32 = 30;
/// Agent events per principal and minute.
const MAX_EVENTS: u32 = 120;

const TOOLS: &[&str] = &[
    "search",
    "request_access",
    "run",
    "inject",
    "create",
    "generate",
    "reveal",
];
const RESULTS: &[&str] = &["ok", "failed", "denied", "expired", "blocked"];

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::Internal(anyhow::anyhow!("{e}"))
}

struct Principal<'a> {
    kind: PrincipalKind,
    id: &'a str,
    /// The account that approves (the session's account or the owner).
    account_id: &'a str,
}

#[derive(Deserialize)]
pub struct CreateRequest {
    request: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateResponse {
    id: String,
    expires_at: i64,
}

async fn create_grant(
    state: &AppState,
    principal: Principal<'_>,
    ip: &str,
    encoded: &str,
) -> ApiResult<(StatusCode, Json<CreateResponse>)> {
    if let Some(wait) = state.limiter.hit(
        &format!("agent-grant:{}", principal.id),
        MAX_REQUESTS,
        std::time::Duration::from_secs(600),
    ) {
        return Err(ApiError::RateLimited(wait));
    }
    validate::base64("request", encoded, validate::MAX_SMALL_LEN * 4)?;
    let request = GrantRequest::decode(encoded)
        .map_err(|e| ApiError::bad_request(format!("invalid request: {e}")))?;
    if request.principal_kind != principal.kind
        || request.principal_id != principal.id
        || request.on_behalf_of != principal.account_id
    {
        return Err(ApiError::bad_request(
            "the request names another principal or account",
        ));
    }
    let now = now_ms();
    if (request.created_at - now).abs() > 5 * 60 * 1000 {
        return Err(ApiError::bad_request(
            "the request's time is off by more than 5 minutes; check the clock",
        ));
    }
    let mut tx = state.db.as_account(principal.account_id).await?;
    sqlx::query!(
        "UPDATE agent_grants SET status = 'expired' WHERE account_id = $1 AND status = 'pending' \
         AND expires_at <= $2",
        principal.account_id,
        now,
    )
    .execute(&mut *tx)
    .await?;
    let pending: i64 = sqlx::query_scalar!(
        "SELECT COUNT(*) AS \"count!\" FROM agent_grants WHERE account_id = $1 AND status = 'pending'",
        principal.account_id,
    )
    .fetch_one(&mut *tx)
    .await?;
    if pending >= MAX_PENDING {
        return Err(ApiError::bad_request(
            "too many requests are waiting for approval; answer or let them expire first",
        ));
    }
    let expires_at = now + PENDING_TTL_MS;
    let inserted = sqlx::query!(
        "INSERT INTO agent_grants (id, account_id, principal_kind, principal_id, client_name, request, \
         status, decision, decision_signature, decided_device, not_after, ip, created_at, expires_at, \
         decided_at) VALUES ($1, $2, $3, $4, $5, $6, 'pending', NULL, NULL, '', 0, $7, $8, $9, 0)",
        &request.id,
        principal.account_id,
        principal.kind.as_str(),
        principal.id,
        &request.client_name,
        encoded,
        ip,
        now,
        expires_at,
    )
    .execute(&mut *tx)
    .await;
    if inserted.is_err() {
        return Err(ApiError::conflict(
            "a request with this ID exists",
            serde_json::json!({}),
        ));
    }
    tx.commit().await?;
    record_event(
        state,
        principal.account_id,
        "agent_grant_requested",
        &request.client_name,
        "agent",
        ip,
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(CreateResponse {
            id: request.id,
            expires_at,
        }),
    ))
}

/// `POST /agent-grants`: a CLI session (`pbx mcp` signed in as the account)
/// asks for a grant.
pub async fn create(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Json(req): Json<CreateRequest>,
) -> ApiResult<(StatusCode, Json<CreateResponse>)> {
    create_grant(
        &state,
        Principal {
            kind: PrincipalKind::Session,
            id: &session.account_id,
            account_id: &session.account_id,
        },
        &ip,
        &req.request,
    )
    .await
}

/// `POST /service-account/agent-grants`: `pbx mcp` running with a service
/// account token asks the owner for a grant.
pub async fn sa_create(
    State(state): State<AppState>,
    auth: ServiceAuth,
    Json(req): Json<CreateRequest>,
) -> ApiResult<(StatusCode, Json<CreateResponse>)> {
    let ip = auth.ip.clone();
    create_grant(
        &state,
        Principal {
            kind: PrincipalKind::Service,
            id: &auth.id,
            account_id: &auth.owner_id,
        },
        &ip,
        &req.request,
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantStatus {
    id: String,
    /// `pending`, `approved`, `denied`, `expired` or `revoked`.
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decision_signature: Option<String>,
    not_after: i64,
    expires_at: i64,
}

type StatusRow = (String, String, Option<String>, Option<String>, i64, i64);

fn status_of(row: StatusRow) -> GrantStatus {
    let (id, mut status, decision, decision_signature, not_after, expires_at) = row;
    if status == "pending" && expires_at <= now_ms() {
        status = "expired".into();
    }
    GrantStatus {
        id,
        status,
        decision,
        decision_signature,
        not_after,
        expires_at,
    }
}

async fn grant_status(
    conn: &mut PgConnection,
    grant_id: &str,
    kind: PrincipalKind,
    principal_id: &str,
) -> ApiResult<GrantStatus> {
    let row: StatusRow = sqlx::query!(
        "SELECT id, status, decision, decision_signature, not_after, expires_at FROM agent_grants \
         WHERE id = $1 AND principal_kind = $2 AND principal_id = $3",
        grant_id,
        kind.as_str(),
        principal_id,
    )
    .map(|row| {
        (
            row.id,
            row.status,
            row.decision,
            row.decision_signature,
            row.not_after,
            row.expires_at,
        )
    })
    .fetch_optional(&mut *conn)
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(status_of(row))
}

/// `GET /agent-grants/{id}`: the requesting session polls for the decision.
pub async fn get(
    State(state): State<AppState>,
    session: Session,
    Path(grant_id): Path<String>,
) -> ApiResult<Json<GrantStatus>> {
    let mut conn = state.db.as_account(&session.account_id).await?;
    Ok(Json(
        grant_status(
            &mut conn,
            &grant_id,
            PrincipalKind::Session,
            &session.account_id,
        )
        .await?,
    ))
}

/// `GET /service-account/agent-grants/{id}`.
pub async fn sa_get(
    State(state): State<AppState>,
    auth: ServiceAuth,
    Path(grant_id): Path<String>,
) -> ApiResult<Json<GrantStatus>> {
    let mut conn = state.db.as_account(&auth.owner_id).await?;
    Ok(Json(
        grant_status(&mut conn, &grant_id, PrincipalKind::Service, &auth.id).await?,
    ))
}

#[derive(Deserialize)]
pub struct ListQuery {
    /// `pending` (default) or `all` (recent grants, newest first).
    #[serde(default)]
    status: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantRecord {
    id: String,
    principal_kind: String,
    principal_id: String,
    /// The service account's name, for service principals.
    #[serde(skip_serializing_if = "Option::is_none")]
    principal_name: Option<String>,
    client_name: String,
    /// Base64url canonical request: parse and display it, then sign that.
    request: String,
    status: String,
    not_after: i64,
    decided_device: String,
    ip: String,
    created_at: i64,
    expires_at: i64,
    decided_at: i64,
}

/// `GET /agent-grants`: requests waiting for this account's decision (or,
/// with `status=all`, the last 100).
pub async fn list(
    State(state): State<AppState>,
    session: Session,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<Vec<GrantRecord>>> {
    let all = query.status.as_deref() == Some("all");
    let now = now_ms();
    let mut tx = state.db.as_account(&session.account_id).await?;
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        String,
        String,
        String,
        Option<String>,
        String,
        String,
        String,
        i64,
        String,
        String,
        i64,
        i64,
        i64,
    )> = if all {
        sqlx::query!(
            "SELECT g.id, g.principal_kind, g.principal_id, s.name AS \"name?\", g.client_name, g.request, g.status, \
             g.not_after, g.decided_device, g.ip, g.created_at, g.expires_at, g.decided_at \
             FROM agent_grants g LEFT JOIN service_accounts s ON g.principal_kind = 'service' \
             AND s.id = g.principal_id WHERE g.account_id = $1 AND g.created_at > $2 \
             ORDER BY g.created_at DESC LIMIT 100",
            &session.account_id,
            now - 30 * 86_400_000,
        ).map(|row| (row.id, row.principal_kind, row.principal_id, row.name, row.client_name, row.request, row.status, row.not_after, row.decided_device, row.ip, row.created_at, row.expires_at, row.decided_at))
        .fetch_all(&mut *tx)
        .await?
    } else {
        sqlx::query!(
            "SELECT g.id, g.principal_kind, g.principal_id, s.name AS \"name?\", g.client_name, g.request, g.status, \
             g.not_after, g.decided_device, g.ip, g.created_at, g.expires_at, g.decided_at \
             FROM agent_grants g LEFT JOIN service_accounts s ON g.principal_kind = 'service' \
             AND s.id = g.principal_id WHERE g.account_id = $1 AND g.status = 'pending' \
             AND g.expires_at > $2 ORDER BY g.created_at DESC LIMIT 100",
            &session.account_id,
            now,
        ).map(|row| (row.id, row.principal_kind, row.principal_id, row.name, row.client_name, row.request, row.status, row.not_after, row.decided_device, row.ip, row.created_at, row.expires_at, row.decided_at))
        .fetch_all(&mut *tx)
        .await?
    };
    Ok(Json(
        rows.into_iter()
            .map(
                |(
                    id,
                    principal_kind,
                    principal_id,
                    principal_name,
                    client_name,
                    request,
                    status,
                    not_after,
                    decided_device,
                    ip,
                    created_at,
                    expires_at,
                    decided_at,
                )| GrantRecord {
                    id,
                    principal_kind,
                    principal_id,
                    principal_name,
                    client_name,
                    request,
                    status: if status == "pending" && expires_at <= now {
                        "expired".into()
                    } else {
                        status
                    },
                    not_after,
                    decided_device,
                    ip,
                    created_at,
                    expires_at,
                    decided_at,
                },
            )
            .collect(),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecideRequest {
    decision: String,
    decision_signature: String,
}

/// `POST /agent-grants/{id}/decision`: the person's signed answer, from one
/// of their signed-in devices.
pub async fn decide(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(grant_id): Path<String>,
    Json(req): Json<DecideRequest>,
) -> ApiResult<Json<GrantStatus>> {
    validate::base64("decision", &req.decision, validate::MAX_SMALL_LEN)?;
    validate::base64("decisionSignature", &req.decision_signature, 256)?;
    // Defense in depth: approvals come from the apps, not from the command
    // line an agent may be driving. (The client kind is self-declared; the
    // real protection is that pbx offers no way to approve.)
    if session.client_kind == "cli" {
        return Err(ApiError::forbidden(
            "forbidden",
            "approve agent requests in the Passbox web or desktop app",
        ));
    }
    let mut tx = state.db.as_account(&session.account_id).await?;
    let row: Option<(String, String, i64)> = sqlx::query!(
        "SELECT request, status, expires_at FROM agent_grants WHERE id = $1 AND account_id = $2",
        &grant_id,
        &session.account_id,
    )
    .map(|row| (row.request, row.status, row.expires_at))
    .fetch_optional(&mut *tx)
    .await?;
    let (request, status, expires_at) = row.ok_or(ApiError::NotFound)?;
    if status != "pending" || expires_at <= now_ms() {
        return Err(ApiError::conflict(
            "this request was already answered or has expired",
            serde_json::json!({ "status": status }),
        ));
    }
    let (bundle, signature): (String, String) = sqlx::query!(
        r#"SELECT bundle AS "bundle!", bundle_signature AS "bundle_signature!" FROM public_keys
           WHERE account_id = $1 ORDER BY key_version DESC LIMIT 1"#,
        &session.account_id,
    )
    .map(|row| (row.bundle, row.bundle_signature))
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::bad_request("publish your account keys first"))?;
    let sig_pk = SignedBundle::parse(&bundle, &signature)
        .map_err(internal)?
        .bundle
        .sig_pk;
    let request_bytes = encoding::decode(&request).map_err(internal)?;
    let decision: Decision = verify_decision(
        &sig_pk,
        &session.account_id,
        &request_bytes,
        &req.decision,
        &req.decision_signature,
    )
    .map_err(|e| ApiError::bad_request(format!("invalid decision: {e}")))?;
    if decision.reveal_allowed {
        let parsed = GrantRequest::from_canonical(&request_bytes).map_err(internal)?;
        let vaults: Vec<String> = parsed.items.iter().map(|i| i.vault_id.clone()).collect();
        check_reveal_policy(&mut tx, &vaults).await?;
    }
    let status = if decision.approved {
        "approved"
    } else {
        "denied"
    };
    sqlx::query!(
        "UPDATE agent_grants SET status = $1, decision = $2, decision_signature = $3, \
         decided_device = $4, not_after = $5, decided_at = $6 WHERE id = $7",
        status,
        &req.decision,
        &req.decision_signature,
        &session.device_name,
        decision.not_after,
        now_ms(),
        &grant_id,
    )
    .execute(&mut *tx)
    .await?;
    let row: StatusRow = sqlx::query!(
        "SELECT id, status, decision, decision_signature, not_after, expires_at FROM agent_grants \
         WHERE id = $1",
        &grant_id,
    )
    .map(|row| {
        (
            row.id,
            row.status,
            row.decision,
            row.decision_signature,
            row.not_after,
            row.expires_at,
        )
    })
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    record_event(
        &state,
        &session.account_id,
        if decision.approved {
            "agent_grant_approved"
        } else {
            "agent_grant_denied"
        },
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    Ok(Json(status_of(row)))
}

/// `POST /agent-grants/{id}/revoke`: ends an approved grant early. The
/// broker checks the grant's status before every use.
pub async fn revoke(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Path(grant_id): Path<String>,
) -> ApiResult<StatusCode> {
    let mut tx = state.db.as_account(&session.account_id).await?;
    let result = sqlx::query!(
        "UPDATE agent_grants SET status = 'revoked' WHERE id = $1 AND account_id = $2 \
         AND status IN ('pending', 'approved')",
        &grant_id,
        &session.account_id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    record_event(
        &state,
        &session.account_id,
        "agent_grant_revoked",
        &session.device_name,
        &session.client_kind,
        &ip,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventRequest {
    /// The grant used; empty for actions without one (search).
    #[serde(default)]
    grant_id: String,
    tool: String,
    #[serde(default)]
    item_ids: Vec<String>,
    /// For example `npm#3f2a…` (first word and hash of the command) or an
    /// output path. Never values.
    #[serde(default)]
    target: String,
    result: String,
    #[serde(default)]
    client_name: String,
}

/// Refuses (403 `policy_violation`) when one of the vaults belongs to an
/// organization whose policy does not allow revealing values to AI agents
/// (`allow_agent_reveal`, off by default and without a policy).
async fn check_reveal_policy(conn: &mut PgConnection, vault_ids: &[String]) -> ApiResult<()> {
    for vault_id in vault_ids {
        let org: Option<Option<String>> =
            sqlx::query_scalar!("SELECT org_id FROM vaults WHERE id = $1", vault_id,)
                .fetch_optional(&mut *conn)
                .await?;
        if let Some(Some(org_id)) = org {
            let allowed = super::org_policy::current_rules(conn, &org_id)
                .await?
                .is_some_and(|r| r.allow_agent_reveal);
            if !allowed {
                return Err(ApiError::forbidden(
                    "policy_violation",
                    "the organization's policy does not allow revealing values of its vaults to AI agents",
                ));
            }
        }
    }
    Ok(())
}

/// A successful `reveal` must name an approved, unexpired grant of this
/// principal whose signed decision allows revealing, covering the items,
/// and the organizations' policies must allow it (403 otherwise; the
/// broker then reveals nothing).
async fn check_reveal(
    state: &AppState,
    principal: &Principal<'_>,
    req: &EventRequest,
) -> ApiResult<()> {
    let denied =
        |message: &str| ApiError::forbidden("agent_reveal_not_allowed", message.to_owned());
    if req.grant_id.is_empty() || req.item_ids.is_empty() {
        return Err(denied("a reveal needs an approved grant"));
    }
    let mut conn = state.db.as_account(principal.account_id).await?;
    let row: Option<(String, String, Option<String>, i64)> = sqlx::query!(
        "SELECT request, status, decision, not_after FROM agent_grants \
         WHERE id = $1 AND account_id = $2 AND principal_kind = $3 AND principal_id = $4",
        &req.grant_id,
        principal.account_id,
        principal.kind.as_str(),
        principal.id,
    )
    .map(|row| (row.request, row.status, row.decision, row.not_after))
    .fetch_optional(&mut *conn)
    .await?;
    let Some((request, status, decision, not_after)) = row else {
        return Err(denied("the grant does not exist"));
    };
    if status != "approved" || not_after <= now_ms() {
        return Err(denied(
            "the grant is not approved, was revoked or has expired",
        ));
    }
    let decision = encoding::decode(decision.as_deref().unwrap_or_default())
        .ok()
        .and_then(|bytes| Decision::from_canonical(&bytes).ok());
    if !decision.is_some_and(|d| d.approved && d.reveal_allowed) {
        return Err(denied(
            "the person did not allow revealing values for this grant",
        ));
    }
    let parsed = GrantRequest::decode(&request).map_err(internal)?;
    if !parsed.asks_reveal() {
        return Err(denied("the grant does not cover revealing values"));
    }
    let mut vaults = Vec::new();
    for item_id in &req.item_ids {
        let Some(item) = parsed.items.iter().find(|i| &i.item_id == item_id) else {
            return Err(denied("the grant does not cover this item"));
        };
        vaults.push(item.vault_id.clone());
    }
    check_reveal_policy(&mut conn, &vaults).await
}

async fn record_agent_event(
    state: &AppState,
    principal: Principal<'_>,
    ip: &str,
    req: EventRequest,
) -> ApiResult<StatusCode> {
    if let Some(wait) = state.limiter.hit(
        &format!("agent-event:{}", principal.id),
        MAX_EVENTS,
        std::time::Duration::from_secs(60),
    ) {
        return Err(ApiError::RateLimited(wait));
    }
    if !TOOLS.contains(&req.tool.as_str()) || !RESULTS.contains(&req.result.as_str()) {
        return Err(ApiError::bad_request("unknown tool or result"));
    }
    if !req.grant_id.is_empty() {
        validate::id("grantId", &req.grant_id)?;
    }
    if req.item_ids.len() > 50 || req.item_ids.iter().any(|i| !id::is_valid_id(i)) {
        return Err(ApiError::bad_request("invalid itemIds"));
    }
    let target: String = req.target.chars().take(200).collect();
    let client_name: String = req.client_name.chars().take(100).collect();
    if target
        .chars()
        .chain(client_name.chars())
        .any(char::is_control)
    {
        return Err(ApiError::bad_request("control characters are not allowed"));
    }
    if req.tool == "reveal" && req.result == "ok" {
        check_reveal(state, &principal, &req).await?;
    }
    let mut tx = state.db.as_account(principal.account_id).await?;
    sqlx::query!(
        "INSERT INTO agent_events (id, account_id, grant_id, principal_kind, principal_id, client_name, \
         tool, item_ids, target, result, ip, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        id::new_id().map_err(internal)?,
        principal.account_id,
        &req.grant_id,
        principal.kind.as_str(),
        principal.id,
        &client_name,
        &req.tool,
        req.item_ids.join(","),
        &target,
        &req.result,
        ip,
        now_ms(),
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    // Searches are frequent and reveal nothing; they stay in the agent log.
    if req.tool != "search" {
        record_event(
            state,
            principal.account_id,
            &format!("agent_{}", req.tool),
            &client_name,
            "agent",
            ip,
        )
        .await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /agent-events`: the broker reports an agent action.
pub async fn event(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Session,
    Json(req): Json<EventRequest>,
) -> ApiResult<StatusCode> {
    record_agent_event(
        &state,
        Principal {
            kind: PrincipalKind::Session,
            id: &session.account_id,
            account_id: &session.account_id,
        },
        &ip,
        req,
    )
    .await
}

/// `POST /service-account/agent-events`.
pub async fn sa_event(
    State(state): State<AppState>,
    auth: ServiceAuth,
    Json(req): Json<EventRequest>,
) -> ApiResult<StatusCode> {
    let ip = auth.ip.clone();
    record_agent_event(
        &state,
        Principal {
            kind: PrincipalKind::Service,
            id: &auth.id,
            account_id: &auth.owner_id,
        },
        &ip,
        req,
    )
    .await
}

#[derive(Deserialize)]
pub struct EventsQuery {
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentEvent {
    id: String,
    grant_id: String,
    principal_kind: String,
    principal_id: String,
    client_name: String,
    tool: String,
    item_ids: Vec<String>,
    target: String,
    result: String,
    ip: String,
    created_at: i64,
}

/// `GET /agent-events`: what agents did on behalf of this account.
pub async fn events(
    State(state): State<AppState>,
    session: Session,
    Query(query): Query<EventsQuery>,
) -> ApiResult<Json<Vec<AgentEvent>>> {
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        i64,
    )> = sqlx::query!(
        "SELECT id, grant_id, principal_kind, principal_id, client_name, tool, item_ids, target, result, \
         ip, created_at FROM agent_events WHERE account_id = $1 ORDER BY created_at DESC LIMIT $2",
        &session.account_id,
        query.limit.unwrap_or(100).clamp(1, 500),
    ).map(|row| (row.id, row.grant_id, row.principal_kind, row.principal_id, row.client_name, row.tool, row.item_ids, row.target, row.result, row.ip, row.created_at))
    .fetch_all(&mut *state.db.as_account(&session.account_id).await?)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(
                |(
                    id,
                    grant_id,
                    principal_kind,
                    principal_id,
                    client_name,
                    tool,
                    item_ids,
                    target,
                    result,
                    ip,
                    created_at,
                )| AgentEvent {
                    id,
                    grant_id,
                    principal_kind,
                    principal_id,
                    client_name,
                    tool,
                    item_ids: item_ids
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .collect(),
                    target,
                    result,
                    ip,
                    created_at,
                },
            )
            .collect(),
    ))
}
