//! Extension points for code that embeds the server.
//!
//! A program that wraps this crate (for example a hosting layer) starts the
//! server with [`crate::run_with`] and an [`Extensions`] value:
//!
//! - `gate`: an [`OrgGate`] asked before an organization gains a member or
//!   uses an administration feature, and told about changes afterwards.
//! - `routes`: more routes, merged into the `/` router before the state is
//!   attached, so they can use [`crate::api::auth::Session`] and the other
//!   extractors.
//! - `on_start`: runs once after the background workers started.
//! - `meta`: extra information for `GET /api/v1/meta` (as `extensions`).
//!
//! [`Extensions::default`] allows everything and adds nothing; it is what
//! `passbox-server` itself runs with. Extensions also get helpers to read
//! organizations ([`org_facts`], [`all_org_facts`], [`account_emails`]) and
//! to make an organization read-only ([`lock_org`], [`unlock_org`]); they
//! run in the database context [`Job::Extensions`], which may read
//! organizations, members and invitations and write `org_locks`, nothing
//! else.

use std::sync::Arc;

use axum::Router;
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::PgConnection;

use crate::db::{Db, Job, now_ms};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

pub use passbox_core::sharing::objects::{OrgKind, OrgRole};

/// Administration features an [`OrgGate`] may restrict per organization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OrgFeature {
    /// Single sign-on configuration.
    Sso,
    /// SCIM provisioning tokens.
    Scim,
    /// Organization policies.
    Policies,
    /// Exporting the audit log.
    AuditLog,
    /// Event tokens (SIEM pull) and webhooks.
    EventsApi,
    /// Other changes in the organization console (organization settings).
    AdminConsole,
}

impl OrgFeature {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sso => "sso",
            Self::Scim => "scim",
            Self::Policies => "policies",
            Self::AuditLog => "audit_log",
            Self::EventsApi => "events_api",
            Self::AdminConsole => "admin_console",
        }
    }
}

/// What the server knows about an organization when it asks the gate.
///
/// The numbers describe the organization before the change in question.
/// When an invitation is accepted, it is still pending and counted in
/// `people`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgFacts {
    pub id: String,
    pub kind: OrgKind,
    pub owner_id: String,
    /// Owners, admins and members in any status (accepted, confirmed,
    /// suspended). Guests are not counted.
    pub seats: i64,
    /// `seats` plus pending, unexpired invitations that are not for guests
    /// (one per email address).
    pub people: i64,
}

/// A gate's refusal. It reaches the client as HTTP 403 with
/// `{ "error": code, "message": message, "details": details }`.
#[derive(Debug, Clone)]
pub struct Denial {
    pub code: &'static str,
    pub message: String,
    pub details: Value,
}

impl Denial {
    pub fn new(code: &'static str, message: impl Into<String>, details: Value) -> Self {
        Self {
            code,
            message: message.into(),
            details,
        }
    }
}

impl From<Denial> for ApiError {
    fn from(denial: Denial) -> Self {
        ApiError::Denied {
            code: denial.code,
            message: denial.message,
            details: denial.details,
        }
    }
}

/// Changes the server reports to the gate after they were committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrgEvent {
    Created {
        org_id: String,
        kind: OrgKind,
        owner_id: String,
    },
    /// Members or pending invitations changed: invited, invitation revoked,
    /// joined, confirmed, role changed, suspended, reactivated, removed,
    /// provisioned or deprovisioned through SCIM, joined through SSO.
    MembersChanged {
        org_id: String,
    },
    Deleted {
        org_id: String,
    },
}

/// Decides whether an organization may grow or use a feature. Every
/// method allows by default.
///
/// The `may_*` methods run inside the request's database transaction
/// (which holds a lock on the organization while a member is added), so
/// keep them quick. `on_event` runs after the commit, on the request's
/// task; spawn anything slow.
#[async_trait::async_trait]
pub trait OrgGate: Send + Sync + 'static {
    /// Before someone joins with `role`: an invitation, accepting one,
    /// promoting a guest, reactivating a suspended member, SCIM
    /// provisioning, joining through SSO.
    async fn may_add_member(&self, _org: &OrgFacts, _role: OrgRole) -> Result<(), Denial> {
        Ok(())
    }

    /// Before a change that uses `feature`. Reading stays allowed.
    async fn may_use(&self, _org: &OrgFacts, _feature: OrgFeature) -> Result<(), Denial> {
        Ok(())
    }

    fn on_event(&self, _event: OrgEvent) {}
}

/// The gate of the open-source server: everything is allowed.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAll;

impl OrgGate for AllowAll {}

/// Builds extra routes; they are merged before the state is attached.
pub type RouterHook = Arc<dyn Fn(&AppState) -> Router<AppState> + Send + Sync>;
/// Runs after the background workers started.
pub type StartHook = Arc<dyn Fn(AppState) + Send + Sync>;
/// Returns the `extensions` object of `/api/v1/meta`.
pub type MetaHook = Arc<dyn Fn() -> Value + Send + Sync>;

/// What an embedding program adds to the server.
#[derive(Clone)]
pub struct Extensions {
    pub gate: Arc<dyn OrgGate>,
    pub routes: Option<RouterHook>,
    pub on_start: Option<StartHook>,
    pub meta: Option<MetaHook>,
}

impl Default for Extensions {
    fn default() -> Self {
        Self {
            gate: Arc::new(AllowAll),
            routes: None,
            on_start: None,
            meta: None,
        }
    }
}

impl Extensions {
    /// Puts the gate and the meta hook into the state.
    pub fn install(&self, state: &mut AppState) {
        state.gate = self.gate.clone();
        state.ext_meta = self.meta.clone();
    }
}

/// Why an organization is read-only, as clients see it (`lock` on
/// organization records, `details` of `org_read_only` errors).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OrgLock {
    pub reason: String,
    pub source: String,
}

/// Error code while an organization is read-only.
pub const ORG_READ_ONLY: &str = "org_read_only";
/// Error code when a family is full (`PASSBOX_FAMILY_MEMBER_LIMIT`).
pub const FAMILY_LIMIT_REACHED: &str = "family_limit_reached";

/// The 403 for changes to a read-only organization.
pub fn read_only(lock: &OrgLock) -> ApiError {
    ApiError::Denied {
        code: ORG_READ_ONLY,
        message: "the organization is read-only".to_owned(),
        details: json!({ "reason": lock.reason, "source": lock.source }),
    }
}

// --- Inside the server ------------------------------------------------------------------

/// The facts and lock of an organization, as the current context may see
/// them (members, invitees, the organization's SCIM and SSO contexts, the
/// extension context).
pub(crate) async fn org_state(
    conn: &mut PgConnection,
    org_id: &str,
) -> ApiResult<Option<(OrgFacts, Option<OrgLock>)>> {
    let row = sqlx::query!(
        r#"SELECT kind AS "kind!", owner_id AS "owner_id!", seats AS "seats!", people AS "people!",
                  lock_reason, lock_source
           FROM passbox.org_facts($1, $2)"#,
        org_id,
        now_ms(),
    )
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let kind = OrgKind::parse(&row.kind).map_err(|e| ApiError::Internal(e.into()))?;
    let lock = match (row.lock_reason, row.lock_source) {
        (Some(reason), Some(source)) => Some(OrgLock { reason, source }),
        _ => None,
    };
    Ok(Some((
        OrgFacts {
            id: org_id.to_owned(),
            kind,
            owner_id: row.owner_id,
            seats: row.seats,
            people: row.people,
        },
        lock,
    )))
}

/// How someone joins, for [`check_add_member`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Joining {
    /// A new invitation (also SCIM provisioning): one more person.
    Invite,
    /// Accepting a pending invitation (also through SSO): the person is
    /// counted already.
    Accept,
    /// A guest becomes a member: one more person.
    Promote,
    /// A suspended member is reactivated: counted already; the family limit
    /// does not apply.
    Reactivate,
}

/// Checks that someone may join the organization with `role`: it is not
/// read-only, the family limit holds and the gate agrees. Serializes
/// concurrent additions to the organization until the transaction ends.
pub(crate) async fn check_add_member(
    state: &AppState,
    conn: &mut PgConnection,
    org_id: &str,
    role: OrgRole,
    joining: Joining,
) -> ApiResult<OrgFacts> {
    sqlx::query("SELECT 1 FROM pg_advisory_xact_lock(hashtextextended($1, 7262270))")
        .bind(org_id)
        .execute(&mut *conn)
        .await?;
    let (facts, lock) = org_state(conn, org_id).await?.ok_or(ApiError::NotFound)?;
    if let Some(lock) = &lock {
        return Err(read_only(lock));
    }
    let limit = i64::from(state.family_member_limit);
    if facts.kind == OrgKind::Family && role != OrgRole::Guest && limit > 0 {
        let after = match joining {
            Joining::Invite | Joining::Promote => Some(facts.people + 1),
            Joining::Accept => Some(facts.people),
            Joining::Reactivate => None,
        };
        if after.is_some_and(|after| after > limit) {
            return Err(Denial::new(
                FAMILY_LIMIT_REACHED,
                format!("a family can have at most {limit} members"),
                json!({ "limit": limit }),
            )
            .into());
        }
    }
    state.gate.may_add_member(&facts, role).await?;
    Ok(facts)
}

/// Checks a change that uses `feature`: the gate agrees and, for `write`,
/// the organization is not read-only.
pub(crate) async fn check_feature(
    state: &AppState,
    conn: &mut PgConnection,
    org_id: &str,
    feature: OrgFeature,
    write: bool,
) -> ApiResult<()> {
    let (facts, lock) = org_state(conn, org_id).await?.ok_or(ApiError::NotFound)?;
    if write && let Some(lock) = &lock {
        return Err(read_only(lock));
    }
    state.gate.may_use(&facts, feature).await?;
    Ok(())
}

/// Tells the gate about a committed change.
pub(crate) fn emit(state: &AppState, event: OrgEvent) {
    state.gate.on_event(event);
}

/// Shorthand for [`OrgEvent::MembersChanged`].
pub(crate) fn members_changed(state: &AppState, org_id: &str) {
    emit(
        state,
        OrgEvent::MembersChanged {
            org_id: org_id.to_owned(),
        },
    );
}

// --- Helpers for extensions -------------------------------------------------------------

/// The facts of one organization (`None` if it does not exist).
pub async fn org_facts(db: &Db, org_id: &str) -> anyhow::Result<Option<OrgFacts>> {
    let mut tx = db.system(Job::Extensions).await?;
    let state = org_state(&mut tx, org_id)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    tx.commit().await?;
    Ok(state.map(|(facts, _)| facts))
}

/// The facts of every organization, oldest first.
pub async fn all_org_facts(db: &Db) -> anyhow::Result<Vec<OrgFacts>> {
    let mut tx = db.system(Job::Extensions).await?;
    let rows = sqlx::query!(
        r#"SELECT o.id, f.kind AS "kind!", f.owner_id AS "owner_id!", f.seats AS "seats!",
                  f.people AS "people!"
           FROM organizations o, passbox.org_facts(o.id, $1) f ORDER BY o.created_at, o.id"#,
        now_ms(),
    )
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    rows.into_iter()
        .map(|row| {
            Ok(OrgFacts {
                kind: OrgKind::parse(&row.kind)?,
                id: row.id,
                owner_id: row.owner_id,
                seats: row.seats,
                people: row.people,
            })
        })
        .collect()
}

/// `(id, email)` of the given accounts (unknown IDs are left out).
pub async fn account_emails(db: &Db, ids: &[String]) -> anyhow::Result<Vec<(String, String)>> {
    let mut tx = db.system(Job::Extensions).await?;
    let rows = sqlx::query!(
        r#"SELECT id AS "id!", email AS "email!" FROM passbox.ext_accounts($1)"#,
        ids,
    )
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(rows.into_iter().map(|row| (row.id, row.email)).collect())
}

/// The lock of an organization, if it is read-only.
pub async fn org_lock(db: &Db, org_id: &str) -> anyhow::Result<Option<OrgLock>> {
    let mut tx = db.system(Job::Extensions).await?;
    let lock = sqlx::query_as!(
        OrgLock,
        "SELECT reason, source FROM org_locks WHERE org_id = $1",
        org_id,
    )
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(lock)
}

/// Makes an organization read-only. An organization has at most one lock:
/// locking it again replaces reason and source. Returns `false` if the
/// organization does not exist.
pub async fn lock_org(db: &Db, org_id: &str, source: &str, reason: &str) -> anyhow::Result<bool> {
    anyhow::ensure!(
        !source.is_empty() && source.len() <= 100,
        "the lock source must have 1 to 100 characters"
    );
    anyhow::ensure!(
        reason.len() <= 500,
        "the lock reason must have at most 500 characters"
    );
    let mut tx = db.system(Job::Extensions).await?;
    let exists = sqlx::query_scalar!(
        r#"SELECT 1::BIGINT AS "one!" FROM organizations WHERE id = $1"#,
        org_id,
    )
    .fetch_optional(&mut *tx)
    .await?
    .is_some();
    if !exists {
        return Ok(false);
    }
    sqlx::query!("DELETE FROM org_locks WHERE org_id = $1", org_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query!(
        "INSERT INTO org_locks (org_id, reason, source, locked_at) VALUES ($1, $2, $3, $4)",
        org_id,
        reason,
        source,
        now_ms(),
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// Removes the organization's lock if `source` set it. Returns whether a
/// lock was removed.
pub async fn unlock_org(db: &Db, org_id: &str, source: &str) -> anyhow::Result<bool> {
    let mut tx = db.system(Job::Extensions).await?;
    let removed = sqlx::query!(
        "DELETE FROM org_locks WHERE org_id = $1 AND source = $2",
        org_id,
        source,
    )
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;
    Ok(removed > 0)
}
