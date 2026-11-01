//! Database access (PostgreSQL only, see docs/adr/0007-postgresql-only.md).
//!
//! Handlers never get a connection pool. Every unit of work is a
//! transaction that first states on whose behalf it runs; row level
//! security policies in the database then limit what its statements can see
//! and change, even if a query forgets a tenant filter
//! (docs/architecture/database-security.md):
//!
//! - [`Db::as_account`]: a signed-in account (`passbox.account_id`).
//! - [`Db::public`]: one of a few named pre-authentication contexts
//!   (`passbox.context`), each limited to the tables its flow needs.
//! - [`Db::as_org`]: an organization's machine credential (SCIM, events
//!   API), limited to that organization (`passbox.org_id`).
//! - [`Db::system`]: a background job or server start (`passbox.system`);
//!   jobs run on the worker pool with the `passbox_worker` role.
//!
//! The settings are transaction-local (`set_config(..., true)`), so nothing
//! carries over to the next user of a pooled connection.

use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use passbox_core::encoding;
use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;
use sqlx::migrate::Migrator;
use sqlx::postgres::{
    PgArgumentBuffer, PgConnectOptions, PgPool, PgPoolOptions, PgTypeInfo, PgValueRef,
};
use sqlx::{Decode, Encode, Postgres, Type};

/// A transaction with its context set.
pub type Tx = sqlx::Transaction<'static, Postgres>;

/// A connection inside a [`Tx`] (`&mut *tx`), for helpers that run several
/// statements of the caller's transaction.
pub type Conn = sqlx::PgConnection;

/// The migrations embedded in the binary.
pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Pre-authentication contexts. Each one sees only the tables its flow
/// needs (see `migrations/0002_rls.sql`); none of them sees vaults, items,
/// keys or organization data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Public {
    /// Sign-up, sign-in, the second factor, recovery by code, SSO sign-in
    /// and new-device flows: the credential tables of all accounts, looked
    /// up by email or by token hash.
    Auth,
    /// Instance information for signed-out clients (`/meta`): the instance
    /// settings only.
    Meta,
    /// The share-link viewer: share links only, by ID.
    ShareLink,
    /// The public breach catalogue (global data, no tenant rows).
    BreachCatalog,
}

impl Public {
    fn name(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Meta => "meta",
            Self::ShareLink => "share_link",
            Self::BreachCatalog => "breach_catalog",
        }
    }
}

/// Machine credentials of an organization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrgCredential {
    /// SCIM provisioning (bearer token of the organization).
    Scim,
    /// The events API (SIEM pull with an event token).
    Events,
    /// The organization's single sign-on integration during a signed-out
    /// SSO sign-in (configuration, identities, joining by invitation).
    Sso,
}

impl OrgCredential {
    fn name(self) -> &'static str {
        match self {
            Self::Scim => "scim",
            Self::Events => "org_events",
            Self::Sso => "sso",
        }
    }
}

/// Server-internal work. Background jobs run on the worker pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Job {
    /// Reading and creating the server secrets (at start, and the SSO key).
    Secrets,
    /// Queueing a mail (request handlers and jobs; insert only).
    Outbox,
    /// Queue depths for `/metrics` (numbers only).
    Metrics,
    /// The mail worker: the outbox.
    Mail,
    /// Webhook delivery of organization audit entries.
    Webhooks,
    /// Removing attachment blobs that lost their item.
    Attachments,
    /// Email breach monitoring.
    Breach,
    /// Deleting organization audit entries past their retention.
    AuditRetention,
    /// The shared website icon store from request handlers (`site_icons`
    /// only; no account is named, so the store never learns who asked).
    Icons,
    /// The background refresh of the shared website icon store.
    IconRefresh,
    /// Refreshing the public breach catalogue from Have I Been Pwned.
    BreachCatalog,
    /// Code that embeds the server (`crate::ext`): reads organizations,
    /// their members and invitations, and sets and removes organization
    /// locks (`org_locks`). Nothing else.
    Extensions,
}

impl Job {
    fn name(self) -> &'static str {
        match self {
            Self::Secrets => "secrets",
            Self::Outbox => "outbox",
            Self::Metrics => "metrics",
            Self::Mail => "worker:mail",
            Self::Webhooks => "worker:webhooks",
            Self::Attachments => "worker:attachments",
            Self::Breach => "worker:breach",
            Self::AuditRetention => "worker:audit_retention",
            Self::Icons => "icons",
            Self::IconRefresh => "worker:icons",
            Self::BreachCatalog => "worker:breach_catalog",
            Self::Extensions => "ext",
        }
    }

    fn on_worker_pool(self) -> bool {
        !matches!(
            self,
            Self::Secrets | Self::Outbox | Self::Metrics | Self::Icons | Self::Extensions
        )
    }
}

/// Database URLs (`PASSBOX_DATABASE_URL` and friends).
#[derive(Clone)]
pub struct Urls {
    /// `passbox_app`: request handlers.
    pub app: String,
    /// `passbox_worker`: background jobs. Defaults to `app`.
    pub worker: Option<String>,
    /// Connections per pool.
    pub max_connections: u32,
}

/// The connection pools. Cheap to clone.
#[derive(Clone)]
pub struct Db {
    app: PgPool,
    worker: PgPool,
}

impl Db {
    /// Connects the pools. Does not run migrations (see [`migrate`]).
    pub async fn connect(urls: &Urls) -> anyhow::Result<Self> {
        let app = pool(&urls.app, urls.max_connections)
            .await
            .context("failed to connect to the database (PASSBOX_DATABASE_URL)")?;
        let worker = match &urls.worker {
            Some(url) if url != &urls.app => pool(url, urls.max_connections.clamp(1, 4))
                .await
                .context("failed to connect to the database (PASSBOX_WORKER_DATABASE_URL)")?,
            _ => app.clone(),
        };
        Ok(Self { app, worker })
    }

    /// Uses existing pools (tests).
    pub fn from_pools(app: PgPool, worker: PgPool) -> Self {
        Self { app, worker }
    }

    /// Work for a signed-in account.
    pub async fn as_account(&self, account_id: &str) -> Result<Tx, sqlx::Error> {
        begin(&self.app, account_id, "", "", "").await
    }

    /// Work of an instance admin (the instance administration). Only the
    /// `AdminSession` extractor calls it, after checking the account.
    pub async fn as_admin(&self, account_id: &str) -> Result<Tx, sqlx::Error> {
        begin(&self.app, account_id, "admin", "", "").await
    }

    /// Work before anyone is authenticated.
    pub async fn public(&self, context: Public) -> Result<Tx, sqlx::Error> {
        begin(&self.app, "", context.name(), "", "").await
    }

    /// Work for an organization's machine credential.
    pub async fn as_org(&self, credential: OrgCredential, org_id: &str) -> Result<Tx, sqlx::Error> {
        begin(&self.app, "", credential.name(), org_id, "").await
    }

    /// Server-internal work.
    pub async fn system(&self, job: Job) -> Result<Tx, sqlx::Error> {
        let pool = if job.on_worker_pool() {
            &self.worker
        } else {
            &self.app
        };
        begin(pool, "", "", "", job.name()).await
    }

    /// Whether the database answers and has the migrations this binary
    /// expects. Returns the applied version.
    pub async fn readiness(&self) -> anyhow::Result<i64> {
        let mut conn = self.app.acquire().await?;
        // sqlx creates this table itself, so the query is not checked at
        // compile time.
        let applied: Option<i64> =
            sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations WHERE success")
                .fetch_one(&mut *conn)
                .await
                .context("cannot read the migration version")?;
        let applied = applied.unwrap_or(0);
        let expected = expected_version();
        anyhow::ensure!(
            applied == expected,
            "database is at migration {applied}, this server needs {expected}; run `passbox-server migrate`"
        );
        Ok(applied)
    }

    /// Connection pool numbers for `/metrics`.
    pub fn pool_stats(&self) -> [(&'static str, u32, usize); 2] {
        [
            ("app", self.app.size(), self.app.num_idle()),
            ("worker", self.worker.size(), self.worker.num_idle()),
        ]
    }

    /// Logs a warning if the app role is not subject to row level security
    /// (a superuser, a role with BYPASSRLS, or the owner of the tables
    /// without forced RLS), so operators know the policies do not apply.
    pub async fn warn_unless_rls_enforced(&self) {
        let row = sqlx::query!(
            r#"SELECT current_user::text AS "role!", r.rolsuper OR r.rolbypassrls AS "bypass!",
                      c.relowner = r.oid AND NOT c.relforcerowsecurity AS "owner_unforced!"
               FROM pg_roles r, pg_class c
               WHERE r.rolname = current_user AND c.oid = 'public.accounts'::regclass"#
        )
        .map(|row| (row.role, row.bypass, row.owner_unforced))
        .fetch_one(&self.app)
        .await;
        match row {
            Ok((role, bypass, owner_unforced)) if bypass || owner_unforced => tracing::warn!(
                role,
                "row level security does not apply to the database role of PASSBOX_DATABASE_URL; \
                 use the passbox_app role (see docs/architecture/database-security.md)"
            ),
            Ok(_) => {}
            Err(err) => tracing::warn!(error = %err, "could not check row level security"),
        }
    }
}

/// The highest migration version embedded in the binary.
pub fn expected_version() -> i64 {
    MIGRATOR
        .iter()
        .map(|migration| migration.version)
        .max()
        .unwrap_or(0)
}

/// Applies pending migrations with the owner role
/// (`PASSBOX_MIGRATION_DATABASE_URL`).
pub async fn migrate(url: &str) -> anyhow::Result<()> {
    let pool = pool(url, 1)
        .await
        .context("failed to connect to the database for migrations")?;
    MIGRATOR
        .run(&pool)
        .await
        .context("failed to run database migrations")?;
    pool.close().await;
    Ok(())
}

async fn pool(url: &str, max_connections: u32) -> anyhow::Result<PgPool> {
    let options = PgConnectOptions::from_str(url)
        .context("invalid database URL")?
        .application_name("passbox-server");
    Ok(PgPoolOptions::new()
        .max_connections(max_connections.max(1))
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(options)
        .await?)
}

async fn begin(
    pool: &PgPool,
    account_id: &str,
    context: &str,
    org_id: &str,
    system: &str,
) -> Result<Tx, sqlx::Error> {
    let mut tx = pool.begin().await?;
    // All four are set every time, so a context never mixes with another.
    sqlx::query(
        "SELECT set_config('passbox.account_id', $1, true), set_config('passbox.context', $2, true), \
         set_config('passbox.org_id', $3, true), set_config('passbox.system', $4, true)",
    )
    .bind(account_id)
    .bind(context)
    .bind(org_id)
    .bind(system)
    .execute(&mut *tx)
    .await?;
    Ok(tx)
}

/// Switches a signed-out transaction to the account it just created or
/// whose credentials it just verified (sign-up, sign-in, recovery), so the
/// rest of the transaction runs with that account's rights only.
pub async fn switch_to_account(conn: &mut Conn, account_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "SELECT set_config('passbox.account_id', $1, true), set_config('passbox.context', '', true), \
         set_config('passbox.org_id', '', true), set_config('passbox.system', '', true)",
    )
    .bind(account_id)
    .execute(conn)
    .await?;
    Ok(())
}

/// Current time in Unix milliseconds.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Takes the next value of the global change counter. Call inside the
/// transaction that performs the change; the row lock serializes writers, so
/// readers never miss a change with a lower sequence number.
pub async fn next_seq(conn: &mut Conn) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar!(
        "UPDATE counters SET value = value + 1 WHERE name = 'change_seq' RETURNING value"
    )
    .fetch_one(conn)
    .await
}

/// Returns the current value of the change counter.
pub async fn current_seq(conn: &mut Conn) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar!("SELECT value FROM counters WHERE name = 'change_seq'")
        .fetch_one(conn)
        .await
}

/// Binary data the API carries as unpadded Base64url text and the database
/// stores as `BYTEA`. Encoding fails for text that is not Base64url, so
/// validate input first (`validate::base64`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct B64(pub String);

impl B64 {
    pub fn into_string(self) -> String {
        self.0
    }
}

impl From<B64> for String {
    fn from(value: B64) -> Self {
        value.0
    }
}

/// Binds Base64url text as `BYTEA` without copying the string.
#[derive(Debug, Clone, Copy)]
pub struct B64Ref<'a>(pub &'a str);

/// Shorthand for binding Base64url text to a `BYTEA` parameter.
pub fn b64(text: &str) -> B64Ref<'_> {
    B64Ref(text)
}

impl Type<Postgres> for B64 {
    fn type_info() -> PgTypeInfo {
        <Vec<u8> as Type<Postgres>>::type_info()
    }
}

impl Type<Postgres> for B64Ref<'_> {
    fn type_info() -> PgTypeInfo {
        <Vec<u8> as Type<Postgres>>::type_info()
    }
}

impl Encode<'_, Postgres> for B64Ref<'_> {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        let bytes = encoding::decode(self.0)?;
        buf.extend_from_slice(&bytes);
        Ok(IsNull::No)
    }
}

impl Encode<'_, Postgres> for B64 {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        B64Ref(&self.0).encode_by_ref(buf)
    }
}

impl<'r> Decode<'r, Postgres> for B64 {
    fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let bytes = <&[u8] as Decode<Postgres>>::decode(value)?;
        Ok(Self(encoding::encode(bytes)))
    }
}

impl sqlx::postgres::PgHasArrayType for B64 {
    fn array_type_info() -> PgTypeInfo {
        <Vec<u8> as sqlx::postgres::PgHasArrayType>::array_type_info()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_version_is_the_newest_migration() {
        assert!(expected_version() >= 2);
    }
}
