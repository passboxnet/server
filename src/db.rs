//! Database access. One code path serves SQLite and PostgreSQL through the
//! sqlx `Any` driver. Queries use `$1, $2, ...` placeholders in ascending
//! order, which both backends accept.

use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use sqlx::any::{AnyConnectOptions, AnyPoolOptions};
use sqlx::{AnyPool, Executor};

pub type Db = AnyPool;

/// Begins a transaction that will write. On SQLite it takes the write lock
/// up front (`BEGIN IMMEDIATE`): a deferred transaction that reads first
/// fails with "database is locked" when another writer committed meanwhile,
/// and the busy timeout does not help in that case.
pub async fn begin_write(db: &Db) -> Result<sqlx::Transaction<'static, sqlx::Any>, sqlx::Error> {
    if db
        .connect_options()
        .database_url
        .scheme()
        .starts_with("sqlite")
    {
        db.begin_with("BEGIN IMMEDIATE").await
    } else {
        db.begin().await
    }
}

/// Opens the database and applies pending migrations.
pub async fn connect(url: &str) -> anyhow::Result<Db> {
    sqlx::any::install_default_drivers();
    let is_sqlite = url.starts_with("sqlite:");
    // An in-memory SQLite database exists once per connection, so it must not be pooled.
    let max_connections = if is_sqlite && url.contains(":memory:") {
        1
    } else {
        10
    };
    let options = AnyConnectOptions::from_str(url).context("invalid database URL")?;
    let pool = AnyPoolOptions::new()
        .max_connections(max_connections)
        .after_connect(move |conn, _| {
            Box::pin(async move {
                if is_sqlite {
                    conn.execute("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;")
                        .await?;
                }
                Ok(())
            })
        })
        .connect_with(options)
        .await
        .context("failed to connect to the database")?;
    if is_sqlite && !url.contains(":memory:") {
        pool.execute("PRAGMA journal_mode = WAL;").await?;
    }
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("failed to run database migrations")?;
    Ok(pool)
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
pub async fn next_seq(tx: &mut sqlx::Transaction<'_, sqlx::Any>) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "UPDATE counters SET value = value + 1 WHERE name = 'change_seq' RETURNING value",
    )
    .fetch_one(&mut **tx)
    .await
}

/// Returns the current value of the change counter.
pub async fn current_seq(db: &Db) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT value FROM counters WHERE name = 'change_seq'")
        .fetch_one(db)
        .await
}
