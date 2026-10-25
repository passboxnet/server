//! Test databases (for this crate's and the client's integration tests).
//!
//! `PASSBOX_TEST_DATABASE_URL` points at a PostgreSQL superuser connection.
//! Each [`TestDatabase`] creates a database of its own, provisions the roles
//! (`sql/roles.sql`), migrates it as `passbox_migrator` and connects the
//! server's pools as `passbox_app` and `passbox_worker`, so the tests run
//! with row level security exactly as in production. The database is
//! dropped when the value is dropped.

use std::str::FromStr;
use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use sqlx::{Connection, Executor, PgConnection};

use crate::db::{Db, MIGRATOR};

/// The provisioning script, as operators run it.
pub const ROLES_SQL: &str = include_str!("../sql/roles.sql");

/// The environment variable with the superuser URL.
pub const URL_VAR: &str = "PASSBOX_TEST_DATABASE_URL";

/// A database of its own for one test run.
pub struct TestDatabase {
    name: String,
    admin: PgConnectOptions,
    /// The server's pools (`passbox_app`, `passbox_worker`).
    pub db: Db,
    /// A superuser pool on the database, for tests that inspect or change
    /// rows directly. It bypasses row level security.
    pub owner: PgPool,
    /// Connections as a given role and nothing else, for policy tests.
    roles: PgConnectOptions,
}

impl TestDatabase {
    /// Creates, provisions and migrates a new database. Panics with a hint
    /// when `PASSBOX_TEST_DATABASE_URL` is not set.
    pub async fn create() -> Self {
        let url = std::env::var(URL_VAR).unwrap_or_else(|_| {
            panic!(
                "{URL_VAR} is not set: point it at a PostgreSQL superuser, for example \
                 postgres://postgres:postgres@localhost:5432/postgres (see CONTRIBUTING.md)"
            )
        });
        let admin = PgConnectOptions::from_str(&url).expect("invalid PASSBOX_TEST_DATABASE_URL");
        let now = crate::db::now_ms() / 1000;
        let name = format!(
            "passbox_test_{now}_{}",
            passbox_core::id::new_id().expect("random")
        );
        let mut conn = PgConnection::connect_with(&admin)
            .await
            .expect("connect to PASSBOX_TEST_DATABASE_URL");
        drop_stale(&mut conn, now).await;
        conn.execute(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .await
            .expect("create the test database");
        let on_db = admin.clone().database(&name);
        {
            // Roles are cluster-wide: serialize provisioning between tests.
            conn.execute("SELECT pg_advisory_lock(7262269)")
                .await
                .expect("lock");
            let mut target = PgConnection::connect_with(&on_db)
                .await
                .expect("connect to the test database");
            let provisioned = sqlx::raw_sql(sqlx::AssertSqlSafe(ROLES_SQL))
                .execute(&mut target)
                .await;
            conn.execute("SELECT pg_advisory_unlock(7262269)")
                .await
                .expect("unlock");
            provisioned.expect("run sql/roles.sql");
            target.close().await.ok();
        }
        conn.close().await.ok();

        let migrator = pool_as(&on_db, "passbox_migrator", 1).await;
        MIGRATOR.run(&migrator).await.expect("run the migrations");
        migrator.close().await;

        let app = pool_as(&on_db, "passbox_app", 8).await;
        let worker = pool_as(&on_db, "passbox_worker", 2).await;
        let owner = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(on_db.clone())
            .await
            .expect("connect the owner pool");
        Self {
            name,
            admin,
            db: Db::from_pools(app, worker),
            owner,
            roles: on_db,
        }
    }

    /// A single connection as `role` (for example `passbox_app`), for tests
    /// of the policies with raw SQL.
    pub async fn connect_as(&self, role: &str) -> PgConnection {
        let mut conn = PgConnection::connect_with(&self.roles)
            .await
            .expect("connect to the test database");
        conn.execute(sqlx::AssertSqlSafe(format!("SET ROLE {role}")))
            .await
            .expect("set role");
        conn
    }

    /// The database's name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Drops test databases left behind by test processes that ended without
/// dropping theirs (servers in background threads), once they are a few
/// hours old.
async fn drop_stale(conn: &mut PgConnection, now: i64) {
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT datname::text FROM pg_database WHERE datname LIKE 'passbox\\_test\\_%'",
    )
    .fetch_all(&mut *conn)
    .await
    .unwrap_or_default();
    for name in names {
        let created = name
            .strip_prefix("passbox_test_")
            .and_then(|rest| rest.split('_').next())
            .and_then(|secs| secs.parse::<i64>().ok());
        if created.is_some_and(|created| now - created > 6 * 60 * 60) {
            let _ = conn
                .execute(sqlx::AssertSqlSafe(format!(
                    "DROP DATABASE IF EXISTS {name} WITH (FORCE)"
                )))
                .await;
        }
    }
}

/// Starts a server with a test database of its own on a random port, in a
/// thread that runs until the test process ends, and returns its URL.
/// `configure` adjusts the state before the server starts; it runs inside
/// the server's runtime (it may spawn tasks).
pub fn spawn_server<F>(configure: F) -> String
where
    F: FnOnce(&mut crate::state::AppState, &TestDatabase) + Send + 'static,
{
    // Internal errors (500) show up in the test output.
    let _ = tracing_subscriber::fmt()
        .with_env_filter("passbox_server=error")
        .with_test_writer()
        .try_init();
    let (tx, rx) = std::sync::mpsc::channel::<std::net::SocketAddr>();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async move {
            let database = TestDatabase::create().await;
            let mut state = crate::state::AppState::load(database.db.clone())
                .await
                .expect("load the server state");
            configure(&mut state, &database);
            let app = crate::routes::router(&crate::config::Config::default(), state);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            tx.send(listener.local_addr().expect("address"))
                .expect("report the address");
            axum::serve(listener, app).await.expect("serve");
        });
    });
    format!("http://{}", rx.recv().expect("the server started"))
}

/// A pool whose connections act as `role` (the test superuser switches to
/// it), so no role passwords are needed.
async fn pool_as(options: &PgConnectOptions, role: &'static str, max: u32) -> PgPool {
    PgPoolOptions::new()
        .max_connections(max)
        .acquire_timeout(Duration::from_secs(30))
        .after_connect(move |conn, _| {
            Box::pin(async move {
                conn.execute(sqlx::AssertSqlSafe(format!("SET ROLE {role}")))
                    .await?;
                Ok(())
            })
        })
        .connect_with(options.clone())
        .await
        .unwrap_or_else(|e| panic!("connect as {role}: {e}"))
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let name = self.name.clone();
        let admin = self.admin.clone();
        // Dropping runs outside the test's runtime, which may be shutting
        // down; FORCE ends the pools' connections.
        let handle = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(async move {
                if let Ok(mut conn) = PgConnection::connect_with(&admin).await {
                    let _ = conn
                        .execute(sqlx::AssertSqlSafe(format!(
                            "DROP DATABASE IF EXISTS {name} WITH (FORCE)"
                        )))
                        .await;
                }
            });
        });
        let _ = handle.join();
    }
}
