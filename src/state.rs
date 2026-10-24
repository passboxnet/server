use std::sync::Arc;

use anyhow::Context;
use passbox_core::encoding;
use passbox_core::opaque::ServerKeys;
use passbox_core::random;

use crate::db::Db;

/// Shared state of all request handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub opaque: Arc<ServerKeys>,
    /// Key for deriving stable fake login parameters for unknown emails.
    pub prelogin_key: Arc<[u8; 32]>,
}

impl AppState {
    /// Loads the server secrets from the database, creating them on first start.
    pub async fn load(db: Db) -> anyhow::Result<Self> {
        let opaque_bytes = load_or_create_secret(&db, "opaque_server_setup", || {
            Ok(ServerKeys::generate().to_bytes().to_vec())
        })
        .await?;
        let opaque = ServerKeys::from_bytes(&opaque_bytes).context("corrupt OPAQUE server keys")?;

        let prelogin_bytes =
            load_or_create_secret(&db, "prelogin_key", || Ok(random::bytes::<32>()?.to_vec()))
                .await?;
        let prelogin_key: [u8; 32] = prelogin_bytes
            .as_slice()
            .try_into()
            .context("corrupt prelogin key")?;

        Ok(Self {
            db,
            opaque: Arc::new(opaque),
            prelogin_key: Arc::new(prelogin_key),
        })
    }
}

/// Returns the named secret. Concurrent first starts are safe: only one
/// insert wins and everyone reads the stored value.
async fn load_or_create_secret(
    db: &Db,
    name: &str,
    generate: impl FnOnce() -> anyhow::Result<Vec<u8>>,
) -> anyhow::Result<Vec<u8>> {
    let candidate = encoding::encode(&generate()?);
    sqlx::query(
        "INSERT INTO server_secrets (name, value) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING",
    )
    .bind(name)
    .bind(&candidate)
    .execute(db)
    .await?;
    let stored: String = sqlx::query_scalar("SELECT value FROM server_secrets WHERE name = $1")
        .bind(name)
        .fetch_one(db)
        .await?;
    Ok(encoding::decode(&stored)?)
}
