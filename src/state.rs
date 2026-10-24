use std::sync::Arc;

use anyhow::Context;
use passbox_core::aead::SymmetricKey;
use passbox_core::encoding;
use passbox_core::opaque::ServerKeys;
use passbox_core::random;

use crate::db::Db;
use crate::security::RateLimiter;

/// Shared state of all request handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub opaque: Arc<ServerKeys>,
    /// Key for deriving stable fake login parameters for unknown emails.
    pub prelogin_key: Arc<[u8; 32]>,
    /// Encrypts login TOTP secrets at rest (see `api::two_factor`).
    pub two_factor_key: Arc<SymmetricKey>,
    /// Limits for authentication endpoints.
    pub limiter: Arc<RateLimiter>,
    /// Trust `X-Forwarded-For` from a reverse proxy for client IPs.
    pub trust_proxy: bool,
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

        let two_factor_bytes =
            load_or_create_secret(
                &db,
                "two_factor_key",
                || Ok(random::bytes::<32>()?.to_vec()),
            )
            .await?;
        let two_factor_key: [u8; 32] = two_factor_bytes
            .as_slice()
            .try_into()
            .context("corrupt two-factor key")?;

        Ok(Self {
            db,
            opaque: Arc::new(opaque),
            prelogin_key: Arc::new(prelogin_key),
            two_factor_key: Arc::new(SymmetricKey::from_bytes(two_factor_key)),
            limiter: Arc::new(RateLimiter::default()),
            trust_proxy: false,
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
