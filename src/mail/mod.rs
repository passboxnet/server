//! Outgoing mail: a durable outbox in the database and a background task
//! that sends it over SMTP.
//!
//! Other modules call [`Mailer::enqueue`] (or [`Mailer::enqueue_for_account`])
//! and never talk to SMTP themselves. The mail is stored in `mail_outbox` and
//! sent by [`Mailer::spawn_worker`], which retries failures with exponential
//! backoff. Without `PASSBOX_SMTP_URL` the worker writes mails to the log
//! instead (development mode), and the administration shows that mail is not
//! configured.

pub mod templates;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use lettre::message::{Mailbox, MultiPart};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use passbox_core::id;
use serde::Serialize;
use serde_json::Value;
use tokio::sync::Notify;

pub use self::templates::{Locale, Template};
use crate::db::{Db, now_ms};

/// Mails per worker round.
const BATCH: i64 = 20;
/// How long a worker owns a mail it picked.
const LEASE_MS: i64 = 2 * 60 * 1000;
/// Attempts before a mail is given up (about 4 hours with the backoff below).
pub const MAX_ATTEMPTS: i64 = 10;
/// First retry delay; doubles with every attempt up to `MAX_BACKOFF_MS`.
const BASE_BACKOFF_MS: i64 = 30 * 1000;
const MAX_BACKOFF_MS: i64 = 60 * 60 * 1000;
/// Sent and failed mails are deleted after this long.
const RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;
/// How often the worker looks for due mails without being woken.
const POLL_INTERVAL: Duration = Duration::from_secs(30);
/// Longest time one SMTP delivery may take.
const SMTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Mail settings from the server configuration.
#[derive(Clone, Default)]
pub struct MailConfig {
    pub smtp_url: Option<String>,
    pub from: Option<String>,
    pub public_url: Option<String>,
}

enum Transport {
    /// No SMTP server configured: mails are logged.
    Log,
    Smtp {
        transport: Box<AsyncSmtpTransport<Tokio1Executor>>,
        /// `smtps`, `starttls` or `smtp` (no TLS, for a local relay).
        security: &'static str,
        host: String,
    },
}

struct Inner {
    db: Db,
    transport: Transport,
    from: Mailbox,
    public_url: Option<String>,
    wake: Notify,
}

/// Queues and sends mail. Cheap to clone.
#[derive(Clone)]
pub struct Mailer {
    inner: Arc<Inner>,
}

/// What the administration shows about mail delivery.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MailStatus {
    /// False when no SMTP server is configured and mails are only logged.
    pub configured: bool,
    /// `smtps`, `starttls`, `smtp` or `log`.
    pub transport: &'static str,
    pub host: Option<String>,
    pub from: String,
    pub public_url: Option<String>,
    pub pending: i64,
    pub failed: i64,
    pub last_sent_at: Option<i64>,
    pub last_error: Option<String>,
}

/// The language a request asks for: an explicit `locale` value, else the
/// `Accept-Language` header.
pub fn request_locale(explicit: Option<&str>, headers: &axum::http::HeaderMap) -> Option<Locale> {
    explicit.and_then(Locale::parse).or_else(|| {
        headers
            .get(axum::http::header::ACCEPT_LANGUAGE)
            .and_then(|value| value.to_str().ok())
            .and_then(Locale::from_accept_language)
    })
}

/// Exponential backoff after `attempts` failed attempts.
pub fn backoff_ms(attempts: i64) -> i64 {
    let exponent = u32::try_from(attempts.saturating_sub(1).clamp(0, 20)).unwrap_or(20);
    BASE_BACKOFF_MS
        .saturating_mul(1_i64 << exponent)
        .min(MAX_BACKOFF_MS)
}

impl Mailer {
    /// A mailer that only logs mails (development mode).
    pub fn log_only(db: Db) -> Self {
        Self::new(db, &MailConfig::default()).expect("the log transport needs no configuration")
    }

    /// Creates the mailer. Fails on an invalid SMTP URL or sender address, so
    /// a misconfiguration stops the server at startup instead of losing mail.
    pub fn new(db: Db, config: &MailConfig) -> anyhow::Result<Self> {
        let transport = match config.smtp_url.as_deref().filter(|u| !u.trim().is_empty()) {
            None => Transport::Log,
            Some(url) => {
                let security = if url.starts_with("smtps://") {
                    "smtps"
                } else if url.contains("tls=required") || url.contains("tls=opportunistic") {
                    "starttls"
                } else {
                    "smtp"
                };
                let host = smtp_host(url).context("PASSBOX_SMTP_URL has no host")?;
                let transport = AsyncSmtpTransport::<Tokio1Executor>::from_url(url)
                    .map_err(|e| anyhow::anyhow!("invalid PASSBOX_SMTP_URL: {e}"))?
                    .timeout(Some(SMTP_TIMEOUT))
                    .build();
                Transport::Smtp {
                    transport: Box::new(transport),
                    security,
                    host,
                }
            }
        };
        let from = match config.from.as_deref().filter(|f| !f.trim().is_empty()) {
            Some(from) => from
                .parse::<Mailbox>()
                .map_err(|e| anyhow::anyhow!("invalid PASSBOX_MAIL_FROM: {e}"))?,
            None if matches!(transport, Transport::Smtp { .. }) => {
                anyhow::bail!("PASSBOX_MAIL_FROM is required when PASSBOX_SMTP_URL is set")
            }
            None => "Passbox <passbox@localhost>"
                .parse()
                .expect("valid default sender"),
        };
        let public_url = match config.public_url.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(url) if url.starts_with("https://") || url.starts_with("http://") => {
                Some(url.trim_end_matches('/').to_owned())
            }
            Some(_) => anyhow::bail!("PASSBOX_PUBLIC_URL must start with https:// or http://"),
        };
        Ok(Self {
            inner: Arc::new(Inner {
                db,
                transport,
                from,
                public_url,
                wake: Notify::new(),
            }),
        })
    }

    /// Whether an SMTP server is configured.
    pub fn is_configured(&self) -> bool {
        matches!(self.inner.transport, Transport::Smtp { .. })
    }

    /// The public URL of the web app without trailing slash, if configured.
    pub fn public_url(&self) -> Option<&str> {
        self.inner.public_url.as_deref()
    }

    /// Queues a mail and wakes the worker. Returns the outbox ID.
    ///
    /// `params` is a JSON object with the template's parameters (see
    /// [`Template`]). The instance name is added when the mail is rendered.
    pub async fn enqueue(
        &self,
        to: &str,
        template: Template,
        locale: Locale,
        params: Value,
    ) -> anyhow::Result<String> {
        let id = insert(&self.inner.db, to, template, locale, &params).await?;
        self.inner.wake.notify_one();
        Ok(id)
    }

    /// Queues a mail inside a write transaction, so it is sent only if the
    /// transaction commits. Call [`Mailer::wake`] after committing.
    pub async fn enqueue_in(
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        to: &str,
        template: Template,
        locale: Locale,
        params: &Value,
    ) -> anyhow::Result<String> {
        insert(&mut **tx, to, template, locale, params).await
    }

    /// Queues a mail to an account in the account's language (or the
    /// instance default). `email` is added to `params`. Returns `None` if
    /// the account does not exist.
    pub async fn enqueue_for_account(
        &self,
        account_id: &str,
        template: Template,
        mut params: Value,
    ) -> anyhow::Result<Option<String>> {
        let row: Option<(String, String)> =
            sqlx::query_as("SELECT email, locale FROM accounts WHERE id = $1")
                .bind(account_id)
                .fetch_optional(&self.inner.db)
                .await?;
        let Some((email, locale)) = row else {
            return Ok(None);
        };
        let locale = match Locale::parse(&locale) {
            Some(locale) => locale,
            None => {
                crate::instance::load_settings(&self.inner.db)
                    .await?
                    .default_locale
            }
        };
        if let Some(object) = params.as_object_mut() {
            object
                .entry("email")
                .or_insert_with(|| Value::String(email.clone()));
        }
        self.enqueue(&email, template, locale, params)
            .await
            .map(Some)
    }

    /// Wakes the worker, for example after committing [`Mailer::enqueue_in`].
    pub fn wake(&self) {
        self.inner.wake.notify_one();
    }

    /// Delivery status for the administration.
    pub async fn status(&self) -> anyhow::Result<MailStatus> {
        let db = &self.inner.db;
        let pending: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM mail_outbox WHERE status = 'pending'")
                .fetch_one(db)
                .await?;
        let failed: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM mail_outbox WHERE status = 'failed'")
                .fetch_one(db)
                .await?;
        let last_sent_at: Option<i64> =
            sqlx::query_scalar("SELECT MAX(sent_at) FROM mail_outbox WHERE status = 'sent'")
                .fetch_one(db)
                .await?;
        let last_error: Option<String> = sqlx::query_scalar(
            "SELECT last_error FROM mail_outbox WHERE last_error <> '' \
             ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_optional(db)
        .await?;
        let (configured, transport, host) = match &self.inner.transport {
            Transport::Log => (false, "log", None),
            Transport::Smtp { security, host, .. } => (true, *security, Some(host.clone())),
        };
        Ok(MailStatus {
            configured,
            transport,
            host,
            from: self.inner.from.to_string(),
            public_url: self.inner.public_url.clone(),
            pending,
            failed,
            last_sent_at,
            last_error,
        })
    }

    /// Sends the mails that are due. Returns how many were processed. The
    /// worker calls this in a loop; tests call it directly.
    pub async fn process_due(&self) -> anyhow::Result<usize> {
        let db = &self.inner.db;
        let now = now_ms();
        let due: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM mail_outbox WHERE status = 'pending' AND next_attempt_at <= $1 \
             AND locked_until <= $2 ORDER BY next_attempt_at, created_at LIMIT $3",
        )
        .bind(now)
        .bind(now)
        .bind(BATCH)
        .fetch_all(db)
        .await?;
        if due.is_empty() {
            return Ok(0);
        }
        let settings = crate::instance::load_settings(db).await?;
        let mut processed = 0;
        for id in due {
            // Several server processes may share the database: only the one
            // that takes the lease sends the mail.
            let now = now_ms();
            let claimed = sqlx::query(
                "UPDATE mail_outbox SET locked_until = $1 WHERE id = $2 AND status = 'pending' \
                 AND locked_until <= $3",
            )
            .bind(now + LEASE_MS)
            .bind(&id)
            .bind(now)
            .execute(db)
            .await?;
            if claimed.rows_affected() == 0 {
                continue;
            }
            let (recipient, template, locale, params, attempts): (
                String,
                String,
                String,
                String,
                i64,
            ) = sqlx::query_as(
                "SELECT recipient, template, locale, params, attempts FROM mail_outbox WHERE id = $1",
            )
            .bind(&id)
            .fetch_one(db)
            .await?;
            let result = self
                .deliver(
                    &recipient,
                    &template,
                    &locale,
                    &params,
                    &settings.instance_name,
                )
                .await;
            let now = now_ms();
            match result {
                Ok(()) => {
                    sqlx::query(
                        "UPDATE mail_outbox SET status = 'sent', params = '{}', attempts = $1, \
                         sent_at = $2, locked_until = 0, last_error = '' WHERE id = $3",
                    )
                    .bind(attempts + 1)
                    .bind(now)
                    .bind(&id)
                    .execute(db)
                    .await?;
                }
                Err(failure) => {
                    let attempts = attempts + 1;
                    let give_up = failure.permanent || attempts >= MAX_ATTEMPTS;
                    tracing::warn!(mail_id = %id, attempts, give_up, error = %failure.message, "mail delivery failed");
                    sqlx::query(
                        "UPDATE mail_outbox SET status = $1, attempts = $2, next_attempt_at = $3, \
                         locked_until = 0, last_error = $4 WHERE id = $5",
                    )
                    .bind(if give_up { "failed" } else { "pending" })
                    .bind(attempts)
                    .bind(now + backoff_ms(attempts))
                    .bind(failure.message.chars().take(500).collect::<String>())
                    .bind(&id)
                    .execute(db)
                    .await?;
                }
            }
            processed += 1;
        }
        Ok(processed)
    }

    async fn deliver(
        &self,
        recipient: &str,
        template: &str,
        locale: &str,
        params: &str,
        instance_name: &str,
    ) -> Result<(), Failure> {
        let template = Template::parse(template)
            .ok_or_else(|| Failure::permanent(format!("unknown template {template}")))?;
        let locale = Locale::parse(locale).unwrap_or_default();
        let params: Value = serde_json::from_str(params)
            .map_err(|e| Failure::permanent(format!("invalid parameters: {e}")))?;
        let mail = templates::render(
            template,
            locale,
            &params,
            &templates::Context {
                instance_name,
                public_url: self.inner.public_url.as_deref(),
            },
        );
        match &self.inner.transport {
            Transport::Log => {
                tracing::info!(
                    to = %recipient,
                    subject = %mail.subject,
                    body = %mail.text,
                    "mail not sent: no SMTP server configured (PASSBOX_SMTP_URL)"
                );
                Ok(())
            }
            Transport::Smtp { transport, .. } => {
                let to: Mailbox = recipient
                    .parse()
                    .map_err(|e| Failure::permanent(format!("invalid recipient: {e}")))?;
                let message = Message::builder()
                    .from(self.inner.from.clone())
                    .to(to)
                    .subject(mail.subject)
                    .multipart(MultiPart::alternative_plain_html(mail.text, mail.html))
                    .map_err(|e| Failure::permanent(format!("could not build mail: {e}")))?;
                transport
                    .send(message)
                    .await
                    .map(|_| ())
                    .map_err(|e| Failure {
                        permanent: e.is_permanent(),
                        message: e.to_string(),
                    })
            }
        }
    }

    /// Deletes old sent and failed mails.
    pub async fn prune(&self) -> anyhow::Result<()> {
        let cutoff = now_ms() - RETENTION_MS;
        sqlx::query(
            "DELETE FROM mail_outbox WHERE (status = 'sent' AND sent_at < $1) \
             OR (status = 'failed' AND created_at < $2)",
        )
        .bind(cutoff)
        .bind(cutoff)
        .execute(&self.inner.db)
        .await?;
        Ok(())
    }

    /// Starts the background task that sends queued mail.
    pub fn spawn_worker(&self) -> tokio::task::JoinHandle<()> {
        let mailer = self.clone();
        tokio::spawn(async move {
            let mut rounds: u64 = 0;
            loop {
                if rounds.is_multiple_of(120)
                    && let Err(err) = mailer.prune().await
                {
                    tracing::warn!(error = ?err, "could not prune the mail outbox");
                }
                rounds = rounds.wrapping_add(1);
                match mailer.process_due().await {
                    // A full batch: more may be waiting.
                    Ok(n) if n as i64 >= BATCH => continue,
                    Ok(_) => {}
                    Err(err) => tracing::warn!(error = ?err, "mail worker error"),
                }
                tokio::select! {
                    () = mailer.inner.wake.notified() => {}
                    () = tokio::time::sleep(POLL_INTERVAL) => {}
                }
            }
        })
    }
}

struct Failure {
    permanent: bool,
    message: String,
}

impl Failure {
    fn permanent(message: String) -> Self {
        Self {
            permanent: true,
            message,
        }
    }
}

async fn insert<'c, E>(
    executor: E,
    to: &str,
    template: Template,
    locale: Locale,
    params: &Value,
) -> anyhow::Result<String>
where
    E: sqlx::Executor<'c, Database = sqlx::Any>,
{
    let id = id::new_id()?;
    let now = now_ms();
    sqlx::query(
        "INSERT INTO mail_outbox (id, recipient, template, locale, params, status, attempts, \
         next_attempt_at, locked_until, last_error, created_at, sent_at) \
         VALUES ($1, $2, $3, $4, $5, 'pending', 0, $6, 0, '', $7, 0)",
    )
    .bind(&id)
    .bind(to)
    .bind(template.as_str())
    .bind(locale.as_str())
    .bind(params.to_string())
    .bind(now)
    .bind(now)
    .execute(executor)
    .await?;
    Ok(id)
}

/// The host of an SMTP URL, without credentials.
fn smtp_host(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?']).next()?;
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    (!host.is_empty()).then(|| host.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_is_capped() {
        assert_eq!(backoff_ms(1), 30_000);
        assert_eq!(backoff_ms(2), 60_000);
        assert_eq!(backoff_ms(3), 120_000);
        assert_eq!(backoff_ms(50), MAX_BACKOFF_MS);
    }

    #[test]
    fn smtp_host_hides_credentials() {
        assert_eq!(
            smtp_host("smtps://user:secret@mail.example.com:465").as_deref(),
            Some("mail.example.com:465")
        );
        assert_eq!(
            smtp_host("smtp://localhost:25?tls=required").as_deref(),
            Some("localhost:25")
        );
    }
}
