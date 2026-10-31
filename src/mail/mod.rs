//! Outgoing mail: a durable outbox in the database and a background task
//! that sends it over SMTP, or through the Camelmailer API when
//! `PASSBOX_CAMELMAILER_API_KEY` is set.
//!
//! Other modules call [`Mailer::enqueue`] (or [`Mailer::enqueue_for_account`])
//! and never talk to SMTP themselves. The mail is stored in `mail_outbox` and
//! sent by [`Mailer::spawn_worker`], which retries failures with exponential
//! backoff. Without `PASSBOX_SMTP_URL` the worker writes mails to the log
//! instead (development mode), and the administration shows that mail is not
//! configured.

pub mod layout;
pub mod templates;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use lettre::message::header::ContentType;
use lettre::message::{Attachment, Mailbox, MultiPart, SinglePart};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use passbox_core::id;
use serde::Serialize;
use serde_json::Value;
use tokio::sync::Notify;

pub use self::templates::{Locale, Template};
use crate::db::{Conn, Db, Job, now_ms};

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
/// Longest time one SMTP delivery or API call may take.
const SMTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Mail settings from the server configuration.
#[derive(Clone, Default)]
pub struct MailConfig {
    pub smtp_url: Option<String>,
    pub camelmailer_api_key: Option<String>,
    pub camelmailer_url: Option<String>,
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
    /// The Camelmailer API (`PASSBOX_CAMELMAILER_API_KEY`).
    CamelMailer {
        client: Box<camelmailer_rs::CamelMailer>,
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
    /// `smtps`, `starttls`, `smtp`, `camelmailer` or `log`.
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
        let smtp_url = config.smtp_url.as_deref().filter(|u| !u.trim().is_empty());
        let api_key = config
            .camelmailer_api_key
            .as_deref()
            .map(str::trim)
            .filter(|k| !k.is_empty());
        let transport = match (smtp_url, api_key) {
            (Some(_), Some(_)) => anyhow::bail!(
                "set either PASSBOX_SMTP_URL or PASSBOX_CAMELMAILER_API_KEY, not both"
            ),
            (None, None) => Transport::Log,
            (None, Some(key)) => {
                let base_url = config
                    .camelmailer_url
                    .as_deref()
                    .map(str::trim)
                    .filter(|u| !u.is_empty())
                    .unwrap_or(camelmailer_rs::DEFAULT_BASE_URL);
                if !base_url.starts_with("https://") && !base_url.starts_with("http://") {
                    anyhow::bail!("PASSBOX_CAMELMAILER_URL must start with https:// or http://");
                }
                let client = camelmailer_rs::CamelMailer::builder(key)
                    .base_url(base_url)
                    .timeout(SMTP_TIMEOUT)
                    .build()
                    .map_err(|e| anyhow::anyhow!("invalid Camelmailer settings: {e}"))?;
                let host = base_url
                    .split_once("://")
                    .map_or(base_url, |(_, rest)| rest)
                    .trim_end_matches('/')
                    .to_owned();
                Transport::CamelMailer {
                    client: Box::new(client),
                    host,
                }
            }
            (Some(url), None) => {
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
            None if !matches!(transport, Transport::Log) => anyhow::bail!(
                "PASSBOX_MAIL_FROM is required when PASSBOX_SMTP_URL or PASSBOX_CAMELMAILER_API_KEY is set"
            ),
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

    /// Whether mail is really sent (SMTP or the Camelmailer API).
    pub fn is_configured(&self) -> bool {
        !matches!(self.inner.transport, Transport::Log)
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
        let mut tx = self.inner.db.system(Job::Outbox).await?;
        let id = insert(&mut tx, to, template, locale, &params).await?;
        tx.commit().await?;
        self.inner.wake.notify_one();
        Ok(id)
    }

    /// Queues a mail inside a write transaction, so it is sent only if the
    /// transaction commits. Call [`Mailer::wake`] after committing.
    pub async fn enqueue_in(
        conn: &mut Conn,
        to: &str,
        template: Template,
        locale: Locale,
        params: &Value,
    ) -> anyhow::Result<String> {
        insert(conn, to, template, locale, params).await
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
        // The recipient may be another account than the one the request
        // runs for; the function reveals only the address and language.
        let mut tx = self.inner.db.system(Job::Outbox).await?;
        let row = sqlx::query!(
            r#"SELECT email AS "email!", locale AS "locale!" FROM passbox.mail_recipient($1)
               WHERE email IS NOT NULL"#,
            account_id
        )
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let locale = match Locale::parse(&row.locale) {
            Some(locale) => locale,
            None => {
                crate::instance::load_settings(&mut tx)
                    .await?
                    .default_locale
            }
        };
        if let Some(object) = params.as_object_mut() {
            object
                .entry("email")
                .or_insert_with(|| Value::String(row.email.clone()));
        }
        let id = insert(&mut tx, &row.email, template, locale, &params).await?;
        tx.commit().await?;
        self.inner.wake.notify_one();
        Ok(Some(id))
    }

    /// Wakes the worker, for example after committing [`Mailer::enqueue_in`].
    pub fn wake(&self) {
        self.inner.wake.notify_one();
    }

    /// Delivery status for the administration (in an instance admin's
    /// transaction).
    pub async fn status(&self, conn: &mut Conn) -> anyhow::Result<MailStatus> {
        let counts = sqlx::query!(
            r#"SELECT count(*) FILTER (WHERE status = 'pending') AS "pending!",
                      count(*) FILTER (WHERE status = 'failed') AS "failed!",
                      max(sent_at) FILTER (WHERE status = 'sent') AS last_sent_at
               FROM mail_outbox"#
        )
        .fetch_one(&mut *conn)
        .await?;
        let (pending, failed, last_sent_at) = (counts.pending, counts.failed, counts.last_sent_at);
        let last_error = sqlx::query_scalar!(
            "SELECT last_error FROM mail_outbox WHERE last_error <> '' \
             ORDER BY created_at DESC LIMIT 1"
        )
        .fetch_optional(&mut *conn)
        .await?;
        let (configured, transport, host) = match &self.inner.transport {
            Transport::Log => (false, "log", None),
            Transport::Smtp { security, host, .. } => (true, *security, Some(host.clone())),
            Transport::CamelMailer { host, .. } => (true, "camelmailer", Some(host.clone())),
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
        let mut tx = db.system(Job::Mail).await?;
        let due = sqlx::query_scalar!(
            "SELECT id FROM mail_outbox WHERE status = 'pending' AND next_attempt_at <= $1 \
             AND locked_until <= $1 ORDER BY next_attempt_at, created_at LIMIT $2",
            now,
            BATCH,
        )
        .fetch_all(&mut *tx)
        .await?;
        if due.is_empty() {
            return Ok(0);
        }
        let settings = crate::instance::load_settings(&mut tx).await?;
        tx.commit().await?;
        let mut processed = 0;
        for id in due {
            // Several server processes may share the database: only the one
            // that takes the lease sends the mail.
            let now = now_ms();
            let mut tx = db.system(Job::Mail).await?;
            let claimed = sqlx::query!(
                r#"UPDATE mail_outbox SET locked_until = $1 WHERE id = $2 AND status = 'pending'
                   AND locked_until <= $3
                   RETURNING recipient, template, locale, params, attempts"#,
                now + LEASE_MS,
                id,
                now,
            )
            .fetch_optional(&mut *tx)
            .await?;
            tx.commit().await?;
            let Some(mail) = claimed else {
                continue;
            };
            let result = self
                .deliver(
                    &id,
                    &mail.recipient,
                    &mail.template,
                    &mail.locale,
                    mail.params,
                    &settings.instance_name,
                )
                .await;
            let now = now_ms();
            let mut tx = db.system(Job::Mail).await?;
            match result {
                Ok(()) => {
                    sqlx::query!(
                        "UPDATE mail_outbox SET status = 'sent', params = '{}', attempts = $1, \
                         sent_at = $2, locked_until = 0, last_error = '' WHERE id = $3",
                        mail.attempts + 1,
                        now,
                        id,
                    )
                    .execute(&mut *tx)
                    .await?;
                }
                Err(failure) => {
                    let attempts = mail.attempts + 1;
                    let give_up = failure.permanent || attempts >= MAX_ATTEMPTS;
                    tracing::warn!(mail_id = %id, attempts, give_up, error = %failure.message, "mail delivery failed");
                    sqlx::query!(
                        "UPDATE mail_outbox SET status = $1, attempts = $2, next_attempt_at = $3, \
                         locked_until = 0, last_error = $4 WHERE id = $5",
                        if give_up { "failed" } else { "pending" },
                        attempts,
                        now + backoff_ms(attempts),
                        failure.message.chars().take(500).collect::<String>(),
                        id,
                    )
                    .execute(&mut *tx)
                    .await?;
                }
            }
            tx.commit().await?;
            processed += 1;
        }
        Ok(processed)
    }

    async fn deliver(
        &self,
        id: &str,
        recipient: &str,
        template: &str,
        locale: &str,
        params: Value,
        instance_name: &str,
    ) -> Result<(), Failure> {
        let template = Template::parse(template)
            .ok_or_else(|| Failure::permanent(format!("unknown template {template}")))?;
        let locale = Locale::parse(locale).unwrap_or_default();
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
                    "mail not sent: neither PASSBOX_SMTP_URL nor PASSBOX_CAMELMAILER_API_KEY is set"
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
                    .multipart(multipart(mail.text, mail.html))
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
            Transport::CamelMailer { client, .. } => {
                let to: Mailbox = recipient
                    .parse()
                    .map_err(|e| Failure::permanent(format!("invalid recipient: {e}")))?;
                let mut request = camelmailer_rs::SendEmailRequest::builder()
                    .from(address(&self.inner.from))
                    .to(address(&to))
                    .subject(mail.subject)
                    .text_body(mail.text)
                    .html_body(mail.html)
                    .tag(template.as_str());
                for image in &layout::INLINE_IMAGES {
                    request = request.attachment(camelmailer_rs::Attachment::inline(
                        image.file_name,
                        "image/png",
                        image.content_id,
                        image.bytes,
                    ));
                }
                // The outbox id makes a retry after a lost response replay
                // the first send instead of mailing twice.
                client
                    .emails()
                    .idempotent(id)
                    .send(request.build())
                    .await
                    .map(|_| ())
                    .map_err(|e| Failure {
                        permanent: api_error_is_permanent(&e),
                        message: e.to_string(),
                    })
            }
        }
    }

    /// Deletes old sent and failed mails.
    pub async fn prune(&self) -> anyhow::Result<()> {
        let cutoff = now_ms() - RETENTION_MS;
        let mut tx = self.inner.db.system(Job::Mail).await?;
        sqlx::query!(
            "DELETE FROM mail_outbox WHERE (status = 'sent' AND sent_at < $1) \
             OR (status = 'failed' AND created_at < $1)",
            cutoff,
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
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

async fn insert(
    conn: &mut Conn,
    to: &str,
    template: Template,
    locale: Locale,
    params: &Value,
) -> anyhow::Result<String> {
    let id = id::new_id()?;
    let now = now_ms();
    sqlx::query!(
        "INSERT INTO mail_outbox (id, recipient, template, locale, params, status, attempts, \
         next_attempt_at, locked_until, last_error, created_at, sent_at) \
         VALUES ($1, $2, $3, $4, $5, 'pending', 0, $6, 0, '', $6, 0)",
        id,
        to,
        template.as_str(),
        locale.as_str(),
        params,
        now,
    )
    .execute(conn)
    .await?;
    Ok(id)
}

/// Plain text and HTML alternatives; the HTML part carries the logos it
/// references as inline images (`cid:`), so no remote image is loaded.
fn multipart(text: String, html: String) -> MultiPart {
    let mut related = MultiPart::related().singlepart(SinglePart::html(html));
    for image in &layout::INLINE_IMAGES {
        related = related.singlepart(Attachment::new_inline(image.content_id.to_owned()).body(
            image.bytes.to_vec(),
            ContentType::parse("image/png").expect("valid type"),
        ));
    }
    MultiPart::alternative()
        .singlepart(SinglePart::plain(text))
        .multipart(related)
}

/// A sender or recipient for the Camelmailer API.
fn address(mailbox: &Mailbox) -> camelmailer_rs::Address {
    let email = mailbox.email.to_string();
    match mailbox.name.as_deref() {
        Some(name) if !name.is_empty() => camelmailer_rs::Address::with_name(email, name),
        _ => camelmailer_rs::Address::from(email),
    }
}

/// Whether a failed API call should not be retried: a request the API
/// refuses (4xx) fails the same way again, except for timeouts and rate
/// limits. Network errors and server errors are retried.
fn api_error_is_permanent(error: &camelmailer_rs::Error) -> bool {
    match error.status() {
        Some(408 | 425 | 429) => false,
        Some(status) => (400..500).contains(&status),
        None => matches!(error, camelmailer_rs::Error::Config(_)),
    }
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
