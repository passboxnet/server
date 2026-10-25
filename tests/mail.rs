//! The mail outbox worker against a tiny local SMTP server.

use std::sync::{Arc, Mutex};

use passbox_server::mail::{Locale, MailConfig, Mailer, Template};
use passbox_server::testing::TestDatabase;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// How the fake server answers `RCPT TO`.
#[derive(Clone, Copy)]
enum Rcpt {
    Accept,
    /// 451: try again later.
    Temporary,
    /// 550: mailbox unavailable.
    Permanent,
}

/// Accepts SMTP connections on a random local port and records the mail
/// data it receives.
async fn smtp_sink(rcpt: Rcpt) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(Mutex::new(Vec::new()));
    let store = received.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let store = store.clone();
            tokio::spawn(async move {
                let (read, mut write) = stream.into_split();
                let mut lines = BufReader::new(read).lines();
                write.write_all(b"220 sink ESMTP\r\n").await.unwrap();
                let mut data: Option<String> = None;
                while let Ok(Some(line)) = lines.next_line().await {
                    if let Some(body) = data.as_mut() {
                        if line == "." {
                            store.lock().unwrap().push(data.take().unwrap_or_default());
                            write.write_all(b"250 queued\r\n").await.unwrap();
                        } else {
                            body.push_str(&line);
                            body.push('\n');
                        }
                        continue;
                    }
                    let command = line.to_ascii_uppercase();
                    let reply: &[u8] = if command.starts_with("EHLO") {
                        b"250-sink\r\n250 8BITMIME\r\n"
                    } else if command.starts_with("HELO") || command.starts_with("MAIL FROM") {
                        b"250 ok\r\n"
                    } else if command.starts_with("RCPT TO") {
                        match rcpt {
                            Rcpt::Accept => b"250 ok\r\n",
                            Rcpt::Temporary => b"451 try again later\r\n",
                            Rcpt::Permanent => b"550 no such mailbox\r\n",
                        }
                    } else if command.starts_with("DATA") {
                        data = Some(String::new());
                        b"354 go ahead\r\n"
                    } else if command.starts_with("QUIT") {
                        write.write_all(b"221 bye\r\n").await.ok();
                        return;
                    } else {
                        b"250 ok\r\n"
                    };
                    if write.write_all(reply).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (port, received)
}

async fn mailer(port: u16) -> (Mailer, TestDatabase) {
    let db = TestDatabase::create().await;
    let mailer = Mailer::new(
        db.db.clone(),
        &MailConfig {
            smtp_url: Some(format!("smtp://127.0.0.1:{port}")),
            from: Some("Passbox <passbox@example.com>".to_owned()),
            public_url: Some("https://vault.example.com/".to_owned()),
        },
    )
    .unwrap();
    (mailer, db)
}

async fn outbox_row(db: &TestDatabase, id: &str) -> (String, i64, String, String) {
    sqlx::query_as(
        "SELECT status, attempts, last_error, params::text FROM mail_outbox WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&db.owner)
    .await
    .unwrap()
}

/// The delivery status as the instance administration sees it.
async fn delivery_status(mailer: &Mailer, db: &TestDatabase) -> passbox_server::mail::MailStatus {
    let admin = passbox_core::id::new_id().unwrap();
    let mut tx = db.db.as_admin(&admin).await.unwrap();
    mailer.status(&mut tx).await.unwrap()
}

#[tokio::test]
async fn outbox_worker_delivers_over_smtp() {
    let (port, received) = smtp_sink(Rcpt::Accept).await;
    let (mailer, db) = mailer(port).await;
    assert!(mailer.is_configured());
    assert_eq!(mailer.public_url(), Some("https://vault.example.com"));

    let id = mailer
        .enqueue(
            "ada@example.com",
            Template::Test,
            Locale::De,
            json!({ "requestedBy": "admin@example.com" }),
        )
        .await
        .unwrap();
    // The background worker picks it up after being woken.
    let worker = mailer.spawn_worker();
    for _ in 0..100 {
        if !received.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    worker.abort();
    let mails = received.lock().unwrap().clone();
    assert_eq!(mails.len(), 1, "{mails:?}");
    let mail = &mails[0];
    assert!(mail.contains("To: ada@example.com"), "{mail}");
    assert!(
        mail.contains("From: Passbox <passbox@example.com>"),
        "{mail}"
    );
    assert!(mail.contains("multipart/alternative"), "{mail}");
    assert!(mail.contains("text/html"), "{mail}");
    // The logos travel inline with the HTML part instead of being loaded.
    assert!(mail.contains("multipart/related"), "{mail}");
    assert!(mail.contains("Content-ID: <logo-light@passbox>"), "{mail}");
    assert!(mail.contains("Content-ID: <logo-dark@passbox>"), "{mail}");

    // Wait until the worker has recorded the delivery.
    let mut status = String::new();
    for _ in 0..100 {
        status = outbox_row(&db, &id).await.0;
        if status == "sent" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(status, "sent");
    let (_, attempts, _, params) = outbox_row(&db, &id).await;
    assert_eq!(attempts, 1);
    assert_eq!(params, "{}");
    let status = delivery_status(&mailer, &db).await;
    assert!(status.configured);
    assert_eq!(status.transport, "smtp");
    assert_eq!(status.host.as_deref(), Some(&*format!("127.0.0.1:{port}")));
    assert_eq!(status.pending, 0);
}

#[tokio::test]
async fn temporary_failures_are_retried_with_backoff() {
    let (port, received) = smtp_sink(Rcpt::Temporary).await;
    let (mailer, db) = mailer(port).await;
    let id = mailer
        .enqueue("ada@example.com", Template::Test, Locale::En, json!({}))
        .await
        .unwrap();
    assert_eq!(mailer.process_due().await.unwrap(), 1);
    let (status, attempts, error, _) = outbox_row(&db, &id).await;
    assert_eq!((status.as_str(), attempts), ("pending", 1));
    assert!(error.contains("451"), "{error}");
    let next: i64 = sqlx::query_scalar("SELECT next_attempt_at FROM mail_outbox WHERE id = $1")
        .bind(&id)
        .fetch_one(&db.owner)
        .await
        .unwrap();
    assert!(next > passbox_server::db::now_ms() + 20_000);
    // Not due yet.
    assert_eq!(mailer.process_due().await.unwrap(), 0);
    assert!(received.lock().unwrap().is_empty());

    // After the last attempt the mail is given up.
    sqlx::query("UPDATE mail_outbox SET next_attempt_at = 0, attempts = $1 WHERE id = $2")
        .bind(passbox_server::mail::MAX_ATTEMPTS - 1)
        .bind(&id)
        .execute(&db.owner)
        .await
        .unwrap();
    assert_eq!(mailer.process_due().await.unwrap(), 1);
    assert_eq!(outbox_row(&db, &id).await.0, "failed");
    let status = delivery_status(&mailer, &db).await;
    assert_eq!(status.failed, 1);
    assert!(status.last_error.unwrap().contains("451"));
}

#[tokio::test]
async fn permanent_failures_are_not_retried() {
    let (port, _) = smtp_sink(Rcpt::Permanent).await;
    let (mailer, db) = mailer(port).await;
    let id = mailer
        .enqueue("nobody@example.com", Template::Test, Locale::En, json!({}))
        .await
        .unwrap();
    assert_eq!(mailer.process_due().await.unwrap(), 1);
    let (status, attempts, error, _) = outbox_row(&db, &id).await;
    assert_eq!((status.as_str(), attempts), ("failed", 1));
    assert!(error.contains("550"), "{error}");
}

#[tokio::test]
async fn invalid_configuration_is_refused() {
    let database = TestDatabase::create().await;
    let db = database.db.clone();
    let config = |smtp: &str, from: Option<&str>, public: Option<&str>| MailConfig {
        smtp_url: Some(smtp.to_owned()),
        from: from.map(str::to_owned),
        public_url: public.map(str::to_owned),
    };
    // SMTP without a sender.
    assert!(Mailer::new(db.clone(), &config("smtp://localhost", None, None)).is_err());
    assert!(
        Mailer::new(
            db.clone(),
            &config("ftp://localhost", Some("a@example.com"), None)
        )
        .is_err()
    );
    assert!(
        Mailer::new(
            db.clone(),
            &config("smtp://localhost", Some("not a mailbox"), None)
        )
        .is_err()
    );
    assert!(
        Mailer::new(
            db.clone(),
            &config(
                "smtps://user:pass@mail.example.com",
                Some("a@example.com"),
                Some("vault.example.com")
            )
        )
        .is_err()
    );
    let mailer = Mailer::new(
        db.clone(),
        &config(
            "smtp://user:pass@mail.example.com:587?tls=required",
            Some("a@example.com"),
            None,
        ),
    )
    .unwrap();
    let status = delivery_status(&mailer, &database).await;
    assert_eq!(status.transport, "starttls");
    assert_eq!(status.host.as_deref(), Some("mail.example.com:587"));
}
