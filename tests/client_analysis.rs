//! The security report, dismissals, breach checks through the server's
//! proxy and email breach monitoring against an in-process server whose
//! Have I Been Pwned upstream is fake (no network access).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use passbox_client::{
    BreachMode, Client, FieldType, FindingKind, ItemCategory, ItemData, MemoryStore, ReportOptions,
    field,
};
use passbox_server::api::breach::{BreachService, BreachUpstream, HibpBreach, UpstreamError};

struct FakeHibp(Arc<AtomicUsize>);

impl BreachUpstream for FakeHibp {
    fn range(&self, prefix: &str) -> Result<String, UpstreamError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(if prefix == "5BAA6" {
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\r\n0000000000000000000000000000000000A:0"
                .into()
        } else {
            "0000000000000000000000000000000000A:0".into()
        })
    }

    fn breached_account(&self, _email: &str) -> Result<Vec<HibpBreach>, UpstreamError> {
        Ok(vec![HibpBreach {
            name: "Adobe".into(),
            title: "Adobe".into(),
            domain: "adobe.com".into(),
            breach_date: "2013-10-04".into(),
            added_date: "2013-12-04T00:00:00Z".into(),
            pwn_count: 152_445_165,
            data_classes: vec!["Email addresses".into(), "Passwords".into()],
        }])
    }
}

/// Starts a server; returns its URL and a function that reads the last
/// confirmation code mailed to an address.
fn start_server(ranges: Arc<AtomicUsize>) -> (String, impl Fn(&str) -> String) {
    let (ask, questions) = std::sync::mpsc::channel::<(String, std::sync::mpsc::Sender<String>)>();
    let url = passbox_server::testing::spawn_server(move |state, database| {
        state.breach = Arc::new(BreachService::new(true, true, Arc::new(FakeHibp(ranges))));
        // Reads the mailed codes past row level security, as the owner.
        let owner = database.owner.clone();
        tokio::spawn(async move {
            loop {
                let Ok((email, answer)) = questions.try_recv() else {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    continue;
                };
                let (params,): (serde_json::Value,) = sqlx::query_as(
                    "SELECT params FROM mail_outbox WHERE recipient = $1 \
                     AND template = 'breach_monitor_code' ORDER BY created_at DESC LIMIT 1",
                )
                .bind(&email)
                .fetch_one(&owner)
                .await
                .unwrap();
                answer
                    .send(params["code"].as_str().unwrap().to_owned())
                    .unwrap();
            }
        });
    });
    let code = move |email: &str| {
        let (answer, receive) = std::sync::mpsc::channel();
        ask.send((email.to_owned(), answer)).unwrap();
        receive.recv().unwrap()
    };
    (url, code)
}

fn login(title: &str, password: &str, url: &str, username: &str) -> ItemData {
    let mut data = ItemData::new(ItemCategory::Login, title);
    data.set_field(field::USERNAME, "Username", FieldType::Text, username);
    data.set_field(field::PASSWORD, "Password", FieldType::Concealed, password);
    data.set_field(field::URL, "Website", FieldType::Url, url);
    data
}

#[test]
fn report_dismissals_proxy_and_monitoring() {
    let ranges = Arc::new(AtomicUsize::new(0));
    let (url, mailed_code) = start_server(ranges.clone());
    let client = Client::new(&url, Arc::new(MemoryStore::default()));
    client
        .sign_up("analysis@example.com", "correct horse battery staple")
        .unwrap();
    let vault = client.vaults().unwrap()[0].id.clone();
    let leaked = client
        .create_item(
            &vault,
            &login("Adobe", "password", "https://adobe.com", "me@example.com"),
        )
        .unwrap();
    let github = client
        .create_item(
            &vault,
            &login("GitHub", "x9$Lq!2vR#pW7zK@", "https://github.com", "octo"),
        )
        .unwrap();
    let typo = client
        .create_item(
            &vault,
            &login("Fake", "G7#kP2!mQ9$wX4&z", "https://githuh.com", "octo"),
        )
        .unwrap();

    let report = client.security_report(&ReportOptions::default()).unwrap();
    assert!(!report.breach_checked);
    let kinds_of = |report: &passbox_client::SecurityReport, id: &str| -> Vec<FindingKind> {
        report
            .findings
            .iter()
            .filter(|f| f.item_id == id && !f.dismissed)
            .map(|f| f.kind)
            .collect()
    };
    assert!(kinds_of(&report, &leaked).contains(&FindingKind::Weak));
    assert!(kinds_of(&report, &github).contains(&FindingKind::MissingTwoFactor));
    assert!(kinds_of(&report, &typo).contains(&FindingKind::Lookalike));
    let lookalike = client.check_lookalike("githuh.com").unwrap();
    assert!(lookalike.is_none(), "saved domains are not lookalikes");
    let lookalike = client.check_lookalike("www.glthub.com").unwrap().unwrap();
    assert_eq!(lookalike.looks_like, "github.com");

    // Breach check through the server (the server-side fake answers).
    assert_eq!(client.breach_mode(), BreachMode::Auto);
    client.set_breach_mode(BreachMode::Server);
    let breached = client.check_breached_items().unwrap();
    assert_eq!(breached.len(), 1);
    assert_eq!(breached[0].item_id, leaked);
    assert!(ranges.load(Ordering::SeqCst) >= 1);
    let report = client.security_report(&ReportOptions::default()).unwrap();
    assert!(report.breach_checked);
    assert_eq!(report.fix_first[0].item_id, leaked);
    assert_eq!(report.fix_first[0].kinds[0], FindingKind::Breached);

    // Dismissing is stored in the item and survives a second device.
    client
        .dismiss_finding(&github, FindingKind::MissingTwoFactor, true)
        .unwrap();
    let report = client.security_report(&ReportOptions::default()).unwrap();
    assert!(!kinds_of(&report, &github).contains(&FindingKind::MissingTwoFactor));
    let category = report
        .categories
        .iter()
        .find(|c| c.kind == FindingKind::MissingTwoFactor)
        .unwrap();
    assert_eq!(category.dismissed, 1);
    assert_eq!(
        client.item(&github).unwrap().data.extra["securityIgnore"],
        serde_json::json!(["missing_two_factor"])
    );
    client
        .dismiss_finding(&github, FindingKind::MissingTwoFactor, false)
        .unwrap();
    assert!(
        !client
            .item(&github)
            .unwrap()
            .data
            .extra
            .contains_key("securityIgnore")
    );

    // Email monitoring: confirm by code, then the exposure shows up.
    let monitoring = client.email_monitoring().unwrap();
    assert!(monitoring.available);
    assert!(monitoring.emails.is_empty());
    let added = client.add_monitored_email("Me@Example.com").unwrap();
    assert!(!added.verified);
    assert!(client.verify_monitored_email(&added.id, "not-it").is_err());
    let code = mailed_code("me@example.com");
    let verified = client.verify_monitored_email(&added.id, &code).unwrap();
    assert!(verified.verified);
    assert_eq!(verified.breaches[0].name, "Adobe");
    let report = client.security_report(&ReportOptions::default()).unwrap();
    assert!(kinds_of(&report, &leaked).contains(&FindingKind::ExposedEmail));
    client.remove_monitored_email(&added.id).unwrap();
    assert!(client.email_monitoring().unwrap().emails.is_empty());

    // Locking forgets breach results.
    client.lock();
    client.unlock("correct horse battery staple").unwrap();
    assert!(
        !client
            .security_report(&ReportOptions::default())
            .unwrap()
            .breach_checked
    );
}

/// A breach catalogue upstream with one breach published tomorrow (after
/// the test's items were saved).
struct FakeCatalog;

impl passbox_server::api::breach_catalog::CatalogUpstream for FakeCatalog {
    fn fetch(
        &self,
        _etag: Option<&str>,
    ) -> Result<passbox_server::api::breach_catalog::Fetched, String> {
        let tomorrow = passbox_core::analysis::breaches::datetime_string(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64
                + 24 * 60 * 60 * 1000,
        );
        Ok(passbox_server::api::breach_catalog::Fetched::Body {
            body: format!(
                r#"[{{"Name":"Netflix","Title":"Netflix","Domain":"netflix.com","BreachDate":"{date}",
                     "AddedDate":"{tomorrow}","ModifiedDate":"{tomorrow}","PwnCount":5000,
                     "DataClasses":["Email addresses","Passwords"],"IsVerified":true}}]"#,
                date = &tomorrow[..10],
            ),
            etag: None,
        })
    }
}

#[test]
fn breached_websites_from_the_server_catalogue() {
    let url = passbox_server::testing::spawn_server(|state, _| {
        let service = Arc::new(passbox_server::api::breach_catalog::CatalogService::new(
            true,
            Arc::new(FakeCatalog),
        ));
        state.breach_catalog = service;
        let state = state.clone();
        tokio::spawn(async move {
            passbox_server::api::breach_catalog::refresh(&state, true)
                .await
                .unwrap();
        });
    });
    let client = Client::new(&url, Arc::new(MemoryStore::default()));
    client
        .sign_up("catalog@example.com", "correct horse battery staple")
        .unwrap();
    let vault = client.vaults().unwrap()[0].id.clone();
    let netflix = client
        .create_item(
            &vault,
            &login(
                "Netflix",
                "x9$Lq!2vR#pW7zK@",
                "https://www.netflix.com",
                "me",
            ),
        )
        .unwrap();

    // Before the download: the bundled snapshot, nothing about the new breach.
    let report = client.security_report(&ReportOptions::default()).unwrap();
    assert!(report.breach_catalog.bundled);
    let mut status = client.refresh_breach_catalog().unwrap();
    for _ in 0..100 {
        if status.changed {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
        status = client.refresh_breach_catalog().unwrap();
    }
    assert!(
        status.available && status.changed && !status.bundled,
        "{status:?}"
    );
    assert_eq!(status.entries, 1);
    // A second check finds nothing new.
    assert!(!client.refresh_breach_catalog().unwrap().changed);

    let report = client.security_report(&ReportOptions::default()).unwrap();
    assert!(!report.breach_catalog.bundled);
    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == FindingKind::BreachedSite)
        .expect("a breached_site finding");
    assert_eq!(finding.item_id, netflix);
    assert_eq!(finding.breaches, ["Netflix"]);
    assert_eq!(
        report.breached_sites[0].affected,
        std::slice::from_ref(&netflix)
    );

    // The alert is shown once.
    let alerts = client.breach_alerts(&ReportOptions::default()).unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].name, "Netflix");
    client.acknowledge_breach_alerts().unwrap();
    assert!(
        client
            .breach_alerts(&ReportOptions::default())
            .unwrap()
            .is_empty()
    );

    // Dismissable like every other finding.
    client
        .dismiss_finding(&netflix, FindingKind::BreachedSite, true)
        .unwrap();
    let report = client.security_report(&ReportOptions::default()).unwrap();
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::BreachedSite && f.dismissed)
    );
}
