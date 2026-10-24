//! Version history, website icons, breach checks, usage, item health and
//! bulk changes against an in-process server (icons from a fake fetcher, no
//! network access).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use passbox_client::{
    BreachRange, Client, FieldType, ItemCategory, ItemData, ItemProblem, MemoryStore, Store,
    UsageKind, field,
};
use passbox_server::api::icons::{Icon, IconFetcher, IconService};
use passbox_server::config::Config;
use passbox_server::state::AppState;

struct FakeIcons(Arc<AtomicUsize>);

impl IconFetcher for FakeIcons {
    fn fetch(&self, domain: &str) -> Option<Icon> {
        self.0.fetch_add(1, Ordering::SeqCst);
        (domain == "github.com").then(|| Icon {
            content_type: "image/png",
            bytes: b"\x89PNG\r\n\x1a\ngithub".to_vec(),
        })
    }
}

fn start_server(fetches: Arc<AtomicUsize>) -> String {
    let (tx, rx) = std::sync::mpsc::channel::<SocketAddr>();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let db = passbox_server::db::connect("sqlite::memory:")
                .await
                .unwrap();
            let mut state = AppState::load(db).await.unwrap();
            state.icons = Arc::new(IconService::new(true, Arc::new(FakeIcons(fetches))));
            let app = passbox_server::routes::router(&Config::default(), state);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send(listener.local_addr().unwrap()).unwrap();
            axum::serve(listener, app).await.unwrap();
        });
    });
    format!("http://{}", rx.recv().unwrap())
}

const PASSWORD: &str = "correct horse battery staple";

fn login(title: &str, password: &str, url: &str) -> ItemData {
    let mut data = ItemData::new(ItemCategory::Login, title);
    data.set_field(field::PASSWORD, "Password", FieldType::Concealed, password);
    data.set_field(field::URL, "Website", FieldType::Url, url);
    data
}

/// Answers range queries like Have I Been Pwned: "password" is breached.
struct FakePwned(Arc<AtomicUsize>);

impl BreachRange for FakePwned {
    fn range(&self, prefix: &str) -> passbox_client::Result<String> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(if prefix == "5BAA6" {
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\r\n0000000000000000000000000000000000A:0"
                .into()
        } else {
            "0000000000000000000000000000000000A:0".into()
        })
    }
}

struct Offline;

impl BreachRange for Offline {
    fn range(&self, _: &str) -> passbox_client::Result<String> {
        Err(passbox_client::Error::Network("offline".into()))
    }
}

#[test]
fn history_icons_breaches_usage_health_and_bulk() {
    let fetches = Arc::new(AtomicUsize::new(0));
    let server = start_server(fetches.clone());
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let client = Client::new(&server, store.clone());
    let email = format!("{}@example.com", passbox_core::id::new_id().unwrap());
    client.sign_up(&email, PASSWORD).unwrap();
    let vault = client.vaults().unwrap().remove(0);

    // Creation time and version history.
    let id = client
        .create_item(
            &vault.id,
            &login("GitHub", "password", "https://github.com"),
        )
        .unwrap();
    let created_at = client.item(&id).unwrap().created_at;
    assert!(created_at > 0);
    assert!(client.item_history(&id).unwrap().is_empty());
    let mut data = client.item(&id).unwrap().data;
    data.title = "GitHub (work)".into();
    client.update_item(&id, &data).unwrap();
    data.set_field(
        field::PASSWORD,
        "Password",
        FieldType::Concealed,
        "x9$Lq!2vR#pW7zK@",
    );
    client.update_item(&id, &data).unwrap();
    let item = client.item(&id).unwrap();
    assert_eq!(item.created_at, created_at);
    let history = client.item_history(&id).unwrap();
    let titles: Vec<&str> = history
        .iter()
        .map(|v| v.data.as_ref().unwrap().title.as_str())
        .collect();
    assert_eq!(titles, ["GitHub (work)", "GitHub"]);
    assert_eq!(history[0].revision, 2);
    assert!(history[0].updated_by.is_some());
    // Restoring a version = saving its data again.
    client
        .update_item(&id, history[1].data.as_ref().unwrap())
        .unwrap();
    let restored = client.item(&id).unwrap();
    assert_eq!(restored.data.title, "GitHub");
    assert_eq!(restored.data.field(field::PASSWORD), Some("password"));
    assert_eq!(
        restored.data.password_history()[0].value,
        "x9$Lq!2vR#pW7zK@"
    );
    assert_eq!(client.item_history(&id).unwrap().len(), 3);

    // Website icons through the server, cached in the store.
    let icon = client.icon("GitHub.com").unwrap().unwrap();
    assert!(icon.starts_with(b"\x89PNG"));
    assert_eq!(client.icon("github.com").unwrap(), Some(icon));
    assert!(store.get("cache_icon_github_com").unwrap().is_some());
    assert_eq!(client.icon("unknown.example").unwrap(), None);
    assert_eq!(client.icon("unknown.example").unwrap(), None);
    assert_eq!(client.icon("not a domain").unwrap(), None);
    assert_eq!(fetches.load(Ordering::SeqCst), 2);

    // Breach checks with k-anonymity, deduplicated and cached.
    let calls = Arc::new(AtomicUsize::new(0));
    client.set_breach_range(Box::new(FakePwned(calls.clone())));
    assert_eq!(client.breach_check("password").unwrap(), 9_659_365);
    assert_eq!(client.breach_check("password").unwrap(), 9_659_365);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let reused = client
        .create_item(&vault.id, &login("Mail", "password", "http://mail.example"))
        .unwrap();
    let strong = client
        .create_item(
            &vault.id,
            &login("Bank", "G7#kP2!mQ9$wX4&z", "https://bank.example"),
        )
        .unwrap();
    let breached = client.check_breached_items().unwrap();
    let mut breached_ids: Vec<&str> = breached.iter().map(|b| b.item_id.as_str()).collect();
    breached_ids.sort_unstable();
    let mut expected = vec![id.as_str(), reused.as_str()];
    expected.sort_unstable();
    assert_eq!(breached_ids, expected);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "one request per new prefix"
    );

    // Item health ("Sicherheits-Check").
    let health = client.item_health(&reused).unwrap();
    assert_eq!(
        health.problems,
        [
            ItemProblem::Weak,
            ItemProblem::Reused,
            ItemProblem::InsecureUrl,
            ItemProblem::MissingTotp,
            ItemProblem::Breached,
        ]
    );
    assert_eq!(health.reused_with, std::slice::from_ref(&id));
    assert_eq!(health.breach_count, Some(9_659_365));
    let health = client.item_health(&strong).unwrap();
    assert_eq!(health.problems, [ItemProblem::MissingTotp]);
    assert_eq!(health.breach_count, Some(0));
    assert!(health.strength.unwrap() >= 3);

    // Usage stays on the device, encrypted.
    assert_eq!(client.item_usage(&id).unwrap(), None);
    client.record_item_use(&id, UsageKind::Copy).unwrap();
    let usage = client.record_item_use(&id, UsageKind::Autofill).unwrap();
    assert_eq!(usage.use_count, 2);
    assert!(usage.last_autofilled_at > 0 && usage.last_used_at >= usage.last_autofilled_at);
    assert_eq!(client.item_usage(&id).unwrap(), Some(usage));
    assert_eq!(client.item_usages().unwrap().len(), 1);
    let raw = store.get("cache_usage").unwrap().unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains(&id));

    // Bulk changes: one failure does not stop the others.
    let missing = passbox_core::id::new_id().unwrap();
    let failures = client
        .set_favorite(&[id.clone(), strong.clone(), missing.clone()], true)
        .unwrap();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].item_id, missing);
    assert!(client.item(&id).unwrap().data.favorite);
    assert!(client.item(&strong).unwrap().data.favorite);
    let failures = client
        .trash_items(&[reused.clone(), strong.clone(), strong.clone()])
        .unwrap();
    assert!(failures.is_empty());
    assert_eq!(client.trashed_items().unwrap().len(), 2);
    assert_eq!(client.items().unwrap().len(), 1);

    // Locking forgets breach results; offline checks fail clearly.
    client.lock();
    client.unlock(PASSWORD).unwrap();
    assert_eq!(client.item_health(&id).unwrap().breach_count, None);
    assert_eq!(client.item_usage(&id).unwrap().unwrap().use_count, 2);
    client.set_breach_range(Box::new(Offline));
    assert!(matches!(
        client.breach_check("password"),
        Err(passbox_client::Error::Network(_))
    ));
    // Signing out removes the usage data.
    client.sign_out().unwrap();
    assert!(store.get("cache_usage").unwrap().is_none());
}
