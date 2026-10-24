//! The Rust client against a real, in-process Passbox server.

use std::net::SocketAddr;
use std::sync::Arc;

use passbox_client::{
    Client, Connectivity, Error, FieldType, FileStore, ItemCategory, ItemData, MemoryStore, Status,
    Store, field,
};
use passbox_server::config::Config;
use passbox_server::state::AppState;

/// Starts a server on a random port and returns its URL. The server runs
/// until the test process exits.
fn start_server() -> String {
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
            let state = AppState::load(db).await.unwrap();
            let app = passbox_server::routes::router(&Config::default(), state);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send(listener.local_addr().unwrap()).unwrap();
            axum::serve(listener, app).await.unwrap();
        });
    });
    format!("http://{}", rx.recv().unwrap())
}

fn email() -> String {
    format!("{}@example.com", passbox_core::id::new_id().unwrap())
}

const PASSWORD: &str = "correct horse battery staple";

fn login_item(title: &str, password: &str) -> ItemData {
    let mut data = ItemData::new(ItemCategory::Login, title);
    data.set_field(field::USERNAME, "Username", FieldType::Text, "octocat");
    data.set_field(field::PASSWORD, "Password", FieldType::Concealed, password);
    data
}

#[test]
fn full_lifecycle_with_two_devices_and_offline_unlock() {
    let server = start_server();
    let email = email();

    // Laptop: sign up and add an item.
    let laptop_store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let laptop = Client::new(&server, laptop_store.clone());
    assert_eq!(laptop.status().unwrap(), Status::SignedOut);
    let secret_key = laptop.sign_up(&email, PASSWORD).unwrap();
    assert_eq!(laptop.status().unwrap(), Status::Unlocked);
    let vault = laptop.vaults().unwrap().remove(0);
    assert_eq!(vault.name, "Private");
    let item_id = laptop
        .create_item(&vault.id, &login_item("GitHub", "hunter2"))
        .unwrap();

    // Phone: sign in with the Secret Key (case and dashes do not matter).
    let phone_dir = tempfile::tempdir().unwrap();
    let phone_store: Arc<dyn Store> = Arc::new(FileStore::new(phone_dir.path()).unwrap());
    let phone = Client::new(&server, phone_store.clone());
    phone
        .sign_in(
            &email.to_uppercase(),
            PASSWORD,
            &secret_key.to_lowercase().replace('-', " "),
        )
        .unwrap();
    assert_eq!(
        phone.item(&item_id).unwrap().data.field(field::PASSWORD),
        Some("hunter2")
    );

    // Concurrent edits: the second writer gets a conflict and the latest data.
    let mut edited = laptop.item(&item_id).unwrap().data;
    edited.title = "GitHub (work)".into();
    laptop.update_item(&item_id, &edited).unwrap();
    let mut stale = phone.item(&item_id).unwrap().data;
    stale.title = "GitHub (phone)".into();
    assert!(matches!(
        phone.update_item(&item_id, &stale),
        Err(Error::Conflict)
    ));
    assert_eq!(phone.item(&item_id).unwrap().data.title, "GitHub (work)");

    // Vaults sync both ways.
    let work = phone.create_vault("Work").unwrap();
    laptop.sync().unwrap();
    laptop.rename_vault(&work, "Office").unwrap();
    phone.sync().unwrap();
    let names: Vec<String> = phone
        .vaults()
        .unwrap()
        .into_iter()
        .map(|v| v.name)
        .collect();
    assert_eq!(names, ["Office", "Private"]);

    // Lock, wrong password, unlock online.
    phone.lock();
    assert_eq!(phone.status().unwrap(), Status::Locked);
    assert!(matches!(phone.items(), Err(Error::Locked)));
    assert!(matches!(
        phone.unlock("wrong"),
        Err(Error::InvalidCredentials)
    ));
    assert_eq!(phone.unlock(PASSWORD).unwrap(), Connectivity::Online);

    // Biometric-style unlock with the exported key, also without Argon2.
    let unlock_key = phone.unlock_key().unwrap();
    phone.lock();
    assert!(matches!(phone.unlock_key(), Err(Error::Locked)));
    assert_eq!(
        phone.unlock_with_key(&unlock_key).unwrap(),
        Connectivity::Online
    );
    let mut tampered = unlock_key.to_vec();
    tampered[5] ^= 1;
    phone.lock();
    assert!(matches!(
        phone.unlock_with_key(&tampered),
        Err(Error::InvalidCredentials)
    ));
    assert!(matches!(
        phone.unlock_with_key(&[1, 2, 3]),
        Err(Error::InvalidCredentials)
    ));

    // Offline: a client pointing at an unreachable server unlocks from the cache.
    phone.lock();
    let offline = Client::new("http://127.0.0.1:9", phone_store.clone());
    assert_eq!(offline.unlock(PASSWORD).unwrap(), Connectivity::Offline);
    assert!(!offline.is_online());
    assert_eq!(offline.item(&item_id).unwrap().data.title, "GitHub (work)");
    assert!(matches!(
        offline.create_item(&work, &login_item("x", "y")),
        Err(Error::Offline)
    ));
    assert!(matches!(offline.sync(), Err(Error::Offline)));
    offline.lock();
    assert!(matches!(
        offline.unlock("wrong"),
        Err(Error::InvalidCredentials)
    ));

    // Delete propagates; sign out removes everything from the device.
    laptop.delete_item(&item_id).unwrap();
    let device_token = phone_store.get("device_token").unwrap().unwrap();
    phone.unlock(PASSWORD).unwrap();
    // Every login rotates the device token.
    assert_ne!(
        phone_store.get("device_token").unwrap().unwrap(),
        device_token
    );
    assert!(matches!(phone.item(&item_id), Err(Error::NotFound(_))));
    assert!(phone_store.get("device_token").unwrap().is_some());
    phone.sign_out().unwrap();
    assert_eq!(phone.status().unwrap(), Status::SignedOut);
    assert!(phone_store.get("cache").unwrap().is_none());
    assert!(phone_store.get("device_token").unwrap().is_none());
}

#[test]
fn wrong_secret_key_and_unknown_email_are_rejected() {
    let server = start_server();
    let email = email();
    let client = Client::new(&server, Arc::new(MemoryStore::new()));
    client.sign_up(&email, PASSWORD).unwrap();

    let other = Client::new(&server, Arc::new(MemoryStore::new()));
    let random_key = passbox_core::secret_key::SecretKey::generate()
        .unwrap()
        .to_display_string();
    assert!(matches!(
        other.sign_in(&email, PASSWORD, &random_key),
        Err(Error::InvalidCredentials)
    ));
    assert!(matches!(
        other.sign_in(&email, PASSWORD, "garbage"),
        Err(Error::InvalidCredentials)
    ));
    assert!(matches!(
        other.sign_in("nobody@example.com", PASSWORD, &random_key),
        Err(Error::InvalidCredentials)
    ));
    assert_eq!(other.status().unwrap(), Status::SignedOut);
}

#[test]
fn watchtower_on_synced_items() {
    let server = start_server();
    let client = Client::new(&server, Arc::new(MemoryStore::new()));
    client.sign_up(&email(), PASSWORD).unwrap();
    let vault = client.vaults().unwrap().remove(0).id;
    client
        .create_item(&vault, &login_item("A", "summer2024"))
        .unwrap();
    client
        .create_item(&vault, &login_item("B", "summer2024"))
        .unwrap();
    let health = client.health().unwrap();
    assert_eq!(health.analyzed, 2);
    assert_eq!(health.weak.len(), 2);
    assert_eq!(health.reused.len(), 1);
}

#[test]
fn devices_activity_and_master_password_change() {
    let server = start_server();
    let email = email();
    let laptop = Client::new(&server, Arc::new(MemoryStore::new()));
    laptop.set_device("Work laptop", "desktop");
    let secret_key = laptop.sign_up(&email, PASSWORD).unwrap();

    let phone_store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let phone = Client::new(&server, phone_store.clone());
    phone.set_device("Anna's phone", "android");
    phone.sign_in(&email, PASSWORD, &secret_key).unwrap();

    let sessions = laptop.sessions().unwrap();
    let current = sessions.iter().find(|s| s.current).unwrap();
    assert_eq!(
        (current.device_name.as_str(), current.client_kind.as_str()),
        ("Work laptop", "desktop")
    );
    let phone_session = sessions
        .iter()
        .find(|s| s.device_name == "Anna's phone")
        .unwrap();
    assert_eq!(phone_session.client_kind, "android");

    // A revoked device locks on its next request.
    laptop.revoke_session(&phone_session.id).unwrap();
    assert!(matches!(phone.sync(), Err(Error::Locked)));
    assert_eq!(phone.status().unwrap(), Status::Locked);
    let kinds: Vec<String> = laptop
        .activity(50)
        .unwrap()
        .into_iter()
        .map(|e| e.kind)
        .collect();
    assert!(kinds.contains(&"session_revoked".to_owned()));
    assert!(kinds.contains(&"login".to_owned()));

    // Changing the master password keeps the data and signs out the phone.
    let vault = laptop.vaults().unwrap().remove(0).id;
    let item = laptop
        .create_item(&vault, &login_item("GitHub", "s3cret"))
        .unwrap();
    assert!(matches!(
        laptop.change_master_password("wrong", "new password 123"),
        Err(Error::InvalidCredentials)
    ));
    phone.unlock(PASSWORD).unwrap();
    laptop
        .change_master_password(PASSWORD, "new password 123")
        .unwrap();
    assert!(matches!(laptop.unlock_key(), Ok(key) if key.len() == 65));
    // The Emergency Kit can be shown again with the current password only.
    assert_eq!(
        laptop.reveal_secret_key("new password 123").unwrap(),
        secret_key
    );
    assert!(matches!(
        laptop.reveal_secret_key(PASSWORD),
        Err(Error::InvalidCredentials)
    ));
    assert!(matches!(phone.sync(), Err(Error::Locked)));
    assert!(matches!(
        phone.unlock(PASSWORD),
        Err(Error::InvalidCredentials)
    ));

    laptop.lock();
    assert!(matches!(
        laptop.unlock(PASSWORD),
        Err(Error::InvalidCredentials)
    ));
    laptop.unlock("new password 123").unwrap();
    assert_eq!(laptop.item(&item).unwrap().data.title, "GitHub");
    assert!(
        laptop
            .activity(50)
            .unwrap()
            .iter()
            .any(|e| e.kind == "password_changed")
    );
}

#[test]
fn trash_and_password_history() {
    let server = start_server();
    let client = Client::new(&server, Arc::new(MemoryStore::new()));
    client.sign_up(&email(), PASSWORD).unwrap();
    let vault = client.vaults().unwrap().remove(0).id;
    let id = client
        .create_item(&vault, &login_item("Bank", "first"))
        .unwrap();

    // Changing the password records the old one; other edits do not.
    let mut data = client.item(&id).unwrap().data;
    data.set_field(field::PASSWORD, "Password", FieldType::Concealed, "second");
    client.update_item(&id, &data).unwrap();
    let mut data = client.item(&id).unwrap().data;
    data.title = "My bank".into();
    // A stale or forged history from the caller is ignored.
    data.set_password_history(&[]);
    client.update_item(&id, &data).unwrap();
    let history = client.item(&id).unwrap().data.password_history();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].value, "first");
    assert!(history[0].replaced_at > 0);

    // Trash hides the item from items() and Watchtower; restore brings it back.
    client.trash_item(&id).unwrap();
    assert!(client.items().unwrap().is_empty());
    assert_eq!(client.trashed_items().unwrap()[0].id, id);
    assert_eq!(client.health().unwrap().analyzed, 0);
    assert_eq!(client.purge_trash(false).unwrap(), 0);
    client.restore_item(&id).unwrap();
    assert_eq!(client.items().unwrap()[0].data.title, "My bank");

    client.trash_item(&id).unwrap();
    assert_eq!(client.purge_trash(true).unwrap(), 1);
    assert!(client.trashed_items().unwrap().is_empty());
    assert!(matches!(client.item(&id), Err(Error::NotFound(_))));
}

#[test]
fn unlock_key_after_master_password_change() {
    let server = start_server();
    let client = Client::new(&server, Arc::new(MemoryStore::new()));
    client.sign_up(&email(), PASSWORD).unwrap();
    client
        .change_master_password(PASSWORD, "violet anchor meadow trumpet 42")
        .unwrap();
    let key = client.unlock_key().unwrap();
    client.lock();
    client.unlock_with_key(&key).unwrap();
    client.sync().unwrap();
    client.lock();
    client.unlock("violet anchor meadow trumpet 42").unwrap();
}

fn totp_code(secret: &str, steps: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    passbox_core::totp::Totp::from_base32(secret)
        .unwrap()
        .generate(now.saturating_add_signed(steps * 30))
}

#[test]
fn two_factor_sign_in_unlock_and_reconnect() {
    let server = start_server();
    let email = email();
    let laptop = Client::new(&server, Arc::new(MemoryStore::new()));
    let secret_key = laptop.sign_up(&email, PASSWORD).unwrap();
    assert!(!laptop.two_factor_status().unwrap().enabled);

    let setup = laptop.start_totp_setup().unwrap();
    assert!(setup.uri.contains(&setup.secret));
    assert!(matches!(
        laptop.confirm_totp_setup("000000"),
        Err(Error::InvalidTwoFactorCode)
    ));
    let recovery = laptop
        .confirm_totp_setup(&totp_code(&setup.secret, 0))
        .unwrap()
        .unwrap();
    assert_eq!(recovery.len(), 10);
    let status = laptop.two_factor_status().unwrap();
    assert!(status.enabled && status.totp);
    assert_eq!(status.recovery_codes_remaining, 10);

    // A new device stops after the password.
    let phone_store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let phone = Client::new(&server, phone_store.clone());
    match phone.sign_in(&email, PASSWORD, &secret_key) {
        Err(Error::TwoFactorRequired { methods }) => assert_eq!(methods, ["totp", "recovery"]),
        other => panic!("expected TwoFactorRequired, got {other:?}"),
    }
    assert_eq!(phone.status().unwrap(), Status::SignedOut);
    assert_eq!(
        phone.pending_two_factor(),
        Some(vec!["totp".to_owned(), "recovery".to_owned()])
    );
    assert!(matches!(
        phone.complete_two_factor("totp", "000000", false),
        Err(Error::InvalidTwoFactorCode)
    ));
    // Still pending after a wrong code; the next step's code works.
    assert_eq!(
        phone
            .complete_two_factor("totp", &totp_code(&setup.secret, 1), true)
            .unwrap(),
        None
    );
    assert_eq!(phone.status().unwrap(), Status::Unlocked);
    assert!(phone.pending_two_factor().is_none());

    // The phone was remembered: unlocking needs no code.
    phone.lock();
    assert_eq!(phone.unlock(PASSWORD).unwrap(), Connectivity::Online);

    // The laptop was not: unlocking from the offline cache asks for a
    // factor and stays locked until it is given.
    laptop.lock();
    assert!(matches!(
        laptop.unlock(PASSWORD),
        Err(Error::TwoFactorRequired { .. })
    ));
    assert_eq!(laptop.status().unwrap(), Status::Locked);
    assert_eq!(
        laptop
            .complete_two_factor("recovery", &recovery[0], false)
            .unwrap(),
        Some(9)
    );
    assert_eq!(laptop.status().unwrap(), Status::Unlocked);
    assert!(laptop.is_online());
    assert!(!laptop.vaults().unwrap().is_empty());

    // A recent login is enough for a master password change.
    laptop
        .change_master_password(PASSWORD, "new horse battery staple")
        .unwrap();
    laptop
        .change_master_password("new horse battery staple", PASSWORD)
        .unwrap();
    assert!(matches!(
        laptop.reauthenticate("wrong"),
        Err(Error::InvalidCredentials)
    ));
    assert!(matches!(
        laptop.reauthenticate(PASSWORD),
        Err(Error::TwoFactorRequired { .. })
    ));
    laptop
        .complete_two_factor("recovery", &recovery[1], false)
        .unwrap();
    assert_eq!(laptop.status().unwrap(), Status::Unlocked);

    // A cancelled login has to start over.
    assert!(matches!(
        laptop.reauthenticate(PASSWORD),
        Err(Error::TwoFactorRequired { .. })
    ));
    laptop.cancel_two_factor();
    assert!(matches!(
        laptop.complete_two_factor("totp", "123456", false),
        Err(Error::TwoFactorExpired)
    ));

    let fresh = laptop.regenerate_recovery_codes().unwrap();
    assert_eq!(fresh.len(), 10);
    let kinds: Vec<String> = laptop
        .activity(50)
        .unwrap()
        .into_iter()
        .map(|e| e.kind)
        .collect();
    assert!(kinds.iter().any(|k| k == "recovery_code_used"), "{kinds:?}");
    assert!(matches!(
        laptop.disable_two_factor("recovery", &recovery[2]),
        Err(Error::InvalidTwoFactorCode)
    ));
    laptop.disable_two_factor("recovery", &fresh[0]).unwrap();
    assert!(!laptop.two_factor_status().unwrap().enabled);
    laptop.lock();
    assert_eq!(laptop.unlock(PASSWORD).unwrap(), Connectivity::Online);
}
