//! Recovery code, organization recovery, emergency access and adding a
//! device by code against a real, in-process server.

use std::net::SocketAddr;
use std::sync::Arc;

use passbox_client::{Client, Error, FieldType, ItemCategory, ItemData, MemoryStore, Store, field};
use passbox_server::config::Config;
use passbox_server::state::AppState;

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
            let mut state = AppState::load(db).await.unwrap();
            state.auth_rate_limit = 1000;
            let app = passbox_server::routes::router(&Config::default(), state);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send(listener.local_addr().unwrap()).unwrap();
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
    });
    format!("http://{}", rx.recv().unwrap())
}

const PASSWORD: &str = "correct horse battery staple";
const NEW_PASSWORD: &str = "violet ocean lantern 42 maple";

fn email(name: &str) -> String {
    format!("{name}-{}@example.com", passbox_core::id::new_id().unwrap())
}

struct Person {
    client: Client,
    email: String,
    secret_key: String,
}

impl Person {
    fn sign_up(server: &str, name: &str) -> Self {
        let client = Client::new(server, Arc::new(MemoryStore::new()));
        let email = email(name);
        let secret_key = client.sign_up(&email, PASSWORD).unwrap();
        Self {
            client,
            email,
            secret_key,
        }
    }

    fn id(&self) -> String {
        self.client.device_account().unwrap().unwrap().account_id
    }

    fn personal_vault(&self) -> String {
        self.client
            .vaults()
            .unwrap()
            .into_iter()
            .find(|v| v.org_id.is_none())
            .unwrap()
            .id
    }
}

fn login(title: &str, password: &str) -> ItemData {
    let mut data = ItemData::new(ItemCategory::Login, title);
    data.set_field(field::PASSWORD, "Password", FieldType::Concealed, password);
    data
}

fn new_device(server: &str) -> Client {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    Client::new(server, store)
}

#[test]
fn recovery_code_sets_a_new_password_and_secret_key() {
    let server = start_server();
    let ada = Person::sign_up(&server, "ada");
    let item = ada
        .client
        .create_item(&ada.personal_vault(), &login("Bank", "s3cret"))
        .unwrap();
    assert!(matches!(
        ada.client.create_recovery_code("wrong password"),
        Err(Error::InvalidCredentials)
    ));
    let code = ada.client.create_recovery_code(PASSWORD).unwrap();
    assert!(code.starts_with("R1-"));
    assert!(
        ada.client
            .recovery_status()
            .unwrap()
            .recovery_code_created_at
            .is_some()
    );

    let device = new_device(&server);
    assert!(matches!(
        device.start_code_recovery(
            &ada.email,
            &passbox_core::recovery::code::RecoveryCode::generate()
                .unwrap()
                .to_display_string()
        ),
        Err(Error::InvalidCredentials)
    ));
    assert!(device.start_code_recovery(&ada.email, "R1-ABC").is_err());
    let start = device.start_code_recovery(&ada.email, &code).unwrap();
    assert_eq!(start.account_id, ada.id());
    assert!(start.two_factor_methods.is_none());
    assert!(device.recovery_ready());
    let result = device.finish_recovery(NEW_PASSWORD).unwrap();
    assert_ne!(result.secret_key, ada.secret_key);
    assert_ne!(result.recovery_code, code);
    assert_eq!(
        device.item(&item).unwrap().data.field(field::PASSWORD),
        Some("s3cret")
    );

    // The old device is signed out; the old Secret Key no longer works.
    assert!(ada.client.sync().is_err());
    assert!(matches!(
        new_device(&server).sign_in(&ada.email, PASSWORD, &ada.secret_key),
        Err(Error::InvalidCredentials)
    ));
    let laptop = new_device(&server);
    laptop
        .sign_in(&ada.email, NEW_PASSWORD, &result.secret_key)
        .unwrap();
    assert!(laptop.item(&item).is_ok());
    // The new recovery code works, the old one does not.
    assert!(matches!(
        new_device(&server).start_code_recovery(&ada.email, &code),
        Err(Error::InvalidCredentials)
    ));
    assert!(
        new_device(&server)
            .start_code_recovery(&ada.email, &result.recovery_code)
            .is_ok()
    );
}

#[test]
fn organization_recovery_and_emergency_access() {
    let server = start_server();
    let alice = Person::sign_up(&server, "alice");
    let bob = Person::sign_up(&server, "bob");
    let org_id = alice.client.create_team("Acme").unwrap();
    let invitation = alice.client.invite(&org_id, &bob.email, "member").unwrap();
    bob.client.accept_invitation(&invitation.link).unwrap();
    alice.client.confirm_member(&org_id, &bob.id()).unwrap();
    bob.client.sync().unwrap();

    // Recovery through the organization.
    assert!(!bob.client.org_recovery(&org_id).unwrap().available);
    alice.client.set_up_org_recovery(&org_id).unwrap();
    let info = bob.client.org_recovery(&org_id).unwrap();
    assert!(info.available && !info.enrolled && !info.can_approve);
    assert_eq!(info.admins, vec![alice.id()]);
    bob.client.enroll_org_recovery(&org_id).unwrap();
    assert!(bob.client.org_recovery(&org_id).unwrap().enrolled);

    let device = new_device(&server);
    let pending = device
        .request_org_recovery(&bob.email, Some(&org_id))
        .unwrap();
    assert_eq!(
        device.pending_org_recovery().unwrap(),
        Some(pending.clone())
    );
    assert_eq!(device.check_org_recovery().unwrap(), "pending");
    let requests = alice.client.recovery_requests(&org_id).unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].request_code, pending.request_code);
    alice
        .client
        .approve_recovery_request(&org_id, &requests[0].id)
        .unwrap();
    assert_eq!(device.check_org_recovery().unwrap(), "approved");
    let result = device.finish_recovery(NEW_PASSWORD).unwrap();
    assert_eq!(result.email, bob.email);
    assert!(device.pending_org_recovery().unwrap().is_none());
    assert!(bob.client.sync().is_err());

    // Emergency access: Alice trusts Bob (now on his recovered device).
    let vault = alice.personal_vault();
    alice
        .client
        .create_item(&vault, &login("Insurance", "policy-123"))
        .unwrap();
    let grant_id = alice.client.add_emergency_contact(&bob.email, 3).unwrap();
    let received = device.emergency_contacts().unwrap().received;
    assert_eq!(received[0].status, "invited");
    device.accept_emergency_invitation(&grant_id).unwrap();
    let fingerprint = alice
        .client
        .confirm_emergency_contact(&grant_id, std::slice::from_ref(&vault))
        .unwrap();
    assert_eq!(fingerprint, device.own_fingerprint().unwrap());
    assert_eq!(alice.client.reseal_emergency_access().unwrap(), 0);
    assert!(device.open_emergency_access(&grant_id).is_err());
    device.request_emergency_access(&grant_id).unwrap();
    assert!(device.open_emergency_access(&grant_id).is_err());
    alice.client.approve_emergency_access(&grant_id).unwrap();
    let opened = device.open_emergency_access(&grant_id).unwrap();
    assert_eq!(opened.vaults[0].0, vault);
    assert_eq!(
        opened.items[0].data.field(field::PASSWORD),
        Some("policy-123")
    );
    alice.client.deny_emergency_access(&grant_id).unwrap();
    assert!(device.open_emergency_access(&grant_id).is_err());
}

#[test]
fn a_device_code_transfers_the_secret_key() {
    let server = start_server();
    let ada = Person::sign_up(&server, "linker");
    let link = ada.client.start_device_link().unwrap();
    assert_eq!(link.code.len(), 19);
    let phone = new_device(&server);
    phone.set_device("Ada's phone", "ios");
    assert!(phone.claim_device_link("ABCD").is_err());
    phone.claim_device_link(&link.code).unwrap();
    assert_eq!(phone.poll_device_link().unwrap(), None);
    let state = ada.client.device_link_status(&link.id).unwrap();
    assert_eq!(state.status, "claimed");
    assert_eq!(state.device_name.as_deref(), Some("Ada's phone"));
    ada.client.approve_device_link(&link.id).unwrap();
    let linked = phone.poll_device_link().unwrap().unwrap();
    assert_eq!(linked.secret_key, ada.secret_key);
    phone
        .sign_in(&linked.email, PASSWORD, &linked.secret_key)
        .unwrap();
    assert!(new_device(&server).claim_device_link(&link.code).is_err());
}
