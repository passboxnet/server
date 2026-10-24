//! Organizations, invitations, groups and shared vaults with several
//! accounts and devices against a real, in-process server.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use passbox_client::api::{HttpTransport, Transport};
use passbox_client::{
    Client, Connectivity, Error, FieldType, ItemCategory, ItemData, MemoryStore, Store, field,
};
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
            let state = AppState::load(db).await.unwrap();
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

fn email(name: &str) -> String {
    format!("{name}-{}@example.com", passbox_core::id::new_id().unwrap())
}

/// A transport that can corrupt the grants of sealed vault keys in sync
/// responses, like a malicious server would.
struct Tampering {
    inner: HttpTransport,
    forge_grants: Arc<AtomicBool>,
}

impl Transport for Tampering {
    fn send(
        &self,
        method: &str,
        url: &str,
        token: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> passbox_client::Result<(u16, Vec<u8>)> {
        let (status, bytes) = self.inner.send(method, url, token, body)?;
        if !self.forge_grants.load(Ordering::SeqCst) || !url.contains("/api/v1/sync") {
            return Ok((status, bytes));
        }
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        if let Some(keys) = value["sharing"]["vaultKeys"].as_array_mut() {
            for key in keys {
                // Drop the own copy and present a grant with a forged signature.
                key["wrappedKey"] = serde_json::Value::Null;
                key["grantSignature"] =
                    serde_json::Value::String(passbox_core::encoding::encode(&[7u8; 64]));
            }
        }
        Ok((status, serde_json::to_vec(&value).unwrap()))
    }
}

struct Person {
    client: Client,
    store: Arc<dyn Store>,
    email: String,
    secret_key: String,
}

impl Person {
    fn sign_up(server: &str, name: &str) -> Self {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let client = Client::new(server, store.clone());
        let email = email(name);
        let secret_key = client.sign_up(&email, PASSWORD).unwrap();
        Self {
            client,
            store,
            email,
            secret_key,
        }
    }

    fn id(&self) -> String {
        self.client.device_account().unwrap().unwrap().account_id
    }
}

fn note(title: &str, password: &str) -> ItemData {
    let mut data = ItemData::new(ItemCategory::Login, title);
    data.set_field(field::PASSWORD, "Password", FieldType::Concealed, password);
    data
}

#[test]
fn family_sharing_roles_groups_and_removal() {
    let server = start_server();
    let alice = Person::sign_up(&server, "alice");
    let bob = Person::sign_up(&server, "bob");
    let carol = Person::sign_up(&server, "carol");

    // Key pairs exist after sign-up and are the same on another device.
    let fingerprint = alice.client.own_fingerprint().unwrap();
    assert_eq!(fingerprint.split(' ').count(), 12);
    let laptop = Client::new(&server, Arc::new(MemoryStore::new()));
    laptop
        .sign_in(&alice.email, PASSWORD, &alice.secret_key)
        .unwrap();
    assert_eq!(laptop.own_fingerprint().unwrap(), fingerprint);
    assert_eq!(
        alice.client.verify_own_key().unwrap().fingerprint,
        fingerprint
    );

    // Alice creates a family; its vault is shared and managed by her.
    let org_id = alice.client.create_family("Doe family", "Family").unwrap();
    let org = alice.client.org(&org_id).unwrap();
    assert_eq!(org.kind, "family");
    assert_eq!(org.name.as_deref(), Some("Doe family"));
    assert!(org.verified);
    let vault_id = org.default_vault_id.clone().unwrap();
    let access = alice.client.vault_access(&vault_id).unwrap();
    assert_eq!(access.org_id.as_deref(), Some(org_id.as_str()));
    assert_eq!(access.role.as_deref(), Some("manage"));
    let personal = alice
        .client
        .vaults()
        .unwrap()
        .into_iter()
        .find(|v| v.org_id.is_none())
        .unwrap();
    assert_eq!(
        alice.client.vault_access(&personal.id).unwrap().org_id,
        None
    );
    let netflix = alice
        .client
        .create_item(&vault_id, &note("Netflix", "family-secret"))
        .unwrap();

    // Invitation link → accept → confirmation (fingerprints match).
    let invitation = alice.client.invite(&org_id, &bob.email, "member").unwrap();
    assert!(invitation.link.contains("/invite/") && invitation.link.contains("#org="));
    assert_eq!(alice.client.invitations(&org_id).unwrap().len(), 1);
    let preview = bob.client.preview_invitation(&invitation.link).unwrap();
    assert_eq!(preview.org_kind, "family");
    assert_eq!(preview.inviter_email.as_deref(), Some(alice.email.as_str()));
    // The invitation is bound to Bob's email.
    assert!(carol.client.accept_invitation(&invitation.link).is_err());
    assert_eq!(
        bob.client.accept_invitation(&invitation.link).unwrap(),
        org_id
    );
    assert!(bob.client.shared_vaults().unwrap().is_empty());
    let confirmed = alice.client.confirm_member(&org_id, &bob.id()).unwrap();
    assert_eq!(confirmed, bob.client.own_fingerprint().unwrap());
    let member = alice
        .client
        .org(&org_id)
        .unwrap()
        .members
        .into_iter()
        .find(|m| m.account_id == bob.id())
        .unwrap();
    assert!(member.verified && member.status == "confirmed");

    // Bob got the family vault (edit) and reads and edits items.
    bob.client.sync().unwrap();
    assert!(
        bob.client.sharing_warnings().unwrap().is_empty(),
        "{:?}",
        bob.client.sharing_warnings()
    );
    let shared = bob.client.vault_members(&vault_id).unwrap();
    assert_eq!(shared.role.as_deref(), Some("edit"));
    assert_eq!(
        bob.client
            .item(&netflix)
            .unwrap()
            .data
            .field(field::PASSWORD),
        Some("family-secret")
    );
    let mut edited = bob.client.item(&netflix).unwrap().data;
    edited.set_field(field::PASSWORD, "Password", FieldType::Concealed, "changed");
    bob.client.update_item(&netflix, &edited).unwrap();
    alice.client.sync().unwrap();
    assert_eq!(
        alice
            .client
            .item(&netflix)
            .unwrap()
            .data
            .field(field::PASSWORD),
        Some("changed")
    );
    // A second device of Bob sees the shared vault too.
    let bob_phone = Client::new(&server, Arc::new(MemoryStore::new()));
    bob_phone
        .sign_in(&bob.email, PASSWORD, &bob.secret_key)
        .unwrap();
    assert!(bob_phone.item(&netflix).is_ok());

    // View-only: the server refuses Bob's writes.
    alice
        .client
        .share_vault(&vault_id, "account", &bob.id(), "view")
        .unwrap();
    bob.client.sync().unwrap();
    assert_eq!(
        bob.client.vault_access(&vault_id).unwrap().role.as_deref(),
        Some("view")
    );
    let error = bob.client.update_item(&netflix, &edited).unwrap_err();
    assert!(
        matches!(error, Error::Server { status: 403, .. }),
        "{error:?}"
    );
    assert!(
        bob.client
            .share_vault(&vault_id, "account", &carol.id(), "view")
            .is_err()
    );

    // Carol joins; a group gets the vault.
    let invitation = alice
        .client
        .invite(&org_id, &carol.email, "member")
        .unwrap();
    carol.client.accept_invitation(&invitation.link).unwrap();
    alice.client.confirm_member(&org_id, &carol.id()).unwrap();
    let group_id = alice
        .client
        .create_group(&org_id, "Kids", &[carol.id()])
        .unwrap();
    assert_eq!(
        alice.client.groups(&org_id).unwrap()[0].name.as_deref(),
        Some("Kids")
    );
    let kids_vault = alice.client.create_shared_vault(&org_id, "Kids").unwrap();
    let game = alice
        .client
        .create_item(&kids_vault, &note("Game", "kids-secret"))
        .unwrap();
    alice
        .client
        .share_vault(&kids_vault, "group", &group_id, "view")
        .unwrap();
    carol.client.sync().unwrap();
    assert_eq!(
        carol
            .client
            .item(&game)
            .unwrap()
            .data
            .field(field::PASSWORD),
        Some("kids-secret")
    );
    let members = alice.client.vault_members(&kids_vault).unwrap().members;
    assert!(
        members
            .iter()
            .any(|m| m.principal_type == "group" && m.principal_id == group_id)
    );

    // Removing Bob from the family rotates the family vault key and
    // re-encrypts its items; Bob loses access, Carol keeps hers.
    let epoch = alice.client.vault_members(&vault_id).unwrap().key_epoch;
    alice.client.remove_member(&org_id, &bob.id()).unwrap();
    let after = alice.client.vault_members(&vault_id).unwrap();
    assert_eq!(after.key_epoch, epoch + 1);
    assert!(!after.rotation_pending);
    assert_eq!(alice.client.item(&netflix).unwrap().key_epoch, epoch + 1);
    bob.client.sync().unwrap();
    assert!(bob.client.item(&netflix).is_err());
    assert!(bob.client.orgs().unwrap().is_empty());
    carol.client.sync().unwrap();
    assert!(
        carol.client.sharing_warnings().unwrap().is_empty(),
        "{:?}",
        carol.client.sharing_warnings()
    );
    assert_eq!(
        carol.client.org(&org_id).unwrap().name.as_deref(),
        Some("Doe family")
    );

    // Removing Carol from the group rotates the group and the Kids vault.
    alice
        .client
        .remove_group_member(&org_id, &group_id, &carol.id())
        .unwrap();
    carol.client.sync().unwrap();
    assert!(carol.client.item(&game).is_err());
    assert!(alice.client.item(&game).is_ok());
    assert_eq!(
        alice.client.vault_members(&kids_vault).unwrap().key_epoch,
        2
    );

    // Offline unlock keeps shared vaults readable.
    alice.client.lock();
    let offline = Client::with_transport(
        "http://127.0.0.1:9",
        alice.store.clone(),
        Box::new(HttpTransport::default()),
    );
    assert_eq!(offline.unlock(PASSWORD).unwrap(), Connectivity::Offline);
    assert!(offline.item(&netflix).is_ok());
    assert_eq!(offline.own_fingerprint().unwrap(), fingerprint);
}

#[test]
fn forged_grants_are_rejected_by_the_client() {
    let server = start_server();
    let alice = Person::sign_up(&server, "alice");
    let forge = Arc::new(AtomicBool::new(false));
    let bob_store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let bob = Client::with_transport(
        &server,
        bob_store,
        Box::new(Tampering {
            inner: HttpTransport::default(),
            forge_grants: forge.clone(),
        }),
    );
    let bob_email = email("bob");
    bob.sign_up(&bob_email, PASSWORD).unwrap();
    let bob_id = bob.device_account().unwrap().unwrap().account_id;

    let org_id = alice.client.create_team("Acme").unwrap();
    let vault_id = alice.client.create_shared_vault(&org_id, "Ops").unwrap();
    let item = alice
        .client
        .create_item(&vault_id, &note("Server", "root"))
        .unwrap();
    let invitation = alice.client.invite(&org_id, &bob_email, "member").unwrap();
    bob.accept_invitation(&invitation.link).unwrap();
    alice.client.confirm_member(&org_id, &bob_id).unwrap();
    alice
        .client
        .share_vault(&vault_id, "account", &bob_id, "edit")
        .unwrap();

    forge.store(true, Ordering::SeqCst);
    bob.sync().unwrap();
    assert!(
        bob.item(&item).is_err(),
        "a forged grant must not open the key"
    );
    assert!(
        bob.sharing_warnings()
            .unwrap()
            .iter()
            .any(|w| w.kind == "grant_invalid")
    );
    assert!(!bob.vault_members(&vault_id).unwrap().has_key);

    forge.store(false, Ordering::SeqCst);
    bob.sync().unwrap();
    assert_eq!(
        bob.item(&item).unwrap().data.field(field::PASSWORD),
        Some("root")
    );
}

#[test]
fn team_admins_and_member_management() {
    let server = start_server();
    let owner = Person::sign_up(&server, "owner");
    let admin = Person::sign_up(&server, "admin");
    let member = Person::sign_up(&server, "member");
    let org_id = owner.client.create_team("Acme").unwrap();
    // Only the owner invites admins.
    let invitation = owner.client.invite(&org_id, &admin.email, "admin").unwrap();
    admin.client.accept_invitation(&invitation.link).unwrap();
    owner.client.confirm_member(&org_id, &admin.id()).unwrap();
    admin.client.sync().unwrap();
    assert_eq!(admin.client.org(&org_id).unwrap().role, "admin");
    assert!(admin.client.invite(&org_id, &email("x"), "admin").is_err());
    // An admin invites and confirms a member; the member sees both verified.
    let invitation = admin
        .client
        .invite(&org_id, &member.email, "member")
        .unwrap();
    member.client.accept_invitation(&invitation.link).unwrap();
    admin.client.confirm_member(&org_id, &member.id()).unwrap();
    member.client.sync().unwrap();
    let org = member.client.org(&org_id).unwrap();
    assert_eq!(org.members.len(), 3);
    assert!(org.members.iter().all(|m| m.verified), "{:?}", org.members);
    assert!(member.client.sharing_warnings().unwrap().is_empty());
    // Members cannot manage the organization.
    assert!(member.client.create_shared_vault(&org_id, "x").is_err());
    assert!(
        member
            .client
            .invite(&org_id, &email("y"), "member")
            .is_err()
    );
    // Removing the admin re-attests the members they confirmed.
    owner.client.remove_member(&org_id, &admin.id()).unwrap();
    member.client.sync().unwrap();
    let org = member.client.org(&org_id).unwrap();
    assert_eq!(org.members.len(), 2);
    assert!(org.members.iter().all(|m| m.verified), "{:?}", org.members);
    assert!(
        member.client.sharing_warnings().unwrap().is_empty(),
        "{:?}",
        member.client.sharing_warnings()
    );
    // Suspension blocks shared vaults on the server.
    let vault_id = owner.client.create_shared_vault(&org_id, "Ops").unwrap();
    owner
        .client
        .share_vault(&vault_id, "account", &member.id(), "view")
        .unwrap();
    member.client.sync().unwrap();
    assert_eq!(member.client.shared_vaults().unwrap().len(), 1);
    owner.client.suspend_member(&org_id, &member.id()).unwrap();
    member.client.sync().unwrap();
    assert!(member.client.shared_vaults().unwrap().is_empty());
    owner
        .client
        .reactivate_member(&org_id, &member.id())
        .unwrap();
    member.client.sync().unwrap();
    assert_eq!(member.client.shared_vaults().unwrap().len(), 1);
    // Members can leave.
    member.client.leave_org(&org_id).unwrap();
    assert!(member.client.orgs().unwrap().is_empty());
}
