//! The product decisions of 25.10.2026 against a real, in-process server:
//! organization recovery on by default with automatic enrollment (C1),
//! view-only guests (B8), the fair-use limit for agents and service
//! accounts, and `passbox_reveal` for AI agents. Runs on SQLite, and on
//! PostgreSQL too when `PASSBOX_TEST_DATABASE_URL` is set.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use passbox_client::agent::{AccessRequest, Backend, Broker, GrantState};
use passbox_client::{
    Client, Error, FieldType, ItemCategory, ItemData, MemoryStore, ServiceAccountClient, field,
};
use passbox_core::policy::PolicyRules;
use passbox_core::service_account::Permission;
use passbox_server::config::Config;
use passbox_server::state::AppState;

const PASSWORD: &str = "correct horse battery staple";

fn start_server(database_url: String, agent_limit: u32) -> String {
    let (tx, rx) = std::sync::mpsc::channel::<SocketAddr>();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let db = passbox_server::db::connect(&database_url).await.unwrap();
            let mut state = AppState::load(db).await.unwrap();
            state.auth_rate_limit = 1000;
            state.agent_limit_per_member = agent_limit;
            let app = passbox_server::routes::router(&Config::default(), state);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send(listener.local_addr().unwrap()).unwrap();
            axum::serve(listener, app).await.unwrap();
        });
    });
    format!("http://{}", rx.recv().unwrap())
}

fn database_urls() -> Vec<String> {
    let mut urls = vec!["sqlite::memory:".to_owned()];
    if let Ok(url) = std::env::var("PASSBOX_TEST_DATABASE_URL") {
        urls.push(url);
    }
    urls
}

fn person(server: &str) -> (Client, String) {
    let client = Client::new(server, Arc::new(MemoryStore::new()));
    let email = format!("{}@example.com", passbox_core::id::new_id().unwrap());
    client.sign_up(&email, PASSWORD).unwrap();
    (client, email)
}

fn id(client: &Client) -> String {
    client.device_account().unwrap().unwrap().account_id
}

fn login(title: &str, password: &str) -> ItemData {
    let mut data = ItemData::new(ItemCategory::Login, title);
    data.set_field(field::PASSWORD, "Password", FieldType::Concealed, password);
    data
}

fn server_code(error: &Error) -> Option<&str> {
    match error {
        Error::Server { code, .. } => Some(code.as_str()),
        _ => None,
    }
}

/// Joins `member` to the organization with `role` (invite, accept, confirm).
fn join(owner: &Client, member: &Client, email: &str, org_id: &str, role: &str) -> bool {
    let invitation = owner.invite(org_id, email, role).unwrap();
    let preview = member.preview_invitation(&invitation.link).unwrap();
    member.accept_invitation(&invitation.link).unwrap();
    owner.confirm_member(org_id, &id(member)).unwrap();
    member.sync().unwrap();
    preview.recovery
}

#[test]
fn recovery_by_default_and_view_only_guests() {
    for url in database_urls() {
        recovery_and_guests_on(&start_server(url, 0));
    }
}

fn recovery_and_guests_on(server: &str) {
    let (owner, _) = person(server);
    let (member, member_email) = person(server);
    let (guest, guest_email) = person(server);

    // A new team has recovery set up, a policy that requires it, and the
    // creator is enrolled.
    let org_id = owner.create_team("Agency").unwrap();
    let recovery = owner.org_recovery(&org_id).unwrap();
    assert!(recovery.available && recovery.enrolled, "{recovery:?}");
    let policy = owner
        .org_policies()
        .unwrap()
        .into_iter()
        .find(|p| p.org_id == org_id)
        .unwrap();
    assert!(policy.rules.require_recovery_enrollment);
    assert!(!policy.rules.allow_agent_reveal);

    // Joining says so up front; the client enrolls once confirmed.
    assert!(join(&owner, &member, &member_email, &org_id, "member"));
    assert!(!member.org_recovery(&org_id).unwrap().enrolled);
    assert_eq!(
        member.enroll_required_org_recovery().unwrap(),
        vec![org_id.clone()]
    );
    assert!(member.org_recovery(&org_id).unwrap().enrolled);
    assert!(member.enroll_required_org_recovery().unwrap().is_empty());

    // Guests: not told about recovery, never enrolled, view-only.
    assert!(!join(&owner, &guest, &guest_email, &org_id, "guest"));
    assert!(
        guest
            .effective_policy()
            .unwrap()
            .recovery_enrollment_orgs
            .is_empty()
    );
    assert!(guest.enroll_required_org_recovery().unwrap().is_empty());
    assert!(!guest.org_recovery(&org_id).unwrap().enrolled);

    let vault_id = owner.create_shared_vault(&org_id, "Client X").unwrap();
    let item_id = owner
        .create_item(&vault_id, &login("CMS", "cms-secret"))
        .unwrap();
    owner
        .share_vault(&vault_id, "account", &id(&member), "edit")
        .unwrap();
    assert!(
        owner
            .share_vault(&vault_id, "account", &id(&guest), "edit")
            .is_err(),
        "a guest cannot get edit"
    );
    owner
        .share_vault(&vault_id, "account", &id(&guest), "view")
        .unwrap();
    guest.sync().unwrap();
    assert_eq!(
        guest.item(&item_id).unwrap().data.field(field::PASSWORD),
        Some("cms-secret")
    );
    assert_eq!(
        guest.vault_access(&vault_id).unwrap().role.as_deref(),
        Some("view")
    );
    let err = guest
        .create_item(&vault_id, &login("Mine", "x"))
        .unwrap_err();
    assert!(
        server_code(&err) == Some("guest_view_only") || matches!(err, Error::InvalidData(_)),
        "{err:?}"
    );
    // No machine access to the vaults shared with a guest.
    let err = guest
        .create_service_account("Guest bot", 0, &[(vault_id.clone(), Permission::Read)])
        .unwrap_err();
    assert_eq!(server_code(&err), Some("guest_view_only"), "{err:?}");
    // A guest in a family does not get the family vault.
    let family = owner.create_family("Doe", "Family").unwrap();
    let (cousin, cousin_email) = person(server);
    join(&owner, &cousin, &cousin_email, &family, "guest");
    let family_vault = owner.org(&family).unwrap().default_vault_id.unwrap();
    assert!(
        cousin.vault_access(&family_vault).is_err() || {
            cousin.vault_access(&family_vault).unwrap().role.is_none()
        }
    );

    // Turning recovery off needs the policy changed first.
    let err = owner.turn_off_org_recovery(&org_id).unwrap_err();
    assert_eq!(server_code(&err), Some("recovery_required"), "{err:?}");
    owner
        .set_org_policy(&org_id, &PolicyRules::default())
        .unwrap();
    owner.turn_off_org_recovery(&org_id).unwrap();
    assert!(!owner.org_recovery(&org_id).unwrap().available);
    member.sync().unwrap();
    assert!(member.enroll_required_org_recovery().unwrap().is_empty());
}

#[test]
fn agent_fair_use_limit() {
    for url in database_urls() {
        agent_limit_on(&start_server(url, 1));
    }
}

fn agent_limit_on(server: &str) {
    // Alone: one service account (the limit per member).
    let (alice, _) = person(server);
    let vault = Client::vaults(&alice).unwrap().remove(0).id;
    let (first, _) = alice
        .create_service_account("CI", 0, &[(vault.clone(), Permission::Read)])
        .unwrap();
    let err = alice
        .create_service_account("Agent", 0, &[(vault.clone(), Permission::Read)])
        .unwrap_err();
    assert_eq!(server_code(&err), Some("agent_limit_reached"), "{err:?}");
    // Revoked ones do not count.
    alice.revoke_service_account(&first.id).unwrap();
    alice
        .create_service_account("Agent", 0, &[(vault.clone(), Permission::Read)])
        .unwrap();

    // In a team, members share a pool of limit × members; guests add nothing.
    let (bob, bob_email) = person(server);
    let (gina, gina_email) = person(server);
    let org_id = alice.create_team("Pool").unwrap();
    join(&alice, &bob, &bob_email, &org_id, "member");
    join(&alice, &gina, &gina_email, &org_id, "guest");
    let bob_vault = Client::vaults(&bob).unwrap().remove(0).id;
    bob.create_service_account("Bob CI", 0, &[(bob_vault.clone(), Permission::Read)])
        .unwrap();
    let err = bob
        .create_service_account("Bob 2", 0, &[(bob_vault, Permission::Read)])
        .unwrap_err();
    assert_eq!(
        server_code(&err),
        Some("agent_limit_reached"),
        "pool of 2 used"
    );
    // The guest's own allowance still applies to their personal vault.
    let gina_vault = Client::vaults(&gina).unwrap().remove(0).id;
    gina.create_service_account("Gina", 0, &[(gina_vault, Permission::Read)])
        .unwrap();
}

/// Approves every pending agent request, with or without the reveal tick.
fn approve(owner: Arc<Client>, reveal: bool, rounds: usize) {
    std::thread::spawn(move || {
        let mut answered = 0;
        for _ in 0..200 {
            std::thread::sleep(Duration::from_millis(50));
            for grant in owner.agent_grants().unwrap_or_default() {
                let _ = owner.decide_agent_grant_with_reveal(&grant, true, reveal, 0);
                answered += 1;
            }
            if answered >= rounds {
                return;
            }
        }
    });
}

#[test]
fn agent_reveal() {
    for url in database_urls() {
        agent_reveal_on(&start_server(url, 0));
    }
}

fn agent_reveal_on(server: &str) {
    let (owner, _) = person(server);
    let owner = Arc::new(owner);
    let personal = Client::vaults(&owner).unwrap().remove(0).id;
    owner
        .create_item(&personal, &login("Staging DB", "personal-secret"))
        .unwrap();
    let org_id = owner.create_team("Ops").unwrap();
    let shared = owner.create_shared_vault(&org_id, "Shared").unwrap();
    owner
        .create_item(&shared, &login("Prod DB", "org-secret"))
        .unwrap();
    let (_, token) = owner
        .create_service_account(
            "Claude Code",
            0,
            &[
                (personal.clone(), Permission::Read),
                (shared, Permission::Read),
            ],
        )
        .unwrap();
    let sa = ServiceAccountClient::connect(server, &token).unwrap();
    let mut broker = Broker::new(sa, None);
    broker.set_poll_interval(Duration::from_millis(50));
    let reference = |title: &str| {
        broker.search(title, None, 5).unwrap()[0]
            .fields
            .iter()
            .find(|f| f.id == "password")
            .unwrap()
            .reference
            .clone()
    };
    let staging = reference("staging");
    let prod = reference("prod");
    let wait = Duration::from_secs(10);

    // Approved without the tick: nothing is revealed.
    approve(owner.clone(), false, 1);
    let result = broker
        .reveal(&staging, "debug the connection", wait)
        .unwrap();
    assert!(
        matches!(result, Err(GrantState::Denied { .. })),
        "{result:?}"
    );

    // With the tick: the value, and a reveal event of its own.
    approve(owner.clone(), true, 1);
    let outcome = broker
        .reveal(&staging, "debug the connection", wait)
        .unwrap()
        .unwrap();
    assert_eq!(outcome.value, "personal-secret");
    let events = owner.activity(100).unwrap();
    assert!(events.iter().any(|e| e.kind == "agent_reveal"));
    // Single use: the next reveal asks again (nobody answers).
    let result = broker
        .reveal(&staging, "again", Duration::from_millis(300))
        .unwrap();
    assert!(
        matches!(result, Err(GrantState::Pending { .. })),
        "{result:?}"
    );

    // The organization's vault: no policy allows it, so the approver's
    // core refuses the tick and the server refuses the reveal.
    approve(owner.clone(), true, 1);
    let result = broker.reveal(&prod, "debug prod", wait).unwrap();
    assert!(result.is_err(), "{result:?}");
    let err = broker
        .backend()
        .agent_call(
            "POST",
            "agent-events",
            Some(serde_json::json!({
                "grantId": passbox_core::id::new_id().unwrap(),
                "tool": "reveal",
                "itemIds": [],
                "result": "ok",
            })),
        )
        .unwrap_err();
    assert_eq!(server_code(&err), Some("agent_reveal_not_allowed"));

    // An admin allows it in the policy: then it works there too.
    owner
        .set_org_policy(
            &org_id,
            &PolicyRules {
                allow_agent_reveal: true,
                ..PolicyRules::new_org_defaults()
            },
        )
        .unwrap();
    owner.sync().unwrap();
    // Pending requests from before the policy change are answered first.
    std::thread::sleep(Duration::from_millis(300));
    approve(owner.clone(), true, 1);
    let outcome = broker.reveal(&prod, "debug prod", wait).unwrap().unwrap();
    assert_eq!(outcome.value, "org-secret");

    // A grant from passbox_request_access covers reveals only with the tick.
    approve(owner.clone(), false, 1);
    let state = broker
        .request_access(
            &AccessRequest {
                items: vec![staging.clone()],
                actions: vec!["run".into(), "reveal".into()],
                commands: vec!["true".into()],
                reason: "work".into(),
                ..AccessRequest::default()
            },
            wait,
        )
        .unwrap();
    assert!(matches!(state, GrantState::Approved { .. }), "{state:?}");
    let result = broker
        .reveal(&staging, "work", Duration::from_millis(300))
        .unwrap();
    assert!(result.is_err(), "{result:?}");
}
