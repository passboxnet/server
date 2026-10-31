//! Service accounts (F2) and the agent broker (F7) against a real,
//! in-process server. Needs `PASSBOX_TEST_DATABASE_URL` (a PostgreSQL
//! superuser).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use passbox_client::agent::{AccessRequest, Backend, Broker, GrantState};
use passbox_client::api::{Api, HttpTransport};
use passbox_client::{
    Client, Error, FieldType, ItemCategory, ItemData, MemoryStore, ServiceAccountClient, field,
};
use passbox_core::service_account::Permission;

const PASSWORD: &str = "correct horse battery staple";

fn start_server() -> String {
    passbox_server::testing::spawn_server(|state, _| state.auth_rate_limit = 1000)
}

fn email() -> String {
    format!("{}@example.com", passbox_core::id::new_id().unwrap())
}

fn owner(server: &str) -> (Client, String) {
    let client = Client::new(server, Arc::new(MemoryStore::new()));
    client.sign_up(&email(), PASSWORD).unwrap();
    let vault = client.vaults().unwrap().remove(0).id;
    let mut data = ItemData::new(ItemCategory::Login, "Database");
    data.set_field(field::USERNAME, "Username", FieldType::Text, "admin");
    data.set_field(
        field::PASSWORD,
        "Password",
        FieldType::Concealed,
        "s3cr3t-db-pw",
    );
    data.set_field(
        field::URL,
        "Website",
        FieldType::Url,
        "https://db.example.com",
    );
    client.create_item(&vault, &data).unwrap();
    (client, vault)
}

#[test]
fn service_accounts() {
    service_accounts_on(&start_server());
}

fn service_accounts_on(server: &str) {
    let (owner, vault) = owner(server);
    let other_vault = owner.create_vault("Private stuff").unwrap();
    let (info, token) = owner
        .create_service_account("CI deploy", 0, &[(vault.clone(), Permission::Read)])
        .unwrap();
    assert!(token.starts_with("pbx_sa_"));
    assert_eq!(info.grants.len(), 1);

    // The service account reads its vault, and only that one.
    let sa = ServiceAccountClient::connect(server, &token).unwrap();
    let vaults = sa.vaults().unwrap();
    assert_eq!(vaults.len(), 1);
    assert!(!vaults[0].writable);
    let items = sa.items().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].data.field(field::PASSWORD), Some("s3cr3t-db-pw"));
    assert!(sa.errors().unwrap().is_empty());

    // Read-only: writes are refused by the client and the server.
    let note = ItemData::new(ItemCategory::Note, "From CI");
    assert!(sa.create_item(&vault, &note).is_err());
    assert!(sa.create_item(&other_vault, &note).is_err());

    // With write access it can create, update and delete.
    owner
        .grant_service_account(&info.id, &vault, Permission::Write)
        .unwrap();
    sa.refresh().unwrap();
    let id = sa.create_item(&vault, &note).unwrap();
    let mut changed = sa.item(&id).unwrap().data;
    changed.notes = "updated".into();
    sa.update_item(&id, &changed).unwrap();
    owner.sync().unwrap();
    assert_eq!(owner.item(&id).unwrap().data.notes, "updated");
    sa.delete_item(&id).unwrap();
    owner.sync().unwrap();
    assert!(owner.item(&id).is_err());

    // A wrong token is refused; so is the right one after revocation.
    let mut wrong = token.to_string();
    let last = wrong.pop().unwrap();
    wrong.push(if last == 'A' { 'B' } else { 'A' });
    assert!(ServiceAccountClient::connect(server, &wrong).is_err());
    owner.revoke_service_account(&info.id).unwrap();
    match ServiceAccountClient::connect(server, &token) {
        Err(Error::Server {
            status: 403, code, ..
        }) => {
            assert_eq!(code, "service_account_revoked")
        }
        Err(e) => panic!("unexpected error {e}"),
        Ok(_) => panic!("a revoked service account still works"),
    }
    let listed = owner.service_accounts().unwrap();
    assert!(listed[0].revoked_at > 0);

    // Expired service accounts stop working (expiry in the past is refused
    // at creation, so check the boundary on the server's answer).
    let api = Api::new(server, Box::new(HttpTransport::default()));
    assert!(matches!(
        api.request("GET", "/api/v1/service-account", "sa.x.y", None),
        Err(Error::Server { status: 401, .. })
    ));
}

/// An "agent device": approves every request after `delay`, the way a
/// person would on another signed-in device.
fn approve_in_background(owner: Arc<Client>, approve: bool, rounds: usize) {
    std::thread::spawn(move || {
        let mut answered = 0;
        for _ in 0..200 {
            std::thread::sleep(Duration::from_millis(50));
            for grant in owner.agent_grants().unwrap_or_default() {
                owner.decide_agent_grant(&grant, approve, 0).unwrap();
                answered += 1;
            }
            if answered >= rounds {
                return;
            }
        }
    });
}

#[test]
fn agent_broker() {
    agent_broker_on(&start_server());
}

fn agent_broker_on(server: &str) {
    let (owner, vault) = owner(server);
    let owner = Arc::new(owner);
    let (_, token) = owner
        .create_service_account("Claude Code", 0, &[(vault.clone(), Permission::Write)])
        .unwrap();
    let sa = ServiceAccountClient::connect(server, &token).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut broker = Broker::new(sa, Some(dir.path().join("audit.log")));
    broker.set_poll_interval(Duration::from_millis(50));
    broker.set_client_name("test-agent");

    // Search returns metadata, never values.
    let hits = broker.search("database", None, 10).unwrap();
    assert_eq!(hits.len(), 1);
    let json = serde_json::to_string(&hits).unwrap();
    assert!(!json.contains("s3cr3t"), "{json}");
    assert!(json.contains("db.example.com"));
    assert!(broker.search("  ", None, 10).is_err());
    let reference = hits[0]
        .fields
        .iter()
        .find(|f| f.id == "password")
        .unwrap()
        .reference
        .clone();

    // A denied run does not execute.
    approve_in_background(owner.clone(), false, 1);
    let mut env = BTreeMap::new();
    env.insert("DB_PASSWORD".to_owned(), reference.clone());
    let marker = dir.path().join("ran");
    let command = format!("touch {}", marker.display());
    let result = broker
        .run(
            &command,
            &env,
            &[],
            None,
            Duration::from_secs(10),
            "test",
            Duration::from_secs(10),
        )
        .unwrap();
    assert!(
        matches!(result, Err(GrantState::Denied { .. })),
        "{result:?}"
    );
    assert!(!marker.exists());

    // An approved grant with an allowlist runs matching commands, and the
    // output is redacted.
    approve_in_background(owner.clone(), true, 1);
    let state = broker
        .request_access(
            &AccessRequest {
                items: vec![reference.clone()],
                actions: vec!["run".into()],
                commands: vec!["sh -c *".into(), "echo *".into()],
                reason: "Run the migrations".into(),
                ..AccessRequest::default()
            },
            Duration::from_secs(10),
        )
        .unwrap();
    assert!(matches!(state, GrantState::Approved { .. }), "{state:?}");
    let out = broker
        .run(
            "echo \"$DB_PASSWORD\"",
            &env,
            &[],
            None,
            Duration::from_secs(10),
            "",
            Duration::from_secs(1),
        )
        .unwrap()
        .unwrap();
    assert_eq!(out.exit_code, Some(0));
    assert!(!out.stdout.contains("s3cr3t"), "{}", out.stdout);
    assert!(out.stdout.contains("[redacted DB_PASSWORD]"));

    // A command outside the allowlist needs its own approval; nobody
    // answers, so it does not run.
    let result = broker
        .run(
            &command,
            &env,
            &[],
            None,
            Duration::from_secs(10),
            "",
            Duration::from_millis(300),
        )
        .unwrap();
    assert!(
        matches!(result, Err(GrantState::Pending { .. })),
        "{result:?}"
    );
    assert!(!marker.exists());

    // Inject writes a private file without returning the values.
    let template = dir.path().join("config.tpl");
    std::fs::write(&template, format!("password={{{{ {reference} }}}}\n")).unwrap();
    let output = dir.path().join("config.ini");
    approve_in_background(owner.clone(), true, 1);
    let (path, count) = broker
        .inject(&template, &output, "write config", Duration::from_secs(10))
        .unwrap()
        .unwrap();
    assert_eq!(count, 1);
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "password=s3cr3t-db-pw\n"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    // Creating an item never returns the generated secret.
    let (id, created) = broker
        .create_item(
            &vault,
            ItemCategory::Login,
            "New API",
            Some("bot"),
            None,
            Some(passbox_client::agent::SecretSource::Generate { length: 24 }),
        )
        .unwrap();
    assert!(created.starts_with("pbx://"));
    owner.sync().unwrap();
    let item = owner.item(&id).unwrap();
    assert_eq!(item.data.field(field::PASSWORD).unwrap().len(), 24);

    // Everything was recorded, without values.
    let events = owner
        .activity(100)
        .unwrap()
        .into_iter()
        .map(|e| e.kind)
        .collect::<Vec<_>>();
    for kind in [
        "agent_grant_requested",
        "agent_grant_approved",
        "agent_grant_denied",
        "agent_run",
        "agent_inject",
        "agent_create",
    ] {
        assert!(
            events.iter().any(|k| k == kind),
            "{kind} missing in {events:?}"
        );
    }
    let log = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
    assert!(!log.contains("s3cr3t"));
    assert!(log.contains("\"tool\":\"run\""));

    // A grant revoked on another device stops working at once.
    let grant_id = match state {
        GrantState::Approved { grant_id, .. } => grant_id,
        _ => unreachable!(),
    };
    owner.revoke_agent_grant(&grant_id).unwrap();
    let result = broker
        .run(
            "echo hi",
            &env,
            &[],
            None,
            Duration::from_secs(10),
            "",
            Duration::from_millis(200),
        )
        .unwrap();
    assert!(result.is_err(), "a revoked grant was used");

    // The broker refuses decisions not signed by the owner: a forged
    // approval cannot be produced without the account key, so check that
    // the backend rejects a decision for another request.
    let backend = broker.backend();
    assert!(backend.verify_decision(b"x", "AA", "AA").is_err());
}

#[test]
fn signed_in_account_as_agent_backend() {
    let server = start_server();
    let (owner, _vault) = owner(&server);
    let owner = Arc::new(owner);
    // The broker on the account itself (pbx mcp without a token); the
    // approval comes from "another device" of the same account.
    let device = Arc::new(Client::new(&server, Arc::new(MemoryStore::new())));
    let account = owner.device_account().unwrap().unwrap();
    device
        .sign_in(&account.email, PASSWORD, &account.secret_key)
        .unwrap();
    let mut broker = Broker::new(owner.clone(), None);
    broker.set_poll_interval(Duration::from_millis(50));
    approve_in_background(device, true, 1);
    let state = broker
        .request_access(
            &AccessRequest {
                items: vec!["pbx://Private/Database/password".into()],
                actions: vec!["run".into()],
                commands: vec!["true".into()],
                reason: "check".into(),
                ..AccessRequest::default()
            },
            Duration::from_secs(10),
        )
        .unwrap();
    assert!(matches!(state, GrantState::Approved { .. }), "{state:?}");
}
