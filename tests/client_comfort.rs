//! Moving items between vaults, the archive, attachments and item types
//! against an in-process server.

use std::sync::Arc;

use passbox_client::{
    Client, FieldType, ItemCategory, ItemData, MemoryStore, Store, field, format,
};

fn start_server() -> String {
    passbox_server::testing::spawn_server(|_, _| {})
}

const PASSWORD: &str = "correct horse battery staple";

#[test]
fn move_archive_attachments_and_types() {
    let server = start_server();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let client = Client::new(&server, store.clone());
    let email = format!("{}@example.com", passbox_core::id::new_id().unwrap());
    let secret_key = client.sign_up(&email, PASSWORD).unwrap();
    let personal = client.vaults().unwrap().remove(0).id;
    // A second device of the same account.
    let phone = Client::new(&server, Arc::new(MemoryStore::new()));
    phone.sign_in(&email, PASSWORD, &secret_key).unwrap();

    // A Wi-Fi item with history and an attachment.
    let mut wifi = ItemData::new(ItemCategory::Wifi, "Home");
    wifi.set_field(field::WIFI_SSID, "", FieldType::Text, "Home net");
    wifi.set_field(field::PASSWORD, "", FieldType::Concealed, "first");
    let id = client.create_item(&personal, &wifi).unwrap();
    wifi.set_field(field::PASSWORD, "", FieldType::Concealed, "second");
    client.update_item(&id, &wifi).unwrap();
    let attachment = client
        .add_attachment(
            &id,
            "router.pdf",
            "application/pdf",
            b"%PDF-1.7 router manual",
        )
        .unwrap();
    assert_eq!(attachment.size, 22);
    let item = client.item(&id).unwrap();
    assert_eq!(item.data.attachments().len(), 1);
    // An editor working on an older copy cannot drop the attachment.
    client.update_item(&id, &wifi).unwrap();
    assert_eq!(client.item(&id).unwrap().data.attachments().len(), 1);
    assert_eq!(
        client.attachment_data(&id, &attachment.id).unwrap(),
        b"%PDF-1.7 router manual"
    );
    let created_at = client.item(&id).unwrap().created_at;

    // Move it into a shared vault: same ID, history and attachment.
    let org = client.create_team("Acme").unwrap();
    let shared = client.create_shared_vault(&org, "Ops").unwrap();
    phone.sync().unwrap();
    assert_eq!(phone.item(&id).unwrap().vault_id, personal);
    let outcome = client
        .move_items(&[id.clone(), id.clone()], &shared)
        .unwrap();
    assert_eq!(outcome.moved, std::slice::from_ref(&id));
    let moved = client.item(&id).unwrap();
    assert_eq!(moved.vault_id, shared);
    assert_eq!(moved.created_at, created_at);
    assert_eq!(moved.data.category, ItemCategory::Wifi);
    let history = client.item_history(&id).unwrap();
    assert!(history.len() >= 3, "{history:?}");
    assert!(history.iter().all(|v| v.data.is_some()));
    assert_eq!(
        client.attachment_data(&id, &attachment.id).unwrap(),
        b"%PDF-1.7 router manual"
    );
    assert_eq!(
        client
            .move_items(std::slice::from_ref(&id), &shared)
            .unwrap()
            .skipped,
        std::slice::from_ref(&id)
    );
    // The other device sees the item in its new vault only.
    phone.sync().unwrap();
    let on_phone = phone.item(&id).unwrap();
    assert_eq!(on_phone.vault_id, shared);
    assert_eq!(
        phone.items().unwrap().iter().filter(|i| i.id == id).count(),
        1
    );
    // And back again.
    client
        .move_items(std::slice::from_ref(&id), &personal)
        .unwrap();
    phone.sync().unwrap();
    assert_eq!(phone.item(&id).unwrap().vault_id, personal);

    // Archive: hidden from items, kept in the vault.
    client.archive_item(&id).unwrap();
    assert!(client.items().unwrap().iter().all(|i| i.id != id));
    assert_eq!(client.archived_items().unwrap()[0].id, id);
    let mut edited = client.item(&id).unwrap().data;
    edited.set_archived_at(None);
    edited.title = "Home (old)".into();
    client.update_item(&id, &edited).unwrap();
    assert!(
        client.item(&id).unwrap().data.archived_at().is_some(),
        "edits keep the archive state"
    );
    client.unarchive_item(&id).unwrap();
    assert!(client.items().unwrap().iter().any(|i| i.id == id));

    // Removing the attachment deletes the file.
    client.remove_attachment(&id, &attachment.id).unwrap();
    assert!(client.item(&id).unwrap().data.attachments().is_empty());
    assert!(client.attachment_data(&id, &attachment.id).is_err());

    // An app that only knows the old categories saves "other": the
    // category is kept.
    let mut old_app = client.item(&id).unwrap().data;
    old_app.category = ItemCategory::Other;
    old_app.extra.remove("category");
    client.update_item(&id, &old_app).unwrap();
    assert_eq!(client.item(&id).unwrap().data.category, ItemCategory::Wifi);

    // A category from a future version survives an edit here.
    let mut future: ItemData = serde_json::from_str(
        r#"{"v":1,"category":"spaceship","title":"Enterprise","fields":[{"id":"d","label":"Launch","type":"text","value":"2263-01-01","format":"date"}]}"#,
    )
    .unwrap();
    let future_id = client.create_item(&personal, &future).unwrap();
    future = client.item(&future_id).unwrap().data;
    future.title = "NCC-1701".into();
    client.update_item(&future_id, &future).unwrap();
    let saved = client.item(&future_id).unwrap().data;
    assert_eq!(saved.category_name(), "spaceship");
    assert_eq!(saved.fields[0].format.as_deref(), Some(format::DATE));
}
