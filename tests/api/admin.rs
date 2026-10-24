//! Instance administration: admin bootstrap, registration modes,
//! invitations, disabling accounts, mail outbox and the hash-chained admin
//! audit log.

use super::*;

impl Client {
    fn with_email(email: &str) -> Self {
        Self {
            email: email.to_owned(),
            ..Self::new()
        }
    }

    /// Registers with extra fields (`inviteToken`, `locale`) and returns the
    /// status and body of the first rejected request, or of the final one.
    async fn try_register(&self, server: &TestServer, extra: Value) -> (StatusCode, Value) {
        let (flow, request) = ClientRegistrationFlow::start(&self.auth_secret).unwrap();
        let mut start = json!({
            "accountId": self.account_id,
            "email": self.email,
            "registrationRequest": encoding::encode(&request),
        });
        merge(&mut start, &extra);
        let (status, body) = server
            .post("/api/v1/auth/register/start", None, start)
            .await;
        if status != StatusCode::OK {
            return (status, body);
        }
        let response = encoding::decode(body["registrationResponse"].as_str().unwrap()).unwrap();
        let upload = flow.finish(&response).unwrap();
        let (mut keyring, encrypted_account_key) =
            Keyring::create(&self.auk, &self.account_id).unwrap();
        let vault = keyring.create_vault(r#"{"name":"Private"}"#).unwrap();
        let mut finish = json!({
            "accountId": self.account_id,
            "email": self.email,
            "registrationUpload": encoding::encode(&upload),
            "kdfSalt": encoding::encode(&[7u8; 16]),
            "kdfParams": KdfParams::DEFAULT,
            "encryptedAccountKey": encrypted_account_key,
            "vault": {
                "id": vault.id,
                "encryptedKey": vault.encrypted_key,
                "encryptedMeta": vault.encrypted_meta,
            },
        });
        merge(&mut finish, &extra);
        server
            .post("/api/v1/auth/register/finish", None, finish)
            .await
    }
}

fn merge(target: &mut Value, extra: &Value) {
    if let (Some(target), Some(extra)) = (target.as_object_mut(), extra.as_object()) {
        for (key, value) in extra {
            target.insert(key.clone(), value.clone());
        }
    }
}

async fn outbox_count(server: &TestServer, recipient: &str, template: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM mail_outbox WHERE recipient = $1 AND template = $2")
        .bind(recipient)
        .bind(template)
        .fetch_one(server.db())
        .await
        .unwrap()
}

async fn set_settings(server: &TestServer, token: &str, changes: Value) -> Value {
    let (status, current) = server
        .request(Method::GET, "/api/v1/admin/settings", Some(token), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{current}");
    let mut settings = current["settings"].clone();
    merge(&mut settings, &changes);
    let (status, body) = server
        .request(
            Method::PUT,
            "/api/v1/admin/settings",
            Some(token),
            Some(settings),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

async fn get_meta(server: &TestServer) -> Value {
    let (status, meta) = server
        .request(Method::GET, "/api/v1/meta", None, None)
        .await;
    assert_eq!(status, StatusCode::OK);
    meta
}

pub async fn instance_administration(server: &TestServer) {
    let accounts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts")
        .fetch_one(server.db())
        .await
        .unwrap();
    assert_eq!(
        accounts, 0,
        "the admin tests need a fresh database (the first account becomes admin)"
    );

    // The first account becomes instance admin, later ones do not.
    let owner = Client::new();
    owner.register(server).await;
    let admin = owner.login(server).await;
    let (_, account) = server
        .request(Method::GET, "/api/v1/account", Some(&admin), None)
        .await;
    assert_eq!(account["instanceAdmin"], true);

    let member = Client::new();
    member.register(server).await;
    let member_token = member.login(server).await;
    let (_, account) = server
        .request(Method::GET, "/api/v1/account", Some(&member_token), None)
        .await;
    assert_eq!(account["instanceAdmin"], false);

    admin_endpoints_need_an_admin(server, &member_token).await;
    registration_modes(server, &admin).await;
    disable_and_enable(server, &admin, &member, &member_token).await;
    new_device_mails(server, &member).await;
    test_mail_and_outbox(server, &owner, &admin).await;
    admin_events_are_hash_chained(server, &admin).await;
}

async fn admin_endpoints_need_an_admin(server: &TestServer, member_token: &str) {
    for (method, uri) in [
        (Method::GET, "/api/v1/admin/settings"),
        (Method::PUT, "/api/v1/admin/settings"),
        (Method::GET, "/api/v1/admin/users"),
        (Method::GET, "/api/v1/admin/events"),
        (Method::GET, "/api/v1/admin/invites"),
        (Method::POST, "/api/v1/admin/invites"),
        (Method::POST, "/api/v1/admin/mail/test"),
        (
            Method::POST,
            "/api/v1/admin/users/0123456789abcdefghijklmn/disable",
        ),
    ] {
        let body = (method != Method::GET).then(|| json!({}));
        let (status, response) = server
            .request(method.clone(), uri, Some(member_token), body.clone())
            .await;
        // Some bodies are invalid as well; the admin check comes first.
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}: {response}");
        assert_eq!(response["error"], "forbidden");
        let (status, _) = server.request(method.clone(), uri, None, body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri}");
    }
}

async fn registration_modes(server: &TestServer, admin: &str) {
    let (status, settings) = server
        .request(Method::GET, "/api/v1/admin/settings", Some(admin), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(settings["settings"]["registration"], "open");
    assert_eq!(settings["mail"]["configured"], false);
    assert_eq!(settings["mail"]["transport"], "log");

    // Invalid settings are refused.
    let (status, _) = server
        .request(
            Method::PUT,
            "/api/v1/admin/settings",
            Some(admin),
            Some(json!({ "registration": "domains", "allowedDomains": [] })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Invite only.
    let body = set_settings(
        server,
        admin,
        json!({ "registration": "invite_only", "instanceName": "ACME Vault", "supportUrl": "https://help.example.com" }),
    )
    .await;
    assert_eq!(body["settings"]["registration"], "invite_only");
    let meta = get_meta(server).await;
    assert_eq!(meta["registration"], "invite_only");
    assert_eq!(meta["instanceName"], "ACME Vault");
    assert_eq!(meta["supportUrl"], "https://help.example.com");

    let stranger = Client::new();
    let (status, body) = stranger.try_register(server, json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "registration_closed");

    // An invitation lets exactly the invited email register, once.
    let invited = Client::new();
    let (status, invite) = server
        .post(
            "/api/v1/admin/invites",
            Some(admin),
            json!({ "email": invited.email, "linkBase": "https://vault.example.com" }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{invite}");
    assert_eq!(invite["status"], "pending");
    let link = invite["link"].as_str().unwrap();
    assert!(
        link.starts_with("https://vault.example.com/#/?invite="),
        "{link}"
    );
    let token = link
        .split("invite=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .to_owned();
    assert_eq!(outbox_count(server, &invited.email, "invitation").await, 1);

    let (status, body) = stranger
        .try_register(server, json!({ "inviteToken": token }))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "invitation_invalid");
    let (status, body) = invited
        .try_register(server, json!({ "inviteToken": token, "locale": "de" }))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let locale: String = sqlx::query_scalar("SELECT locale FROM accounts WHERE id = $1")
        .bind(&invited.account_id)
        .fetch_one(server.db())
        .await
        .unwrap();
    assert_eq!(locale, "de");
    let (_, invites) = server
        .request(Method::GET, "/api/v1/admin/invites", Some(admin), None)
        .await;
    assert_eq!(invites[0]["status"], "used");
    // Spent: the email has an account now.
    let again = Client::with_email(&invited.email);
    let (status, _) = again
        .try_register(server, json!({ "inviteToken": token }))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Revoked invitations no longer work.
    let revoked = Client::new();
    let (_, invite) = server
        .post(
            "/api/v1/admin/invites",
            Some(admin),
            json!({ "email": revoked.email }),
        )
        .await;
    assert_eq!(invite["link"], Value::Null, "no public URL and no linkBase");
    let (status, _) = server
        .request(
            Method::DELETE,
            &format!("/api/v1/admin/invites/{}", invite["id"].as_str().unwrap()),
            Some(admin),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Allowed domains.
    set_settings(
        server,
        admin,
        json!({ "registration": "domains", "allowedDomains": ["Allowed.example"] }),
    )
    .await;
    let meta = get_meta(server).await;
    assert_eq!(meta["registration"], "domains");
    assert_eq!(meta["allowedDomains"], json!(["allowed.example"]));
    let colleague = Client::with_email(&format!("{}@allowed.example", id::new_id().unwrap()));
    let (status, body) = colleague.try_register(server, json!({})).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let outsider = Client::with_email(&format!("{}@other.example", id::new_id().unwrap()));
    let (status, body) = outsider.try_register(server, json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "domain_not_allowed");

    // Emails from PASSBOX_ADMIN_EMAILS may always register and are admins.
    let env_admin = Client::with_email(&server.env_admin_email);
    let (status, body) = env_admin.try_register(server, json!({})).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let env_token = env_admin.login(server).await;
    let (status, _) = server
        .request(
            Method::GET,
            "/api/v1/admin/settings",
            Some(&env_token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    set_settings(server, admin, json!({ "registration": "open" })).await;
    assert_eq!(get_meta(server).await["registration"], "open");
    let (status, _) = outsider.try_register(server, json!({})).await;
    assert_eq!(status, StatusCode::CREATED);
}

async fn disable_and_enable(server: &TestServer, admin: &str, member: &Client, member_token: &str) {
    let query = member.email.split('@').next().unwrap();
    let (status, list) = server
        .request(
            Method::GET,
            &format!("/api/v1/admin/users?q={query}&limit=10"),
            Some(admin),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(list["total"], 1);
    let user = &list["users"][0];
    assert_eq!(user["email"], member.email.as_str());
    assert_eq!(user["status"], "active");
    assert_eq!(user["instanceAdmin"], false);
    assert_eq!(user["activeSessions"], 1);
    assert!(user["lastActivityAt"].as_i64().unwrap() > 0);
    let (_, all) = server
        .request(
            Method::GET,
            "/api/v1/admin/users?limit=2",
            Some(admin),
            None,
        )
        .await;
    assert_eq!(all["users"].as_array().unwrap().len(), 2);
    assert!(all["total"].as_i64().unwrap() >= 6);
    // LIKE wildcards are matched literally.
    let (_, none) = server
        .request(Method::GET, "/api/v1/admin/users?q=%25", Some(admin), None)
        .await;
    assert_eq!(none["total"], 0);

    let disable = format!("/api/v1/admin/users/{}/disable", member.account_id);
    let (status, _) = server.post(&disable, Some(admin), json!({})).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    // All sessions end immediately and the account cannot sign in.
    let (status, _) = server
        .request(Method::GET, "/api/v1/account", Some(member_token), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = member
        .try_login(server, &member.auth_secret, None, None)
        .await
        .err()
        .unwrap();
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "account_disabled");
    // A wrong password still reads as a wrong password.
    let (status, _) = member
        .try_login(server, b"wrong", None, None)
        .await
        .err()
        .unwrap();
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (_, list) = server
        .request(
            Method::GET,
            &format!("/api/v1/admin/users?q={query}"),
            Some(admin),
            None,
        )
        .await;
    assert_eq!(list["users"][0]["status"], "disabled");
    assert_eq!(list["users"][0]["activeSessions"], 0);

    // Admins cannot lock themselves out.
    let (_, me) = server
        .request(Method::GET, "/api/v1/account", Some(admin), None)
        .await;
    let (status, _) = server
        .post(
            &format!(
                "/api/v1/admin/users/{}/disable",
                me["accountId"].as_str().unwrap()
            ),
            Some(admin),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = server
        .post(
            "/api/v1/admin/users/0123456789abcdefghijklmn/disable",
            Some(admin),
            json!({}),
        )
        .await;
    assert!(status == StatusCode::NOT_FOUND || status == StatusCode::BAD_REQUEST);

    let (status, _) = server
        .post(
            &format!("/api/v1/admin/users/{}/enable", member.account_id),
            Some(admin),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    member
        .try_login(server, &member.auth_secret, None, None)
        .await
        .unwrap();
}

async fn new_device_mails(server: &TestServer, member: &Client) {
    // The first login right after registering is no new device.
    let newcomer = Client::new();
    newcomer.register(server).await;
    newcomer.login(server).await;
    assert_eq!(outbox_count(server, &newcomer.email, "new_device").await, 0);

    // `member` signed in before: a login without device token is reported,
    // one with a valid device token is not.
    let before = outbox_count(server, &member.email, "new_device").await;
    let login = member
        .try_login(server, &member.auth_secret, Some("10.9.0.1"), None)
        .await
        .unwrap();
    assert_eq!(
        outbox_count(server, &member.email, "new_device").await,
        before + 1
    );
    let params: String = sqlx::query_scalar(
        "SELECT params FROM mail_outbox WHERE recipient = $1 AND template = 'new_device' \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&member.email)
    .fetch_one(server.db())
    .await
    .unwrap();
    let params: Value = serde_json::from_str(&params).unwrap();
    assert_eq!(params["ip"], "10.9.0.1");
    assert_eq!(params["email"], member.email.as_str());

    let login = member
        .try_login(
            server,
            &member.auth_secret,
            Some("10.9.0.1"),
            Some(&login.device_token),
        )
        .await
        .unwrap();
    assert_eq!(
        outbox_count(server, &member.email, "new_device").await,
        before + 1
    );

    // The owner can turn the mail off.
    let (status, prefs) = server
        .request(
            Method::PUT,
            "/api/v1/account/preferences",
            Some(&login.token),
            Some(json!({ "notifyNewDevice": false, "locale": "de" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{prefs}");
    assert_eq!(prefs, json!({ "notifyNewDevice": false, "locale": "de" }));
    let (status, _) = server
        .request(
            Method::PUT,
            "/api/v1/account/preferences",
            Some(&login.token),
            Some(json!({ "locale": "fr" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    member
        .try_login(server, &member.auth_secret, Some("10.9.0.2"), None)
        .await
        .unwrap();
    assert_eq!(
        outbox_count(server, &member.email, "new_device").await,
        before + 1
    );
    let (_, prefs) = server
        .request(
            Method::PUT,
            "/api/v1/account/preferences",
            Some(&login.token),
            Some(json!({ "notifyNewDevice": true, "locale": "" })),
        )
        .await;
    assert_eq!(prefs, json!({ "notifyNewDevice": true, "locale": null }));
}

async fn test_mail_and_outbox(server: &TestServer, owner: &Client, admin: &str) {
    let (status, body) = server
        .post("/api/v1/admin/mail/test", Some(admin), json!({}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["to"], owner.email.as_str());
    assert_eq!(body["mailConfigured"], false);
    assert_eq!(outbox_count(server, &owner.email, "test").await, 1);
    let (status, _) = server
        .post(
            "/api/v1/admin/mail/test",
            Some(admin),
            json!({ "to": "not an email" }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Without SMTP the worker logs the mails and marks them as sent; their
    // parameters (which may hold invitation links) are deleted.
    let (_, settings) = server
        .request(Method::GET, "/api/v1/admin/settings", Some(admin), None)
        .await;
    assert!(settings["mail"]["pending"].as_i64().unwrap() >= 3);
    while server.state.mailer.process_due().await.unwrap() > 0 {}
    let (_, settings) = server
        .request(Method::GET, "/api/v1/admin/settings", Some(admin), None)
        .await;
    assert_eq!(settings["mail"]["pending"], 0);
    assert!(settings["mail"]["lastSentAt"].as_i64().unwrap() > 0);
    let leftover: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mail_outbox WHERE status = 'sent' AND params <> '{}'",
    )
    .fetch_one(server.db())
    .await
    .unwrap();
    assert_eq!(leftover, 0);
}

async fn admin_events_are_hash_chained(server: &TestServer, admin: &str) {
    let (status, body) = server
        .request(
            Method::GET,
            "/api/v1/admin/events?limit=500",
            Some(admin),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["chain"]["valid"], true, "{}", body["chain"]);
    let events = body["events"].as_array().unwrap();
    let actions: Vec<&str> = events
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    for action in [
        "instance_admin_bootstrap",
        "settings_updated",
        "invite_created",
        "invite_used",
        "invite_revoked",
        "user_disabled",
        "user_enabled",
        "test_mail_sent",
    ] {
        assert!(actions.contains(&action), "missing {action} in {actions:?}");
    }
    // Newest first, each linked to the one before.
    assert_eq!(actions[0], "test_mail_sent");
    for pair in events.windows(2) {
        assert_eq!(pair[0]["prevHash"], pair[1]["hash"]);
    }
    let disabled = events
        .iter()
        .find(|e| e["action"] == "user_disabled")
        .unwrap();
    assert_eq!(disabled["details"]["sessionsRevoked"], 1);

    // A changed row breaks the chain at that row.
    let seq = disabled["seq"].as_i64().unwrap();
    let original = disabled["details"].to_string();
    sqlx::query("UPDATE admin_events SET details = $1 WHERE seq = $2")
        .bind(r#"{"email":"someone-else@example.com"}"#)
        .bind(seq)
        .execute(server.db())
        .await
        .unwrap();
    let status = chain(server, admin).await;
    assert_eq!(status["valid"], false);
    assert_eq!(status["brokenAt"], seq);
    sqlx::query("UPDATE admin_events SET details = $1 WHERE seq = $2")
        .bind(&original)
        .bind(seq)
        .execute(server.db())
        .await
        .unwrap();
    assert_eq!(chain(server, admin).await["valid"], true);

    // So does a deleted row, even the newest one.
    let last: (i64, String, String) =
        sqlx::query_as("SELECT seq, id, hash FROM admin_events ORDER BY seq DESC LIMIT 1")
            .fetch_one(server.db())
            .await
            .unwrap();
    let row: (String, String, String, String, String, String, i64, String) = sqlx::query_as(
        "SELECT actor_id, actor_email, action, target, details, ip, created_at, prev_hash \
         FROM admin_events WHERE seq = $1",
    )
    .bind(last.0)
    .fetch_one(server.db())
    .await
    .unwrap();
    sqlx::query("DELETE FROM admin_events WHERE seq = $1")
        .bind(last.0)
        .execute(server.db())
        .await
        .unwrap();
    let status = chain(server, admin).await;
    assert_eq!(status["valid"], false);
    assert_eq!(status["brokenAt"], last.0);
    sqlx::query(
        "INSERT INTO admin_events (seq, id, actor_id, actor_email, action, target, details, ip, \
         created_at, prev_hash, hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(last.0)
    .bind(&last.1)
    .bind(&row.0)
    .bind(&row.1)
    .bind(&row.2)
    .bind(&row.3)
    .bind(&row.4)
    .bind(&row.5)
    .bind(row.6)
    .bind(&row.7)
    .bind(&last.2)
    .execute(server.db())
    .await
    .unwrap();
    assert_eq!(chain(server, admin).await["valid"], true);
}

async fn chain(server: &TestServer, admin: &str) -> Value {
    let (_, body) = server
        .request(
            Method::GET,
            "/api/v1/admin/events?limit=1",
            Some(admin),
            None,
        )
        .await;
    body["chain"].clone()
}
