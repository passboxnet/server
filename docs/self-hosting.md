# Self-hosting

Passbox is one binary (`passbox-server`) that serves the API and the web client. The Docker image contains both.

## Quick start

```sh
docker compose -f deploy/docker-compose.yml up -d
```

The vault is then available at `http://localhost:8080`. Browsers only allow the cryptography and clipboard APIs Passbox needs on HTTPS (or `localhost`), so put a reverse proxy with TLS in front of it before you use it from other machines.

## Configuration

Every option can be set as a command-line flag or an environment variable.

| Variable | Default | Description |
| --- | --- | --- |
| `PASSBOX_BIND` | `0.0.0.0:8080` | Address and port to listen on |
| `PASSBOX_DATABASE_URL` | `sqlite://passbox.db?mode=rwc` | `sqlite://<path>?mode=rwc` or `postgres://user:password@host/database` |
| `PASSBOX_WEB_DIR` | unset | Directory with the built web client; the Docker image sets it |
| `PASSBOX_TRUST_PROXY` | `false` | Take the client IP from `X-Forwarded-For`. Enable only behind a reverse proxy that sets it; client IPs are used for rate limiting and shown in the activity log and device list |
| `PASSBOX_AUTH_RATE_LIMIT` | `60` | Sign-in and registration requests per client IP and minute. Raise it only for test servers that many clients share |
| `PASSBOX_SMTP_URL` | unset | SMTP server for outgoing mail, see [Email](#email). Without it, mails are only written to the log |
| `PASSBOX_MAIL_FROM` | unset | Sender, for example `Passbox <passbox@example.com>`. Required with `PASSBOX_SMTP_URL` |
| `PASSBOX_PUBLIC_URL` | unset | Address users open Passbox at, for example `https://passbox.example.com`. Used for links in mails; required for [single sign-on](#single-sign-on-sso) (redirect URI) |
| `PASSBOX_SSO_ALLOW_HTTP_LOOPBACK` | unset | `1` allows `http://` identity providers on `localhost`/`127.0.0.1`/`[::1]`, for development only |
| `PASSBOX_ADMIN_EMAILS` | unset | Comma-separated emails of accounts that are always instance admins, see [Administration](#administration) |
| `PASSBOX_ICONS` | `on` | `on` lets signed-in apps load website icons through the server, `off` turns this off. See [Website icons](#website-icons) |
| `PASSBOX_BREACH_PROXY` | `on` | `on` lets signed-in apps check passwords against Have I Been Pwned through the server (k-anonymity: only 5-character hash prefixes), so Have I Been Pwned never sees users' IP addresses; `off` turns the endpoint off. See [Breach checks and email monitoring](#breach-checks-and-email-monitoring) |
| `PASSBOX_HIBP_API_KEY` | – | Have I Been Pwned API key ([subscription](https://haveibeenpwned.com/API/Key)). Turns on email breach monitoring: users confirm addresses by code, the server checks them and mails new breaches |
| `PASSBOX_HIBP_CHECK_HOURS` | `24` | Hours between checks of each monitored address |
| `PASSBOX_HIBP_RPM` | `10` | Breached-account requests per minute your subscription allows; the server paces its checks to it |
| `PASSBOX_WEBHOOK_ALLOW_PRIVATE` | `false` | Allow organization webhooks to private and loopback addresses (and plain HTTP), for a SIEM in the same network. See [Administration](architecture/administration.md) |
| `PASSBOX_LOG_FORMAT` | `pretty` | `pretty` or `json` |
| `RUST_LOG` | `info` | Log level, for example `debug` or `passbox_server=debug` |

Migrations run automatically at startup.

## Administration

The **first account created on a fresh server becomes its instance admin.** Create your own account right after starting the server, before you share its address. On servers upgraded from a version without administration, the oldest account becomes admin. Accounts whose email is listed in `PASSBOX_ADMIN_EMAILS` are admins as well, and may always register, whatever the registration mode is; use it to recover admin access or to name several admins.

Admins see **Administration** in the web app's sidebar (and in Settings). There they can:

- name the server (shown in mails and the app) and set a help address (`https://…` or `mailto:…`) that the sign-in screen and Settings link to,
- choose who can create an account (see below) and the language of mails for accounts that have not chosen one,
- require stronger master passwords: a minimum strength (strong or very strong) and length (12 or more). The server never sees passwords, so clients enforce the policy; they get it from `/api/v1/meta`,
- see the mail status and send a test mail,
- invite people, list accounts with their last activity, and **disable** accounts: a disabled account is signed out on every device at once, cannot sign in (`account_disabled`) and keeps its data until it is enabled again,
- read the **administration log**. Every change is recorded with who made it, when and from which IP. Each row contains the SHA-256 hash of its content and of the previous row, and the server checks the whole chain whenever the log is shown, so a changed or deleted row is reported ("Log was changed or shortened"). Someone with write access to the database could still rewrite the whole chain; keep backups if you need an independent record.

Vault contents stay end-to-end encrypted: admins cannot read anyone's items.

### Registration modes

| Mode | Who can create an account |
| --- | --- |
| `open` (default) | Anyone who can reach the server |
| `invite_only` | Only people with an invitation. The web app hides "Create account" and explains that an invitation is needed |
| `domains` | Emails of the allowed domains (for example `example.com`), plus invited people |

Registrations that are not allowed fail with `registration_closed`, `domain_not_allowed` or `invitation_invalid`. `/api/v1/meta` publishes the mode (and the allowed domains in `domains` mode), so clients can adapt their sign-up screen.

An invitation is a link `https://<server>/#/?invite=<token>&email=<email>` that is mailed to the person and shown to the admin to pass on (useful while mail is not set up). It is valid for 7 days, works once and only for that email. The server stores only a hash of the token.

## Email

Passbox sends invitations and security notices: sign-in from a new device (users can turn it off under Settings → Notifications), master password changed, two-step sign-in changes, a new recovery code, an account recovery, organization recovery requests and their outcome (to the member and the recovery admins), and emergency access invitations, requests, approvals, denials and use. Mails are written in English or German (formal "Sie"), as plain text and simple HTML, in the language the user chose in Passbox or else the server's default language.

Configure an SMTP server with a URL:

| Example | Connection |
| --- | --- |
| `smtps://user:password@mail.example.com:465` | TLS from the start (port 465) |
| `smtp://user:password@mail.example.com:587?tls=required` | STARTTLS, required |
| `smtp://user:password@mail.example.com:587?tls=opportunistic` | STARTTLS if offered (not recommended) |
| `smtp://localhost:25` | No encryption, for a relay on the same host only |

Percent-encode special characters in the user name and password (`@` → `%40`). TLS uses rustls and the operating system's certificate store (the Docker image includes the usual CA certificates).

```sh
PASSBOX_SMTP_URL='smtps://passbox%40example.com:app-password@smtp.example.com:465'
PASSBOX_MAIL_FROM='Passbox <passbox@example.com>'
PASSBOX_PUBLIC_URL='https://passbox.example.com'
```

An invalid URL or sender stops the server at startup. Without `PASSBOX_SMTP_URL`, mails are written to the server log instead (development mode) and the administration says that mail is not set up. Use **Send test email** in the administration to check the configuration.

Mails go through a queue in the database (`mail_outbox`): requests never wait for the mail server, and mails survive restarts. A background task sends them and retries temporary failures with growing delays (30 seconds up to an hour, 10 attempts, about 4 hours in total); permanent rejections (5xx) are not retried. The administration shows waiting and failed mails and the last error. Sent and failed mails are deleted after 30 days, and the parameters of a mail (which can contain invitation links) are deleted as soon as it is sent. Several server processes can share one database; each mail is sent once.

## Cross-origin requests (CORS)

The API answers cross-origin requests from any origin, so the [desktop app](desktop.md) (origins such as `tauri://localhost` and `http://tauri.localhost`) and web clients hosted elsewhere can use your server. This is safe because Passbox authenticates every request with a bearer token in the `Authorization` header and never uses cookies: a foreign page cannot act on behalf of a user without already holding their session token.

The server sends:

| Header | Value |
| --- | --- |
| `Access-Control-Allow-Origin` | `*` |
| `Access-Control-Allow-Methods` | `GET, POST, PUT, DELETE` |
| `Access-Control-Allow-Headers` | `authorization, content-type` |
| `Access-Control-Max-Age` | `3600` |

`Access-Control-Allow-Credentials` is never sent. If your reverse proxy adds its own CORS headers, remove them so they do not conflict with these.

## Website icons

Apps show the icons (favicons) of the websites in a vault. So that the user's devices never contact those websites, they load the icons through their own server: `GET /api/v1/icons/{domain}`. The server fetches `https://{domain}/apple-touch-icon.png`, `/favicon.ico` or the icon linked from the homepage and caches the result in memory (7 days, "no icon" for a day).

**Privacy:** with icons on, the server learns which domains are in its users' vaults (the vault contents stay encrypted), and the websites see requests from the server's IP address. Turn it off with `PASSBOX_ICONS=off` if that is not acceptable; `/api/v1/meta` then reports `"icons": false` and the apps show monograms. Users can also turn icons off in their apps ("Website-Icons anzeigen").

**Outbound connections:** the server needs HTTPS access to the internet for icons. Requests do not use a proxy (`HTTPS_PROXY` is ignored), go only to port 443 of public addresses (the server resolves the name itself and refuses loopback, private, link-local, multicast, unique-local and other special addresses, also after redirects), follow at most 3 redirects, time out after 3 seconds and read at most 200 KB. Only PNG, ICO, JPEG, GIF and WebP images are passed on; cookies are neither stored nor forwarded. Each session may load 600 icons per minute.

## Backups

Back up the database. Everything in it except the server secrets is encrypted by the clients, but treat backups as sensitive anyway.

- **SQLite:** use `sqlite3 passbox.db ".backup backup.db"` while the server runs (the database uses WAL mode, so copying the file alone is not enough).
- **PostgreSQL:** use `pg_dump` as usual.

Losing the `server_secrets` table invalidates all logins: users cannot sign in anymore, although their data stays intact. Keep it in your backups.

## Security behavior

- **Security headers:** every response carries a Content Security Policy (no framing, scripts only from the server plus WebAssembly), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, a restrictive `Permissions-Policy` and `Strict-Transport-Security` (effective once served over HTTPS). API responses are `Cache-Control: no-store`.
- **Rate limiting:** authentication endpoints accept 60 requests per minute and IP. Failed logins are counted per 15-minute window:
  - Devices that signed in successfully before present a **device token** and are exempt from the per-email limits. Each device token has its own limit of 10 failures.
  - Other logins are refused after 10 failures for the same email from the same IP, or 50 failures for the email from all IPs together (a backstop against distributed guessing).
  - Every IP is refused after 100 failures, with or without device token.

  So someone who knows a user's email cannot lock the user out of their signed-in devices; at most new devices have to wait. Limits are kept in memory per server process and answered with `429`, `Retry-After` and `details.retryAfterSeconds` (the remaining time of the window).
- **Device tokens:** every successful login issues a new random device token and invalidates the one the login was started with. The server stores only SHA-256 hashes. A device token grants no access by itself; it only lifts the per-email lockout. It survives logout, locking and signing out a session from the device list, expires after a year, and at most 50 are kept per account. Changing the master password invalidates the device tokens of all other devices. Clients delete their token when the user signs out of the account.
- **Two-factor sign-in:** users can add an authenticator app (TOTP, RFC 6238, ±1 step of 30 seconds, each code accepted once), security keys or passkeys (WebAuthn, ES256 and Ed25519) and get 10 one-time recovery codes. With a second factor, a login stops after the password with a 5-minute challenge; wrong factors are limited to 5 per challenge, 10 per account and 100 per IP in 15 minutes. "Remember this device" skips the step for 30 days on that device (stored with its device token; a master password change or turning two-factor sign-in off forgets it). Adding factors needs a login in the last 10 minutes, turning it off needs a second factor or recovery code. TOTP secrets are encrypted with a server key (`two_factor_key` in `server_secrets`), recovery codes are stored as SHA-256 hashes. Security keys are bound to the host name the web vault is served from (the WebAuthn RP ID): moving the vault to another domain makes them unusable, so users should keep their recovery codes. They need https (or `localhost`).
- **Account recovery:** see [recovery.md](architecture/recovery.md). A recovery (by recovery code or through an organization) sets a new master password and a new Secret Key, signs out every device, deletes all device tokens and mails the account. Recovery-code logins share the per-IP authentication limit and are refused after 10 failures per email and IP, 20 per email and 100 per IP in 15 minutes; with two-factor sign-in the second factor is required too. Organization recovery requests are limited to 10 per IP and 3 per email per hour and expire after 48 hours; unknown emails get the same answer as known ones. Recovery tokens are single use and valid for 15 minutes.
- **Emergency access:** the server releases the sealed vault keys only after the waiting period the owner chose (1–30 days, default 7) or the owner's approval; the owner can deny until then. A server operator who changes the clock or the database can shorten the waiting period, but cannot read the vaults without the trusted person's private key. At most 20 contacts and 20 invitations per hour per account.
- **Device codes:** adding a device with a code needs approval on the signed-in device; codes are valid for 10 minutes, claims are limited to 10 per IP and minute and 5 open codes per account. Only the email and the Secret Key move; the master password is never transferred.
- **Item history:** every change of an item keeps the previous encrypted version on the server (the newest 20 per item); a permanent deletion removes them. They are encrypted like the item itself.
- **Sessions:** users see their signed-in devices and can sign them out. Changing the master password signs out every other device.
- **Activity log:** sign-ins (with or without a second factor), failed sign-ins and second factors, sign-outs, revoked sessions, password changes, two-factor changes, used recovery codes, account recoveries and emergency access events are recorded per account and visible to the account owner.
- **Single sign-on:** see [Single sign-on (SSO)](#single-sign-on-sso). Flows, tickets, proofs, device requests and SCIM tokens are random 256-bit values stored as SHA-256 hashes; client secrets are encrypted with a server key (`sso_key` in `server_secrets`). Deprovisioning through SCIM ends all sessions of the person immediately.

## Single sign-on (SSO)

Team organizations can sign in their members through an OpenID Connect identity provider and provision them with SCIM 2.0. Everything is included in every installation. How it works and what it protects: [docs/architecture/sso.md](architecture/sso.md). SAML is not supported ([ADR 0005](adr/0005-saml-deferred.md)); use your provider's OpenID Connect support (ADFS 2016 and later have it).

**Before you start:** set `PASSBOX_PUBLIC_URL` to the address users open Passbox at (`https://passbox.example.com`). The identity provider sends users back to `{PASSBOX_PUBLIC_URL}/api/v1/sso/callback`, and SCIM is served at `{PASSBOX_PUBLIC_URL}/api/v1/scim/v2`. The server must reach the provider over https (outbound). For a development provider on the same machine over plain http, set `PASSBOX_SSO_ALLOW_HTTP_LOOPBACK=1` (only `localhost`, `127.0.0.1` and `[::1]`; never in production).

**In Passbox:** open the team (Family & team → your team) → Settings → **Single sign-on → Set up**, as owner or admin:

1. Choose the provider, enter a name for the sign-in button, the **issuer URL**, the **client ID** and the **client secret**, and the **email domains** of your organization (one per line). Copy the **redirect URI** into the provider's app registration.
2. **Check connection** reads the provider's discovery document and keys. Save with **Single sign-on is on**.
3. **Test sign-in** opens the provider in a popup and shows the claims it sent and whether a real sign-in would work, without signing you in.
4. Optional: **Require single sign-on** (members must sign in through the provider; owners and admins keep the master password as a fallback) and **Allow unlocking with single sign-on** (members can trust their devices and unlock without the master password; read the trade-off in [sso.md](architecture/sso.md#threat-model-of-sso-unlock) first).

Members still need their master password and, on a new device, the Secret Key, unless the device is trusted. Users sign in with **Use single sign-on (SSO)** on the sign-in page, or the option appears when they type an email of a configured domain.

### Microsoft Entra ID

1. Entra admin center → App registrations → **New registration**: name "Passbox", single tenant, redirect URI type **Web** = the redirect URI from Passbox.
2. Certificates & secrets → **New client secret**; copy the value (not the ID).
3. Token configuration → **Add optional claim** → ID token → `email`. Optional: **Add groups claim** (shows in the test result).
4. In Passbox: issuer `https://login.microsoftonline.com/<tenant-id>/v2.0` (the tenant ID from Overview; never `common` or `organizations`), client ID = Application (client) ID. Turn **Require a verified email** off under Advanced: Entra ID does not send `email_verified`, and the email claim is only as trustworthy as your tenant's directory (Passbox links accounts by the stable `sub` after the first sign-in).
5. Users must be assigned to the app if "Assignment required" is on (Enterprise applications → Passbox → Properties).

### Google Workspace

1. Google Cloud console → APIs & Services → OAuth consent screen: **Internal**. Credentials → **Create OAuth client ID** → Web application; authorized redirect URI = the redirect URI from Passbox.
2. In Passbox: issuer `https://accounts.google.com`, client ID and secret from the credential. Google sends `email_verified`; keep the setting on. Google does not send groups in ID tokens.

### Okta

1. Applications → **Create App Integration** → OIDC, Web Application; sign-in redirect URI = the redirect URI from Passbox; grant type Authorization Code; assign the people or groups.
2. In Passbox: issuer `https://<your-org>.okta.com` (org authorization server) or `https://<your-org>.okta.com/oauth2/default` (custom authorization server; it must match the `iss` Okta puts into tokens), client ID and secret.
3. Groups (optional): Sign On → OpenID Connect ID Token → Groups claim filter `groups` matches `.*`.

### Keycloak

1. Realm → Clients → **Create client**: OpenID Connect, client ID `passbox`, **Client authentication on**, Standard flow on; valid redirect URI = the redirect URI from Passbox. Advanced → Proof Key for Code Exchange: S256.
2. Credentials tab: copy the client secret.
3. In Passbox: issuer `https://<host>/realms/<realm>`. Groups (optional): client scopes → add a "Group Membership" mapper with token claim name `groups`, full group path off.

### authentik

1. Applications → Providers → **Create** → OAuth2/OpenID Provider: client type Confidential, redirect URI (strict) = the redirect URI from Passbox, signing key: your certificate (RS256). Then create an Application for it with slug `passbox`.
2. In Passbox: issuer `https://<host>/application/o/passbox/` (with the trailing slash, as authentik shows it), client ID and secret from the provider. authentik sends `email_verified` and `groups` with the default scope mappings.

### ZITADEL

1. Project → **New application** → Web, authentication method **Code** (or PKCE for a public client), redirect URI = the redirect URI from Passbox.
2. In Passbox: issuer `https://<instance>.zitadel.cloud` (or your own domain), client ID and secret. Choose client authentication "Client secret (HTTP Basic)" for the Code method, or "None" for PKCE. Roles appear under `urn:zitadel:iam:org:project:roles` if you enable "Assert roles on authentication"; set the groups claim to that name to see them in the test.

### SCIM provisioning

In the team's Single sign-on page, **Provisioning (SCIM)** shows the base URL. **Create token** (owner or admin, sign-in within the last 10 minutes) shows a token once; enter both in your provider. Tokens expire after the chosen 1–730 days; create a new one before that and revoke the old one.

- **Microsoft Entra ID:** Enterprise applications → (a non-gallery app) → Provisioning → Automatic; Tenant URL = base URL, Secret token = the token; Test connection; mappings: `userPrincipalName` or `mail` → `userName`, `Switch([IsSoftDeleted], , "False", "True", "True", "False")` → `active` (the default), keep emails and names. Entra deprovisions with `active: false` and later `DELETE`.
- **Okta:** in the OIDC app (or a SCIM 2.0 app) → General → enable SCIM provisioning; base URL, authentication "HTTP Header" with the token; unique identifier `userName`; enable Push New Users, Push Profile Updates, Push Groups and Deactivate Users.
- **Keycloak, authentik, ZITADEL, JumpCloud, OneLogin:** use their SCIM 2.0 outbound connector or plugin with the base URL and bearer token.

What provisioning does: new people get an invitation mail (or join on their first SSO sign-in); existing members are linked. People who joined are **pending confirmation** until an owner or admin confirms them in the list (an admin's unlocked Passbox seals the organization key for them; the server cannot). Deactivating someone suspends the membership and immediately ends all their sessions and trusted devices; reactivating restores the membership. Directory groups are shown, but adding their members to Passbox groups is done by an admin.

## Breach checks and email monitoring

Passbox's security check (see [security-analysis.md](architecture/security-analysis.md)) can use Have I Been Pwned in two ways; both go through your server.

**Leaked passwords** (`PASSBOX_BREACH_PROXY`, on by default). Apps send the first 5 characters of a password's SHA-1 hash to `GET /api/v1/breach/range/{prefix}`; the server fetches the padded range from `api.pwnedpasswords.com` (free, no key) and returns it, and the app compares locally. Have I Been Pwned sees your server's IP address, never the user's; your server sees hash prefixes, each shared by hundreds of passwords, never a password. Responses are cached in memory for a day; each account may fetch 3000 prefixes per hour. With the proxy off, apps fall back to asking Have I Been Pwned directly (users can also choose "Direkt" or "Über Passbox-Server" in the settings of the security check).

**Email breach monitoring** (`PASSBOX_HIBP_API_KEY`, off without a key). Users add email addresses in the security check and confirm each with a 6-digit code mailed to it (so nobody can monitor someone else's address). The server stores only the address and the breach list (table `breach_monitor_emails`, `breach_monitor_results`), sends the address to `haveibeenpwned.com/api/v3/breachedaccount/…` with your key, re-checks every `PASSBOX_HIBP_CHECK_HOURS` (paced to `PASSBOX_HIBP_RPM`) and mails the account owner when a new breach appears. Removing an address deletes its results; deleting the account deletes everything. Mail must be configured (`PASSBOX_SMTP_URL`) for codes and alerts to arrive. Self-hosted instances get the full feature with their own key; Have I Been Pwned's terms apply to the key holder.
