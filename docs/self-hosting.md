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
| `PASSBOX_SMTP_URL` | unset | SMTP server for outgoing mail, see [Email](#email). Without it, mails are only written to the log |
| `PASSBOX_MAIL_FROM` | unset | Sender, for example `Passbox <passbox@example.com>`. Required with `PASSBOX_SMTP_URL` |
| `PASSBOX_PUBLIC_URL` | unset | Address users open Passbox at, for example `https://passbox.example.com`. Used for links in mails |
| `PASSBOX_ADMIN_EMAILS` | unset | Comma-separated emails of accounts that are always instance admins, see [Administration](#administration) |
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

Passbox sends invitations and security notices: sign-in from a new device (users can turn it off under Settings → Notifications), master password changed, and later two-step sign-in, emergency access and recovery notices. Mails are written in English or German (formal "Sie"), as plain text and simple HTML, in the language the user chose in Passbox or else the server's default language.

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
- **Sessions:** users see their signed-in devices and can sign them out. Changing the master password signs out every other device.
- **Activity log:** sign-ins, failed sign-ins, sign-outs, revoked sessions and password changes are recorded per account and visible to the account owner.
