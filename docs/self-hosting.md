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
| `PASSBOX_LOG_FORMAT` | `pretty` | `pretty` or `json` |
| `RUST_LOG` | `info` | Log level, for example `debug` or `passbox_server=debug` |

Migrations run automatically at startup.

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
- **Two-factor sign-in:** users can add an authenticator app (TOTP, RFC 6238, ±1 step of 30 seconds, each code accepted once), security keys or passkeys (WebAuthn, ES256 and Ed25519) and get 10 one-time recovery codes. With a second factor, a login stops after the password with a 5-minute challenge; wrong factors are limited to 5 per challenge, 10 per account and 100 per IP in 15 minutes. "Remember this device" skips the step for 30 days on that device (stored with its device token; a master password change or turning two-factor sign-in off forgets it). Adding factors needs a login in the last 10 minutes, turning it off needs a second factor or recovery code. TOTP secrets are encrypted with a server key (`two_factor_key` in `server_secrets`), recovery codes are stored as SHA-256 hashes. Security keys are bound to the host name the web vault is served from (the WebAuthn RP ID): moving the vault to another domain makes them unusable, so users should keep their recovery codes. They need https (or `localhost`).
- **Sessions:** users see their signed-in devices and can sign them out. Changing the master password signs out every other device.
- **Activity log:** sign-ins (with or without a second factor), failed sign-ins and second factors, sign-outs, revoked sessions, password changes, two-factor changes and used recovery codes are recorded per account and visible to the account owner.
