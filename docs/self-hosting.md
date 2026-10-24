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
- **Rate limiting:** authentication endpoints accept 60 requests per minute and IP. After 10 failed logins for one email within 15 minutes, further logins for that email are refused for the rest of the window (100 failures per IP). Limits are kept in memory per server process and answered with `429` and `Retry-After`.
- **Sessions:** users see their signed-in devices and can sign them out. Changing the master password signs out every other device.
- **Activity log:** sign-ins, failed sign-ins, sign-outs, revoked sessions and password changes are recorded per account and visible to the account owner.
