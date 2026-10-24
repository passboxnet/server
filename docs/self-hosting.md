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
