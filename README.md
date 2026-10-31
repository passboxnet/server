# Passbox server

The server of [Passbox](https://passbox.net), an open-source password manager with passkeys, a built-in authenticator and single sign-on. It stores and syncs end-to-end encrypted data, never sees a key, and serves the web vault. Rust (axum) and PostgreSQL.

> **Status: early development.** The cryptographic design is a draft and has not been audited. Do not store real secrets in Passbox yet.

## Self-hosting

```sh
cd deploy/compose
cp .env.example .env   # domain, passwords, backup key
docker compose up -d
```

This starts Passbox with PostgreSQL, Caddy for HTTPS and encrypted daily backups. The image `ghcr.io/passboxnet/server` (`linux/amd64` and `linux/arm64`, signed with cosign) serves the API and the web vault. Every feature is included. See [docs/self-hosting.md](docs/self-hosting.md).

## Development

```sh
PASSBOX_DATABASE_URL=postgres://postgres:postgres@localhost:5432/passbox cargo run   # http://localhost:8080
PASSBOX_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres cargo test
```

The cryptographic core and the Rust client come from [passboxnet/core](https://github.com/passboxnet/core) (git dependency on a release tag). `tests/client_*.rs` run the Rust client against this server. For the web vault run [passboxnet/web](https://github.com/passboxnet/web) next to it. The queries are checked against the committed `.sqlx` cache (`SQLX_OFFLINE=true`).

The API is described in [docs/api](docs/api).

## Image

A tag `vX.Y.Z` builds the image for both architectures, scans it with Trivy, signs it with cosign and attaches an SBOM and SLSA provenance. The web vault inside is the released archive of passboxnet/web at `WEB_VERSION` in the [Dockerfile](Dockerfile), checked against `WEB_SHA256`.

## Repositories

| Repository | Contents |
| --- | --- |
| [passboxnet/core](https://github.com/passboxnet/core) | Cryptographic core (Rust), WebAssembly build, Rust client, Swift/Kotlin bindings, AI gateway, shared TypeScript packages (`@passbox/*`) |
| [passboxnet/server](https://github.com/passboxnet/server) | Server (API, sync, web vault hosting), container image, Docker Compose for self-hosting |
| [passboxnet/web](https://github.com/passboxnet/web) | Web vault (React, Vite) and browser end-to-end tests |
| [passboxnet/browser-extension](https://github.com/passboxnet/browser-extension) | Browser extension with autofill and passkeys |
| [passboxnet/desktop](https://github.com/passboxnet/desktop) | Desktop app for Windows, macOS and Linux (Tauri) |
| [passboxnet/ios](https://github.com/passboxnet/ios) | iOS and iPadOS app |
| [passboxnet/android](https://github.com/passboxnet/android) | Android app |
| [passboxnet/cli](https://github.com/passboxnet/cli) | `pbx` command-line client and MCP server |

## Security

Read [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

[MIT](LICENSE)
