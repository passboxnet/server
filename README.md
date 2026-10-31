# Passbox server

The server of [Passbox](https://passbox.net), an open-source password manager with passkeys, a built-in authenticator and single sign-on. It stores and syncs end-to-end encrypted data, never sees a key, and serves the web vault. Rust (axum) and PostgreSQL.

> **Status: early development.** The cryptographic design is a draft and has not been audited. Do not store real secrets in Passbox yet.

## Self-hosting

```sh
cd deploy/compose
cp .env.example .env   # domain, passwords, backup key
docker compose up -d
```

This starts Passbox with PostgreSQL, Caddy for HTTPS and encrypted daily backups. The image `ghcr.io/passboxnet/passbox-server` (`linux/amd64` and `linux/arm64`, signed with cosign) serves the API and the web vault. Every feature is included. See [docs/self-hosting.md](docs/self-hosting.md).

## Development

```sh
PASSBOX_DATABASE_URL=postgres://postgres:postgres@localhost:5432/passbox cargo run   # http://localhost:8080
PASSBOX_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres cargo test
```

The cryptographic core and the Rust client come from [passbox-core](https://github.com/passboxnet/passbox-core) (git dependency on a release tag). `tests/client_*.rs` run the Rust client against this server. For the web vault run [passbox-web](https://github.com/passboxnet/passbox-web) next to it. The queries are checked against the committed `.sqlx` cache (`SQLX_OFFLINE=true`).

The API is described in [docs/api](docs/api).

## Image

A tag `vX.Y.Z` builds the image for both architectures, scans it with Trivy, signs it with cosign and attaches an SBOM and SLSA provenance. The web vault inside is the released archive of passbox-web at `WEB_VERSION` in the [Dockerfile](Dockerfile), checked against `WEB_SHA256`.

## Repositories

| Repository | Contents |
| --- | --- |
| [passbox-core](https://github.com/passboxnet/passbox-core) | Cryptographic core (Rust), WebAssembly build, Rust client, Swift/Kotlin bindings, AI gateway, shared TypeScript packages (`@passbox/*`) |
| [passbox-server](https://github.com/passboxnet/passbox-server) | Server (API, sync, web vault hosting), container image, Docker Compose for self-hosting |
| [passbox-web](https://github.com/passboxnet/passbox-web) | Web vault (React, Vite) and browser end-to-end tests |
| [passbox-extension](https://github.com/passboxnet/passbox-extension) | Browser extension with autofill and passkeys |
| [passbox-desktop](https://github.com/passboxnet/passbox-desktop) | Desktop app for Windows, macOS and Linux (Tauri) |
| [passbox-ios](https://github.com/passboxnet/passbox-ios) | iOS and iPadOS app |
| [passbox-android](https://github.com/passboxnet/passbox-android) | Android app |
| [passbox-cli](https://github.com/passboxnet/passbox-cli) | `pbx` command-line client and MCP server |

## Security

Read [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

[MIT](LICENSE)
