# Passbox

Passbox is an open-source password manager with passkeys, a built-in authenticator and single sign-on. Use it as a hosted service or run it on your own server.

> **Status: early development.** The cryptographic design is a draft and has not been audited. Do not store real secrets in Passbox yet.

## What's in this repository

Passbox is developed as one monorepo. It will be split into separate repositories once everything works.

| Path | Description |
| --- | --- |
| [`crates/core`](crates/core) | Cryptographic core in Rust: key derivation, encryption, Secret Key, TOTP, password generator |
| [`crates/core-wasm`](crates/core-wasm) | WebAssembly bindings of the core for the web client and the extension |
| [`crates/server`](crates/server) | Headless server (axum). Stores and syncs encrypted data and serves the web client |
| [`crates/cli`](crates/cli) | `pbx` command-line client |
| [`apps/web`](apps/web) | Web client (React, Vite) |
| [`apps/extension`](apps/extension) | Chrome extension (Manifest V3) |
| [`apps/website`](apps/website) | Marketing website (Next.js, static export) |
| [`packages/ui`](packages/ui) | Shared design system (React, Tailwind CSS tokens) |
| [`packages/api-client`](packages/api-client) | Typed TypeScript client for the server API |
| [`docs`](docs) | Architecture, decisions (ADRs), API specification and planning |
| [`deploy`](deploy) | Docker Compose setup for self-hosting |

## Getting started

Requirements: Rust (stable, see `rust-toolchain.toml`), Node.js 22+, pnpm 10 (`corepack enable`), and [`wasm-bindgen-cli`](https://github.com/wasm-bindgen/wasm-bindgen) in the version listed in `Cargo.lock`:

```sh
cargo install wasm-bindgen-cli --version 0.2.129 --locked
```

Install and build:

```sh
pnpm install
pnpm build:wasm          # builds the Rust core to WebAssembly
cargo test --workspace   # Rust tests
pnpm test                # TypeScript tests
```

Run the server and the web client in two terminals:

```sh
cargo run -p passbox-server   # http://localhost:8080
pnpm dev:web                  # http://localhost:5173, proxies /api to the server
```

Other entry points:

```sh
pnpm dev:website                       # website on http://localhost:3000
pnpm --filter @passbox/extension build # extension in apps/extension/dist, load it via chrome://extensions
cargo run -p passbox-cli -- totp JBSWY3DPEHPK3PXP
```

## Self-hosting

```sh
docker compose -f deploy/docker-compose.yml up -d
```

The server listens on port 8080 and serves the web client. See [the configuration options](crates/server/src/config.rs).

## Pricing

Passbox is free to self-host with every feature included. The hosted service costs:

| Plan | Monthly | Yearly |
| --- | --- | --- |
| Personal | 1 € per member | 10 € per member |
| Teams | 3 € per member | 30 € per member |

## Security

Read [SECURITY.md](SECURITY.md) to report a vulnerability and [docs/architecture/cryptography.md](docs/architecture/cryptography.md) for the design.

## License

[MIT](LICENSE)
