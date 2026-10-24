# Contributing to Passbox

Thanks for your interest in Passbox! This document explains how the repository is organized and what we expect from changes.

## Conventions

- **Language:** code, comments, commit messages and technical documentation are written in English. Planning and research documents in `docs/planning/` are written in German.
- **Monorepo:** everything lives in this repository for now. Keep package boundaries clean so we can split it later: apps never import from each other, and shared code goes into `packages/` or `crates/`.
- **Cryptography lives only in `crates/core`.** Clients call it natively or through WebAssembly. Do not add cryptographic code in TypeScript.
- **No secrets in logs, errors or `Debug` output.** Secret types redact themselves; keep it that way.

## Before you open a pull request

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
pnpm lint
pnpm build:wasm && pnpm typecheck && pnpm test && pnpm build
pnpm e2e
```

See the README for running the API tests against PostgreSQL and the client tests against a live server.

Significant design decisions are recorded as ADRs in [`docs/adr`](docs/adr). Add one when you change the architecture, the cryptography or a public interface.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
