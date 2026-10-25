# Contributing to Passbox

Thanks for your interest in Passbox! This document explains how the repository is organized and what we expect from changes.

## Conventions

- **Language:** code, comments, commit messages and technical documentation are written in English. Planning and research documents in `docs/planning/` are written in German.
- **Monorepo:** everything lives in this repository for now. Keep package boundaries clean so we can split it later: apps never import from each other, and shared code goes into `packages/` or `crates/`.
- **Cryptography lives only in `crates/core`.** Clients call it natively or through WebAssembly. Do not add cryptographic code in TypeScript.
- **No secrets in logs, errors or `Debug` output.** Secret types redact themselves; keep it that way.
- **PostgreSQL only** ([ADR 0007](docs/adr/0007-postgresql-only.md)). Every table with tenant data has row level security; follow the checklist in [database-security.md](docs/architecture/database-security.md#checklist-adding-a-table) when you add one. Queries go through a `Db` context (`as_account`, `public`, `as_org`, `system`) and use the checked `sqlx::query!` macros.

## Database for development and tests

The tests and a local server need PostgreSQL 15 or newer. For example:

```sh
docker run -d --name passbox-pg -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:16
export PASSBOX_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres
export PASSBOX_E2E_DATABASE_URL=$PASSBOX_TEST_DATABASE_URL
```

- `PASSBOX_TEST_DATABASE_URL` is a superuser connection. Every Rust test run creates a database of its own (`passbox_test_*`), provisions the roles with `crates/server/sql/roles.sql`, migrates it as `passbox_migrator` and connects as `passbox_app` and `passbox_worker`, so the tests see row level security exactly as production does. The database is dropped afterwards (servers started by client tests leave theirs; a later run drops those that are older than half an hour and no longer in use).
- `PASSBOX_E2E_DATABASE_URL` is the same for `pnpm e2e`: `e2e/database.sh` (needs `psql`) recreates one database per test server.
- **Query cache:** `sqlx::query!` checks queries at compile time. Without `DATABASE_URL` the macros read the committed cache in `.sqlx/`, which is what CI does (`SQLX_OFFLINE=true`). After adding or changing a query, migrate a development database and rebuild with it, writing the cache:

  ```sh
  createdb passbox_dev && for f in crates/server/migrations/*.sql; do psql -d passbox_dev -v ON_ERROR_STOP=1 -f "$f"; done
  rm -rf .sqlx && DATABASE_URL=postgres://postgres:postgres@localhost:5432/passbox_dev \
    SQLX_OFFLINE_DIR=$PWD/.sqlx cargo check -p passbox-server --all-targets
  ```

  (`cargo sqlx prepare --workspace` from sqlx-cli does the same.) Commit the changed `.sqlx/` files with the query.
- **Migrations:** add a new file in `crates/server/migrations`; never change one that was released. Policies and grants for new tables go into the same migration.

## Before you open a pull request

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
pnpm lint
pnpm build:wasm && pnpm typecheck && pnpm test && pnpm build
pnpm e2e
```

The Rust tests need `PASSBOX_TEST_DATABASE_URL` and `pnpm e2e` needs `PASSBOX_E2E_DATABASE_URL` (above). See the README for the client tests against a live server.

Significant design decisions are recorded as ADRs in [`docs/adr`](docs/adr). Add one when you change the architecture, the cryptography or a public interface.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
