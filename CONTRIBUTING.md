# Contributing to Passbox

Thanks for your interest in Passbox! This document explains how the repository is organized and what we expect from changes.

## Conventions

- **Language:** code, comments, commit messages and technical documentation are written in English.
- **Repositories:** Passbox is split into several repositories (see the [README](README.md#repositories)). This one is the server. The cryptographic core, the Rust client and the shared TypeScript packages live in [passboxnet/core](https://github.com/passboxnet/core), which this crate uses as a git dependency on a release tag.
- **Cryptography lives only in passboxnet/core.** The server never sees keys or plaintext. Do not add cryptographic code here.
- **No secrets in logs, errors or `Debug` output.** Secret types redact themselves; keep it that way.
- **PostgreSQL only** ([ADR 0007](https://github.com/passboxnet/core/blob/main/docs/adr/0007-postgresql-only.md)). Every table with tenant data has row level security; follow the checklist in [database-security.md](https://github.com/passboxnet/core/blob/main/docs/architecture/database-security.md#checklist-adding-a-table) when you add one. Queries go through a `Db` context (`as_account`, `public`, `as_org`, `system`) and use the checked `sqlx::query!` macros.

## Database for development and tests

The tests and a local server need PostgreSQL 15 or newer. For example:

```sh
docker run -d --name passbox-pg -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:16
export PASSBOX_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres
```

- `PASSBOX_TEST_DATABASE_URL` is a superuser connection. Every test run creates a database of its own (`passbox_test_*`), provisions the roles with `sql/roles.sql`, migrates it as `passbox_migrator` and connects as `passbox_app` and `passbox_worker`, so the tests see row level security exactly as production does. The database is dropped afterwards (servers started by client tests in other repositories leave theirs; a later run drops those that are older than half an hour and no longer in use).
- `scripts/test-database.sh` (needs `psql`) creates and drops such a database for one server. The end-to-end tests of [passboxnet/web](https://github.com/passboxnet/web) and the host tests of the Android and iOS apps use it to give every server they start a database of its own.
- **Query cache:** `sqlx::query!` checks queries at compile time. Without `DATABASE_URL` the macros read the committed cache in `.sqlx/`, which is what CI does (`SQLX_OFFLINE=true`). After adding or changing a query, migrate a development database and rebuild with it, writing the cache:

  ```sh
  createdb passbox_dev && for f in migrations/*.sql; do psql -d passbox_dev -v ON_ERROR_STOP=1 -f "$f"; done
  rm -rf .sqlx && DATABASE_URL=postgres://postgres:postgres@localhost:5432/passbox_dev \
    SQLX_OFFLINE_DIR=$PWD/.sqlx cargo check --all-targets
  ```

  (`cargo sqlx prepare` from sqlx-cli does the same.) Commit the changed `.sqlx/` files with the query.
- **Migrations:** add a new file in `migrations/`; never change one that was released. Policies and grants for new tables go into the same migration.

## Before you open a pull request

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
```

The tests need `PASSBOX_TEST_DATABASE_URL` (above). `tests/client_*.rs` run the Rust client from passboxnet/core against this server.

Significant design decisions are recorded as ADRs in [passboxnet/core: `docs/adr`](https://github.com/passboxnet/core/tree/main/docs/adr). Add one when you change the architecture, the cryptography or a public interface.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
