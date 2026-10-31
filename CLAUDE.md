# Notes for AI coding agents

- Code, comments, commits and technical docs: **English**.
- Passbox is split into repositories (see README). This one is the server; it uses passboxnet/core through a git dependency on a release tag.
- The server never sees keys or plaintext. All cryptography belongs in passboxnet/core.
- License is MIT. Self-hosting must always include every feature.
- PostgreSQL only. Every table with tenant data has RLS (passboxnet/core: docs/architecture/database-security.md). After changing a query, refresh `.sqlx` with `cargo sqlx prepare`.
- Checks: `cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`, `cargo test` (needs `PASSBOX_TEST_DATABASE_URL`).
- No AI attribution in commits or PRs (`git config core.hooksPath .githooks`).
