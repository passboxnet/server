# Notes for AI coding agents

- Code, comments, commits and technical docs: **English**. Planning and research docs (`docs/planning/`): **German**.
- This is one monorepo on purpose. Keep package boundaries clean (no imports between apps); splitting happens later.
- All cryptography belongs in `crates/core`. Web and extension use it via `@passbox/core-wasm`.
- License is MIT. Self-hosting must always include every feature.
- PostgreSQL only (see docs/adr/0007-postgresql-only.md). Every table with tenant data has RLS; see docs/architecture/database-security.md.
- Checks: `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `pnpm lint`, `pnpm build:wasm && pnpm typecheck && pnpm test && pnpm build`, `pnpm e2e`.
