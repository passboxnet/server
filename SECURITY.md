# Security Policy

## Cryptographic design

The cryptographic design is documented in [docs/architecture/cryptography.md](https://github.com/passboxnet/core/blob/main/docs/architecture/cryptography.md) in passboxnet/core.

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Report them privately through [GitHub Security Advisories](https://github.com/passboxnet/server/security/advisories/new).

Include:

- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- the affected version or commit.

We will acknowledge your report within three working days and keep you informed until it is resolved. We are happy to credit you in the advisory.

## Scope

In scope: everything in this repository, including the server (API, sync, background jobs, web vault hosting), the container image, the Docker Compose setup and the build pipeline. Report problems in the cryptographic core or the Rust client to [passboxnet/core](https://github.com/passboxnet/core/security/advisories/new). If you are not sure where a problem belongs, report it here; we will move it.

Especially welcome are findings where a malicious or compromised server can read, modify, swap or roll back vault data. Passbox is designed to resist that.
