# Security Policy

## Status

Passbox is in early development. The cryptographic design in [docs/architecture/cryptography.md](docs/architecture/cryptography.md) is a draft and has not been independently reviewed or audited. Do not use Passbox for real secrets yet.

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Report them privately through [GitHub Security Advisories](https://github.com/relationsoftware/passbox/security/advisories/new).

Include:

- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- the affected version or commit.

We will acknowledge your report within three working days and keep you informed until it is resolved. We are happy to credit you in the advisory.

## Scope

In scope: everything in this repository, including the cryptographic core, the server, the web client, the browser extension and the build pipeline.

Especially welcome are findings where a malicious or compromised server can read, modify, swap or roll back vault data. Passbox is designed to resist that.
