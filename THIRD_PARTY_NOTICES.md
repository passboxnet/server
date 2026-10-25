# Third-party data

Passbox is MIT-licensed. It bundles the following third-party data, which
keeps its own license. Software dependencies are listed in `Cargo.lock` and
`pnpm-lock.yaml` with their licenses in their packages.

## 2fa.directory

- **What:** which websites support two-factor authentication and how, with
  links to their instructions. Used by the security analysis ("Zwei-Faktor-
  Anmeldung möglich").
- **Bundled as:** `crates/core/data/twofactor-sites.tsv` (domain, methods,
  documentation URL; sites without 2FA are left out).
- **Source:** <https://2fa.directory/>, API `https://api.2fa.directory/v4/all.json`,
  repository <https://github.com/2factorauth/twofactorauth>.
- **Snapshot:** 2026-10-24 (the first line of the file names the date).
- **License:** MIT License, Copyright (c) 2fa.directory / 2factorauth
  contributors. The images of the project are not bundled.

## Passkeys Directory

- **What:** which websites support passkeys, for sign-in and as a second
  factor, with links to their instructions. Used by the security analysis
  ("Passkey möglich").
- **Bundled as:** `crates/core/data/passkey-sites.tsv` (domain, flags,
  documentation URL; sites without passkey support are left out).
- **Source:** <https://passkeys.2fa.directory/>, API
  `https://passkeys-api.2fa.directory/v1/all.json`, repository
  <https://github.com/2factorauth/passkeys>.
- **Snapshot:** 2026-10-24.
- **License:** Creative Commons Attribution 4.0 International
  (<https://creativecommons.org/licenses/by/4.0/>). Attribution: data from the
  Passkeys Directory by 2factorauth and its contributors, converted to a
  compact list (fields reduced, domains normalized). The images of the
  project are not bundled.

The site "passkeys.directory" was considered too; we found no open license
for its data, so it is not bundled.

Refresh both lists with `python3 scripts/update-site-directories.py` and
update the snapshot dates above.
