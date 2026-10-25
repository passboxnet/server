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

## Have I Been Pwned breach catalogue

- **What:** the list of breached websites (name, title, domain, breach and
  publication dates, number of accounts, kinds of exposed data, verified
  and sensitive flags) used for the "Website mit Datenleck" (breached
  website) check of the security analysis.
- **Source:** Have I Been Pwned by Troy Hunt, <https://haveibeenpwned.com/>,
  API `https://haveibeenpwned.com/api/v3/breaches`.
- **License:** [Creative Commons Attribution 4.0 International
  (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/). Passbox names
  Have I Been Pwned as the source, with a link, wherever it shows breach
  data (web and desktop security check, extension, iOS and Android
  Sicherheits-Check, organization reports). The data is compacted (fields
  left out, entries without a domain, fabricated entries, spam lists and
  retired breaches removed); it is not otherwise changed.
- **Bundled as:** `crates/core/data/site-breaches.tsv`, snapshot of
  2026-10-25 (979 entries), written by `scripts/update-breach-catalog.py`.
  Servers fetch the current list themselves (`PASSBOX_BREACH_CATALOG`).

## Brand icons of third-party services

- **What:** the public website icons (favicons, apple-touch-icons or app
  icons) of the services Passbox names in its user interface: import sources
  (1Password, Bitwarden, LastPass, Dashlane, Keeper, Proton Pass, KeePass,
  KeePassXC, Passbolt, NordPass, Enpass, RoboForm, Google Password Manager,
  Apple Passwords), browsers and platforms (Chrome, Edge, Firefox, Safari,
  Brave, Windows, macOS, Linux, iOS, App Store, Android, Google Play), email
  alias providers (SimpleLogin, addy.io, Fastmail, DuckDuckGo, Firefox Relay),
  identity providers (Microsoft Entra ID, Google, Okta, Keycloak, authentik,
  ZITADEL), SIEMs (Splunk, Microsoft Sentinel, Elastic, Graylog, Wazuh), AI
  agent clients and providers (Claude, Anthropic, Cursor, Visual Studio Code,
  OpenAI, GitHub, Langdock, Mistral AI, IONOS, STACKIT, Scaleway, Ollama),
  Have I Been Pwned and 2fa.directory.
- **Bundled as:** `packages/brand-icons/icons/<id>.png` (scaled to 64×64
  pixels), with `packages/brand-icons/manifest.json` naming each icon's
  domain, source URL and the date it was fetched.
- **Source:** each service's own website, as listed in the manifest.
- **Rights:** the names, logos and icons are trademarks or other marks of
  their respective owners. They are not covered by Passbox's MIT license.
  Passbox uses them only to identify the services it works with or imports
  from (nominative use); this implies no endorsement by, or affiliation
  with, their owners. Owners who want an icon removed or replaced can open an
  issue.

Refresh the icons with `node scripts/update-brand-icons.mjs` (all) or
`node scripts/update-brand-icons.mjs okta github` (some); the service list is
`packages/brand-icons/services.json`. The apps never load these icons from
the services at run time.

## Website icons of popular sites

- **What:** the public website icons (apple-touch-icons, favicons or the
  icon a homepage links) of the most popular sites, so the apps show them
  without asking any server. Generated on 2026-10-25 from the top 5,000
  domains of the ranking below; 3,516 had a usable icon.
- **Ranking:** [Majestic Million](https://majestic.com/reports/majestic-million)
  by Majestic-12 Ltd, downloaded 2026-10-25 from
  `https://downloads.majestic.com/majestic_million.csv`, licensed under
  [Creative Commons Attribution 3.0 Unported](https://creativecommons.org/licenses/by/3.0/).
  Only the domain names and their order are used. The default
  [Tranco](https://tranco-list.eu/) list was not used: it includes Cloudflare
  Radar data under CC BY-NC 4.0, which does not allow commercial use.
- **Bundled as:** `packages/site-icons/packs/web-32.pbia` (32 px, all
  3,516 sites) and `web-64.pbia` (64 px, the 1,000 most popular) for the web
  app, desktop app and extension; `packages/site-icons/mobile/site-icons-64.pbic`
  (64 px, the 1,000 most popular) for iOS and Android. WebP, scaled from the
  originals. `packages/site-icons/manifest.json` lists every domain with its
  rank and the URL its icon came from.
- **Source:** each site's own website, fetched with the Passbox server's
  icon fetcher.
- **Rights:** the icons are trademarks or other marks of their respective
  owners and are not covered by Passbox's MIT license. Passbox shows them
  only to identify the website a saved login belongs to, as a browser does
  next to a bookmark; this implies no endorsement by, or affiliation with,
  their owners. Owners who want an icon removed or replaced can open an
  issue.

Regenerate with `node scripts/update-site-icons.mjs` (see the script for
options) and update the dates above.
