-- Single sign-on (OIDC), trusted devices for SSO unlock and SCIM
-- provisioning (wave E). Portable SQL (SQLite and PostgreSQL): Base64url
-- text for binary values, Unix milliseconds for times, BIGINT for flags.
-- See docs/architecture/sso.md.

-- OIDC configuration of an organization. The client secret is encrypted
-- with the server's `sso_key` (associated data names the organization).
-- `discovery` and `jwks` cache the provider's metadata and signing keys.
CREATE TABLE org_sso (
    org_id TEXT PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    enabled BIGINT NOT NULL,
    required BIGINT NOT NULL,
    allow_device_unlock BIGINT NOT NULL,
    provider TEXT NOT NULL,
    display_name TEXT NOT NULL,
    issuer TEXT NOT NULL,
    client_id TEXT NOT NULL,
    encrypted_client_secret TEXT NOT NULL,
    token_auth_method TEXT NOT NULL,
    scopes TEXT NOT NULL,
    email_claim TEXT NOT NULL,
    require_verified_email BIGINT NOT NULL,
    name_claim TEXT NOT NULL,
    groups_claim TEXT NOT NULL,
    allowed_domains TEXT NOT NULL,
    reauth_hours BIGINT NOT NULL,
    discovery TEXT NOT NULL,
    jwks TEXT NOT NULL,
    jwks_fetched_at BIGINT NOT NULL,
    updated_by TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

-- Email domains that sign in through an organization's identity provider.
-- A domain belongs to at most one organization on the instance.
CREATE TABLE sso_domains (
    domain TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE
);
CREATE INDEX sso_domains_org_id ON sso_domains (org_id);

-- Identity provider accounts linked to Passbox accounts (by `sub`). Linking
-- happens on the first SSO sign-in by verified email; later sign-ins use
-- the subject only, so a changed email at the provider cannot move the link.
CREATE TABLE sso_identities (
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    last_login_at BIGINT NOT NULL,
    PRIMARY KEY (org_id, subject)
);
CREATE INDEX sso_identities_account_id ON sso_identities (account_id);

-- Authorization requests in flight (10 minutes, single use). `state_hash`
-- is the SHA-256 of the `state` parameter; `binding_hash` the SHA-256 of
-- the flow secret the starting client keeps.
CREATE TABLE sso_flows (
    state_hash TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    purpose TEXT NOT NULL,
    nonce TEXT NOT NULL,
    code_verifier TEXT NOT NULL,
    binding_hash TEXT NOT NULL,
    return_to TEXT NOT NULL,
    initiated_by TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);

-- Results of the provider's callback, redeemed once by the client that
-- started the flow (5 minutes). `outcome` is `ok` or an error code.
CREATE TABLE sso_tickets (
    ticket_hash TEXT PRIMARY KEY,
    binding_hash TEXT NOT NULL,
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    purpose TEXT NOT NULL,
    outcome TEXT NOT NULL,
    account_id TEXT,
    email TEXT NOT NULL,
    result TEXT NOT NULL,
    initiated_by TEXT NOT NULL,
    expires_at BIGINT NOT NULL
);

-- Proof of a completed SSO sign-in for one account (10 minutes, single
-- use): satisfies the "SSO required" policy at login/finish, or unlocks a
-- trusted device.
CREATE TABLE sso_proofs (
    proof_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);

-- A device that signed in with SSO is remembered for the organization's
-- re-authentication interval, like `two_factor_until`.
ALTER TABLE device_tokens ADD COLUMN sso_until BIGINT NOT NULL DEFAULT 0;

-- Devices that unlock with SSO instead of the master password (E2). The
-- account key is sealed to the device's X-Wing key; `grant_data` is signed
-- with the account's signing key.
CREATE TABLE trusted_devices (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    sealed_key TEXT NOT NULL,
    grant_data TEXT NOT NULL,
    grant_signature TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    last_used_at BIGINT NOT NULL
);
CREATE INDEX trusted_devices_account_id ON trusted_devices (account_id);

-- New devices waiting for approval by a trusted device (30 minutes).
CREATE TABLE trusted_device_requests (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    public_key TEXT NOT NULL,
    device_name TEXT NOT NULL,
    client_kind TEXT NOT NULL,
    ip TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE INDEX trusted_device_requests_account_id ON trusted_device_requests (account_id, status);

-- SCIM bearer tokens of an organization (only hashes are stored).
CREATE TABLE scim_tokens (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    last_used_at BIGINT NOT NULL
);
CREATE INDEX scim_tokens_org_id ON scim_tokens (org_id);

-- Users provisioned by the organization's directory. `account_id` is set
-- once a Passbox account with the email exists and joined; until then an
-- invitation is pending. `suspended_from` keeps the membership status a
-- deactivation suspended, to restore it on reactivation.
CREATE TABLE scim_users (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    external_id TEXT NOT NULL,
    user_name TEXT NOT NULL,
    user_name_key TEXT NOT NULL,
    email TEXT NOT NULL,
    display_name TEXT NOT NULL,
    given_name TEXT NOT NULL,
    family_name TEXT NOT NULL,
    active BIGINT NOT NULL,
    account_id TEXT,
    suspended_from TEXT NOT NULL,
    version BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE (org_id, user_name_key)
);
CREATE INDEX scim_users_email ON scim_users (org_id, email);

CREATE TABLE scim_groups (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    external_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    version BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE INDEX scim_groups_org_id ON scim_groups (org_id);

CREATE TABLE scim_group_members (
    group_id TEXT NOT NULL REFERENCES scim_groups (id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES scim_users (id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX scim_group_members_user_id ON scim_group_members (user_id);
