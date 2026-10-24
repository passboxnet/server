-- Account recovery, emergency access and adding devices by code (wave C).
-- Portable SQL (SQLite and PostgreSQL): Base64url text for binary values,
-- Unix milliseconds for times (0 = not set), BIGINT for numbers and flags.
-- See docs/architecture/recovery.md.

-- Personal recovery code (C2): a second OPAQUE record whose password is
-- derived from the code, and the account key wrapped with a key derived
-- from the code. The server hands out the wrapped key only after an OPAQUE
-- login with the code.
CREATE TABLE account_recovery (
    account_id TEXT PRIMARY KEY REFERENCES accounts (id) ON DELETE CASCADE,
    opaque_record TEXT NOT NULL,
    wrapped_account_key TEXT NOT NULL,
    created_at BIGINT NOT NULL
);

-- First round of a recovery-code login (like login_attempts). `account_id`
-- is NULL for unknown emails or accounts without a recovery code.
CREATE TABLE recovery_attempts (
    id TEXT PRIMARY KEY,
    account_id TEXT,
    state TEXT NOT NULL,
    email TEXT NOT NULL,
    ip TEXT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE INDEX recovery_attempts_expires_at ON recovery_attempts (expires_at);

-- A proven recovery (by code or an approved organization request) that may
-- set new credentials. Only the SHA-256 of the token is stored; single use.
-- `method` is `code` or `org`; `source_id` names the organization request.
-- `two_factor_pending` is 1 while a recovery by code still needs the
-- account's second factor.
CREATE TABLE recovery_sessions (
    token_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    method TEXT NOT NULL,
    source_id TEXT NOT NULL,
    two_factor_pending BIGINT NOT NULL,
    device_name TEXT NOT NULL,
    client_kind TEXT NOT NULL,
    ip TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE INDEX recovery_sessions_account_id ON recovery_sessions (account_id);

-- Organization recovery (C1). The recovery public key is signed by an admin;
-- its private key is sealed to each admin who may approve requests.
CREATE TABLE org_recovery_keys (
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    key_version BIGINT NOT NULL,
    bundle TEXT NOT NULL,
    bundle_signature TEXT NOT NULL,
    bundle_hash TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (org_id, key_version)
);

CREATE TABLE org_recovery_grants (
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    key_version BIGINT NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    sealed_key TEXT NOT NULL,
    grant_data TEXT NOT NULL,
    grant_signature TEXT NOT NULL,
    granted_by TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (org_id, key_version, account_id)
);

-- A member's account key sealed to the recovery key (opt-in), signed by the
-- member.
CREATE TABLE org_recovery_escrows (
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    key_version BIGINT NOT NULL,
    escrow TEXT NOT NULL,
    escrow_signature TEXT NOT NULL,
    sealed_key TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (org_id, account_id)
);
CREATE INDEX org_recovery_escrows_account_id ON org_recovery_escrows (account_id);

-- Requests from a device that lost access. `status`: pending, approved,
-- denied, completed or cancelled (expiry is checked with `expires_at`).
-- Only the SHA-256 of the device's request token is stored.
CREATE TABLE org_recovery_requests (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    ephemeral_key TEXT NOT NULL,
    status TEXT NOT NULL,
    approval TEXT NOT NULL,
    approval_signature TEXT NOT NULL,
    sealed_key TEXT NOT NULL,
    request_code TEXT NOT NULL,
    decided_by TEXT NOT NULL,
    decided_at BIGINT NOT NULL,
    device_name TEXT NOT NULL,
    ip TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE INDEX org_recovery_requests_org_id ON org_recovery_requests (org_id, status);
CREATE INDEX org_recovery_requests_account_id ON org_recovery_requests (account_id);

-- Emergency access (C3). `status`: invited (by email), accepted (the
-- grantee accepted), confirmed (keys sealed for the grantee). A request
-- releases the sealed keys after `wait_days` unless the grantor declines;
-- `approved_at` releases them early. `vault_ids` is a JSON array of the
-- grantor's personal vaults named in the signed grant.
CREATE TABLE emergency_grants (
    id TEXT PRIMARY KEY,
    grantor_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    grantee_email TEXT NOT NULL,
    grantee_id TEXT REFERENCES accounts (id) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    wait_days BIGINT NOT NULL,
    status TEXT NOT NULL,
    vault_ids TEXT NOT NULL,
    grant_data TEXT NOT NULL,
    grant_signature TEXT NOT NULL,
    sealed_keys TEXT NOT NULL,
    version BIGINT NOT NULL,
    requested_at BIGINT NOT NULL,
    approved_at BIGINT NOT NULL,
    denied_at BIGINT NOT NULL,
    accessed_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE INDEX emergency_grants_grantor_id ON emergency_grants (grantor_id);
CREATE INDEX emergency_grants_grantee_id ON emergency_grants (grantee_id);
CREATE INDEX emergency_grants_grantee_email ON emergency_grants (grantee_email);

-- Adding a device by code (C4). The signed-in device opens a link; the new
-- device claims it with an ephemeral key and a MAC under the code's secret
-- (which the server never sees). `status`: open, claimed, approved.
CREATE TABLE device_links (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    short_id TEXT NOT NULL,
    status TEXT NOT NULL,
    ephemeral_key TEXT NOT NULL,
    mac TEXT NOT NULL,
    claim_token_hash TEXT NOT NULL,
    claim_device_name TEXT NOT NULL,
    claim_ip TEXT NOT NULL,
    claimed_at BIGINT NOT NULL,
    sealed_payload TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE INDEX device_links_short_id ON device_links (short_id);
CREATE INDEX device_links_claim_token_hash ON device_links (claim_token_hash);
