-- Account key pairs, the key directory, organizations, groups and shared
-- vaults. Portable SQL (SQLite and PostgreSQL): Base64url text for binary
-- values, Unix milliseconds for times, BIGINT for numbers and flags.
-- See docs/architecture/sharing.md.

-- Published public key bundles and the account's private keys, encrypted
-- with its account key. `bundle` is the canonical encoding clients verify.
CREATE TABLE account_keys (
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    key_version BIGINT NOT NULL,
    bundle TEXT NOT NULL,
    bundle_signature TEXT NOT NULL,
    bundle_hash TEXT NOT NULL,
    encrypted_private TEXT NOT NULL,
    log_seq BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (account_id, key_version)
);
CREATE INDEX account_keys_bundle_hash ON account_keys (bundle_hash);

-- Append-only, hash-chained log of published bundles (key directory).
-- Rows are never updated or deleted, also not when an account is deleted.
CREATE TABLE key_log (
    seq BIGINT PRIMARY KEY,
    account_id TEXT NOT NULL,
    key_version BIGINT NOT NULL,
    bundle_hash TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX key_log_account_id ON key_log (account_id, seq);
INSERT INTO counters (name, value) VALUES ('key_log_seq', 0);

-- Organizations. Name and other metadata are encrypted with the
-- organization key (epoch `meta_epoch`); `genesis` is signed by the owner.
CREATE TABLE organizations (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    owner_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    genesis TEXT NOT NULL,
    genesis_signature TEXT NOT NULL,
    encrypted_meta TEXT NOT NULL,
    meta_epoch BIGINT NOT NULL,
    default_vault_id TEXT,
    revision BIGINT NOT NULL,
    seq BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

-- Members: `accepted` after accepting an invitation, `confirmed` once an
-- admin attested their key, `suspended` while blocked. Removed members are
-- deleted.
CREATE TABLE org_members (
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    status TEXT NOT NULL,
    attestation TEXT,
    attestation_signature TEXT,
    invited_by TEXT NOT NULL,
    seq BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (org_id, account_id)
);
CREATE INDEX org_members_account_id ON org_members (account_id);

-- Invitations. Only the SHA-256 hash of the token in the link is stored.
CREATE TABLE org_invitations (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    -- pending, accepted or revoked
    status TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    accepted_by TEXT,
    accepted_at BIGINT
);
CREATE INDEX org_invitations_org_id ON org_invitations (org_id, status);

-- The organization key, sealed per member and epoch.
CREATE TABLE org_keys (
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    epoch BIGINT NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    sealed_key TEXT NOT NULL,
    grant_data TEXT NOT NULL,
    grant_signature TEXT NOT NULL,
    seq BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (org_id, epoch, account_id)
);

-- Groups: principals with their own encryption key pair.
CREATE TABLE org_groups (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    key_version BIGINT NOT NULL,
    bundle TEXT NOT NULL,
    bundle_signature TEXT NOT NULL,
    encrypted_meta TEXT NOT NULL,
    meta_epoch BIGINT NOT NULL,
    seq BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE INDEX org_groups_org_id ON org_groups (org_id);

-- Every key version of a group (members need old versions to open vault
-- keys of older epochs until those are re-encrypted).
CREATE TABLE group_versions (
    group_id TEXT NOT NULL REFERENCES org_groups (id) ON DELETE CASCADE,
    key_version BIGINT NOT NULL,
    bundle TEXT NOT NULL,
    bundle_signature TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (group_id, key_version)
);

-- The group private key sealed per member and key version. Members of
-- the group are the accounts with a row for the current key version.
CREATE TABLE group_members (
    group_id TEXT NOT NULL REFERENCES org_groups (id) ON DELETE CASCADE,
    key_version BIGINT NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    sealed_key TEXT NOT NULL,
    grant_data TEXT NOT NULL,
    grant_signature TEXT NOT NULL,
    seq BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (group_id, key_version, account_id)
);
CREATE INDEX group_members_account_id ON group_members (account_id);

-- Shared vaults belong to an organization. `account_id` stays the creator,
-- personal vaults have no `org_id`. Items record the key epoch they were
-- encrypted with (0 for personal vaults).
ALTER TABLE vaults ADD COLUMN org_id TEXT;
ALTER TABLE vaults ADD COLUMN key_epoch BIGINT NOT NULL DEFAULT 0;
ALTER TABLE vaults ADD COLUMN rotation_pending BIGINT NOT NULL DEFAULT 0;
ALTER TABLE items ADD COLUMN key_epoch BIGINT NOT NULL DEFAULT 0;
CREATE INDEX vaults_org_id ON vaults (org_id);

-- Current members of shared vaults (the server's authorization source).
CREATE TABLE vault_members (
    vault_id TEXT NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    principal_type TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    role TEXT NOT NULL,
    seq BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (vault_id, principal_type, principal_id)
);
CREATE INDEX vault_members_principal ON vault_members (principal_type, principal_id);

-- Vault keys sealed per epoch and principal, with the signed grant and the
-- member's own wrapped copy once it opened the sealed key.
CREATE TABLE vault_keys (
    vault_id TEXT NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    key_epoch BIGINT NOT NULL,
    principal_type TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    sealed_key TEXT NOT NULL,
    wrapped_key TEXT,
    grant_data TEXT NOT NULL,
    grant_signature TEXT NOT NULL,
    seq BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (vault_id, key_epoch, principal_type, principal_id)
);

-- Signed member lists of shared vaults, one row per version.
CREATE TABLE vault_manifests (
    vault_id TEXT NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    version BIGINT NOT NULL,
    manifest TEXT NOT NULL,
    signature TEXT NOT NULL,
    signer_id TEXT NOT NULL,
    seq BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (vault_id, version)
);

-- Notifications for a mailer to deliver (see crates/server/src/notify.rs).
-- `params` (JSON, may contain an invitation link with its token) is cleared
-- once delivered.
CREATE TABLE notification_outbox (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    recipient TEXT NOT NULL,
    params TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    delivered_at BIGINT NOT NULL
);
