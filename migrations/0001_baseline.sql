-- Passbox schema baseline (PostgreSQL 15 or newer).
--
-- Replaces the migrations of the SQLite era (0001-0013); the product was not
-- released, so no data needs converting. See docs/adr/0007-postgresql-only.md.
--
-- Conventions:
-- - IDs are client- or server-generated 128-bit values as 26 lowercase
--   Crockford Base32 characters (passbox_core::id), stored as TEXT and
--   checked with passbox.valid_id(). They are part of the API and of signed
--   and encrypted data (associated data), so they keep their text form.
-- - Encrypted payloads and key material are BYTEA. The API still carries
--   them as unpadded Base64url (crate::db::B64 converts at the edge).
--   Signed canonical objects (bundles, grants, manifests, policies,
--   attestations) and their signatures stay Base64url TEXT: clients verify
--   them byte for byte and the server compares some of them as text.
-- - Times are BIGINT Unix milliseconds, as in the API; 0 means "not set"
--   where a column says so.
-- - Flags are BOOLEAN, structured documents JSONB, enumerations TEXT with
--   CHECK constraints.
-- - Row level security, roles and grants: 0002_rls.sql. Every new table
--   with tenant data needs a policy there (docs/architecture/database-security.md).

CREATE SCHEMA passbox;

CREATE FUNCTION passbox.valid_id(value TEXT) RETURNS BOOLEAN
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    RETURN value ~ '^[0-7][0-9a-hjkmnp-tv-z]{25}$';

-- SHA-256 hashes of tokens, as lowercase hex.
CREATE FUNCTION passbox.valid_hash(value TEXT) RETURNS BOOLEAN
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    RETURN value ~ '^[0-9a-f]{64}$';

-- --- Instance ----------------------------------------------------------------

-- Secrets generated on first start (OPAQUE server setup, prelogin key,
-- two-factor key, key log signing key, SSO key).
CREATE TABLE server_secrets (
    name TEXT PRIMARY KEY,
    value BYTEA NOT NULL
);

-- Global counters. `change_seq`: every write takes the next value, and
-- clients sync everything with a higher value than their cursor.
CREATE TABLE counters (
    name TEXT PRIMARY KEY,
    value BIGINT NOT NULL CHECK (value >= 0)
);
INSERT INTO counters (name, value) VALUES ('change_seq', 0), ('key_log_seq', 0), ('admin_event_seq', 0);

-- Instance-wide state as named JSON documents: `settings` (registration
-- mode, instance name, ...) and `first_admin` (the account that became
-- instance admin by registering first; its unique name makes sure only one
-- account does, even when two register at the same time).
CREATE TABLE instance_state (
    name TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at BIGINT NOT NULL
);

-- --- Accounts and sign-in ------------------------------------------------------

-- `disabled_at` is 0 for active accounts. `locale` is the account's
-- language for mail ('' = instance default).
CREATE TABLE accounts (
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
    email TEXT NOT NULL UNIQUE CHECK (email = lower(email) AND email LIKE '%_@_%'),
    opaque_record BYTEA NOT NULL,
    kdf_salt BYTEA NOT NULL CHECK (length(kdf_salt) = 16),
    kdf_memory_kib BIGINT NOT NULL CHECK (kdf_memory_kib > 0),
    kdf_iterations BIGINT NOT NULL CHECK (kdf_iterations > 0),
    kdf_parallelism BIGINT NOT NULL CHECK (kdf_parallelism > 0),
    encrypted_account_key BYTEA NOT NULL,
    created_at BIGINT NOT NULL,
    instance_admin BOOLEAN NOT NULL DEFAULT false,
    disabled_at BIGINT NOT NULL DEFAULT 0,
    locale TEXT NOT NULL DEFAULT '',
    notify_new_device BOOLEAN NOT NULL DEFAULT true
);

-- Sessions. `id` is the public ID shown in the device list; only the
-- SHA-256 of the bearer token is stored. `device_token_hash` is the device
-- token issued with the session, so a password change can keep the current
-- device's token while invalidating all others.
CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY CHECK (passbox.valid_hash(token_hash)),
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    id TEXT NOT NULL UNIQUE CHECK (passbox.valid_id(id)),
    device_name TEXT NOT NULL,
    client_kind TEXT NOT NULL,
    ip TEXT NOT NULL,
    last_used_at BIGINT NOT NULL,
    device_token_hash TEXT NOT NULL
);
CREATE INDEX sessions_account_id ON sessions (account_id);

-- Pending OPAQUE logins between the start and finish requests. `account_id`
-- is NULL for unknown emails; `device_token_hash` is the valid device token
-- the login was started with ('' for none), so a failure is counted
-- against the right limits.
CREATE TABLE login_attempts (
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
    account_id TEXT REFERENCES accounts (id) ON DELETE CASCADE,
    state BYTEA NOT NULL,
    expires_at BIGINT NOT NULL,
    ip TEXT NOT NULL,
    email TEXT NOT NULL,
    device_token_hash TEXT NOT NULL
);
CREATE INDEX login_attempts_expires_at ON login_attempts (expires_at);

-- Activity log of an account.
CREATE TABLE account_events (
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    device_name TEXT NOT NULL,
    client_kind TEXT NOT NULL,
    ip TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX account_events_account_id_created_at ON account_events (account_id, created_at);

-- Device tokens identify devices that have signed in successfully before.
-- A login that presents a valid one is exempt from the per-email lockout,
-- so failed logins from elsewhere cannot lock a user out of their own
-- devices. Only SHA-256 hashes are stored. `two_factor_until` and
-- `sso_until` remember the device for the second factor and for SSO
-- (Unix ms, 0 = not remembered).
CREATE TABLE device_tokens (
    token_hash TEXT PRIMARY KEY CHECK (passbox.valid_hash(token_hash)),
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    two_factor_until BIGINT NOT NULL DEFAULT 0,
    sso_until BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX device_tokens_account_id ON device_tokens (account_id);

-- --- Login two-factor authentication ---------------------------------------------
-- None of these values protects vault data; they protect server sessions.

-- The login TOTP of an account, encrypted with the server's two-factor key
-- (XChaCha20-Poly1305, bound to the account ID). `last_step` is the last
-- accepted time step, so a code cannot be used twice.
CREATE TABLE two_factor_totp (
    account_id TEXT PRIMARY KEY REFERENCES accounts (id) ON DELETE CASCADE,
    sealed_secret BYTEA NOT NULL,
    confirmed BOOLEAN NOT NULL,
    last_step BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);

-- WebAuthn security keys and passkeys registered as a second factor.
CREATE TABLE webauthn_credentials (
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    algorithm BIGINT NOT NULL,
    sign_count BIGINT NOT NULL CHECK (sign_count >= 0),
    rp_id TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    last_used_at BIGINT NOT NULL
);
CREATE INDEX webauthn_credentials_account_id ON webauthn_credentials (account_id);

-- One-time recovery codes, as SHA-256 hashes. A used code is deleted.
CREATE TABLE recovery_codes (
    code_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    created_at BIGINT NOT NULL
);
CREATE INDEX recovery_codes_account_id ON recovery_codes (account_id);

-- Pending second steps: a login waiting for its second factor, a WebAuthn
-- registration, or a check of a second factor. Only SHA-256 hashes of the
-- tokens are stored; each one expires after a few minutes.
CREATE TABLE two_factor_challenges (
    token_hash TEXT PRIMARY KEY CHECK (passbox.valid_hash(token_hash)),
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    purpose TEXT NOT NULL,
    webauthn_challenge TEXT NOT NULL,
    rp_id TEXT NOT NULL,
    device_name TEXT NOT NULL,
    client_kind TEXT NOT NULL,
    ip TEXT NOT NULL,
    device_token_hash TEXT NOT NULL,
    attempts BIGINT NOT NULL CHECK (attempts >= 0),
    expires_at BIGINT NOT NULL
);
CREATE INDEX two_factor_challenges_account_id ON two_factor_challenges (account_id);

-- --- Keys and the key directory -----------------------------------------------------

-- Published public key bundles and the account's private keys, encrypted
-- with its account key. `bundle` is the canonical encoding clients verify.
CREATE TABLE account_keys (
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    key_version BIGINT NOT NULL CHECK (key_version >= 1),
    bundle TEXT NOT NULL,
    bundle_signature TEXT NOT NULL,
    bundle_hash TEXT NOT NULL,
    encrypted_private BYTEA NOT NULL,
    log_seq BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (account_id, key_version)
);
CREATE INDEX account_keys_bundle_hash ON account_keys (bundle_hash);

-- Append-only, hash-chained log of published bundles (key directory).
-- Rows are never updated or deleted, also not when an account is deleted,
-- so `account_id` has no foreign key.
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

-- --- Vaults and items ------------------------------------------------------------------

-- Personal vaults have no `org_id`; shared vaults belong to an organization
-- and `account_id` stays their creator. `key_epoch` is the current vault
-- key epoch of a shared vault (0 for personal vaults).
CREATE TABLE vaults (
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    encrypted_key BYTEA NOT NULL,
    encrypted_meta BYTEA NOT NULL,
    revision BIGINT NOT NULL CHECK (revision >= 1),
    seq BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    org_id TEXT,
    key_epoch BIGINT NOT NULL DEFAULT 0 CHECK (key_epoch >= 0),
    rotation_pending BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX vaults_account_id_seq ON vaults (account_id, seq);
CREATE INDEX vaults_org_id ON vaults (org_id);

-- Items: one encrypted blob each. Deleted items stay as tombstones without
-- data. `key_epoch` is the vault key epoch the data is encrypted with;
-- `updated_by` the public ID of the session (device) that wrote it.
CREATE TABLE items (
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
    vault_id TEXT NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    encrypted_data BYTEA,
    revision BIGINT NOT NULL CHECK (revision >= 1),
    deleted BOOLEAN NOT NULL,
    seq BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    key_epoch BIGINT NOT NULL DEFAULT 0 CHECK (key_epoch >= 0),
    updated_by TEXT,
    CHECK (deleted = (encrypted_data IS NULL))
);
CREATE INDEX items_vault_id_seq ON items (vault_id, seq);

-- Item version history ("Eintragsverlauf"): every update keeps the replaced
-- row, still encrypted and bound to its own revision and key epoch. The
-- server keeps the newest 20 versions per item.
CREATE TABLE item_versions (
    item_id TEXT NOT NULL REFERENCES items (id) ON DELETE CASCADE,
    revision BIGINT NOT NULL,
    key_epoch BIGINT NOT NULL,
    encrypted_data BYTEA NOT NULL,
    updated_at BIGINT NOT NULL,
    updated_by TEXT,
    PRIMARY KEY (item_id, revision)
);

-- Where an item was before it moved to another vault, so devices of members
-- of the old vault learn that it left (sync sends a tombstone for the old
-- vault). No foreign keys: the record must outlive both vaults' changes.
CREATE TABLE item_moves (
    item_id TEXT NOT NULL,
    from_vault_id TEXT NOT NULL,
    to_vault_id TEXT NOT NULL,
    revision BIGINT NOT NULL,
    seq BIGINT NOT NULL,
    moved_at BIGINT NOT NULL
);
CREATE INDEX item_moves_from_vault ON item_moves (from_vault_id, seq);
CREATE INDEX item_moves_item_id ON item_moves (item_id);

-- --- Organizations, groups and shared vaults -----------------------------------------
-- See docs/architecture/sharing.md.

-- Name and other metadata are encrypted with the organization key (epoch
-- `meta_epoch`); `genesis` is signed by the owner.
CREATE TABLE organizations (
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
    kind TEXT NOT NULL CHECK (kind IN ('family', 'team')),
    owner_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    genesis TEXT NOT NULL,
    genesis_signature TEXT NOT NULL,
    encrypted_meta BYTEA NOT NULL,
    meta_epoch BIGINT NOT NULL,
    default_vault_id TEXT,
    revision BIGINT NOT NULL,
    seq BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE INDEX organizations_owner_id ON organizations (owner_id);

ALTER TABLE vaults ADD FOREIGN KEY (org_id) REFERENCES organizations (id) ON DELETE CASCADE;
-- The organization is created before its first vault (same transaction).
ALTER TABLE organizations ADD FOREIGN KEY (default_vault_id) REFERENCES vaults (id)
    ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED;

-- Members: `accepted` after accepting an invitation, `confirmed` once an
-- admin attested their key, `suspended` while blocked. Removed members are
-- deleted.
CREATE TABLE org_members (
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'guest')),
    status TEXT NOT NULL CHECK (status IN ('accepted', 'confirmed', 'suspended')),
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
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'guest')),
    token_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('pending', 'accepted', 'revoked')),
    created_by TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    accepted_by TEXT,
    accepted_at BIGINT
);
CREATE INDEX org_invitations_org_id ON org_invitations (org_id, status);
CREATE INDEX org_invitations_email ON org_invitations (email, status);

-- The organization key, sealed per member and epoch.
CREATE TABLE org_keys (
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    epoch BIGINT NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    sealed_key BYTEA NOT NULL,
    grant_data TEXT NOT NULL,
    grant_signature TEXT NOT NULL,
    seq BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (org_id, epoch, account_id)
);
CREATE INDEX org_keys_account_id ON org_keys (account_id);

-- Groups: principals with their own encryption key pair.
CREATE TABLE org_groups (
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    key_version BIGINT NOT NULL,
    bundle TEXT NOT NULL,
    bundle_signature TEXT NOT NULL,
    encrypted_meta BYTEA NOT NULL,
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
    sealed_key BYTEA NOT NULL,
    grant_data TEXT NOT NULL,
    grant_signature TEXT NOT NULL,
    seq BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (group_id, key_version, account_id)
);
CREATE INDEX group_members_account_id ON group_members (account_id);

-- Current members of shared vaults (the server's authorization source).
CREATE TABLE vault_members (
    vault_id TEXT NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    principal_type TEXT NOT NULL CHECK (principal_type IN ('account', 'group')),
    principal_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('view', 'edit', 'manage')),
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
    principal_type TEXT NOT NULL CHECK (principal_type IN ('account', 'group')),
    principal_id TEXT NOT NULL,
    sealed_key BYTEA NOT NULL,
    wrapped_key BYTEA,
    grant_data TEXT NOT NULL,
    grant_signature TEXT NOT NULL,
    seq BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (vault_id, key_epoch, principal_type, principal_id)
);
CREATE INDEX vault_keys_principal ON vault_keys (principal_type, principal_id);

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

-- --- Instance administration and mail ----------------------------------------------------

-- Mails waiting to be sent. A background task renders and sends them,
-- retrying with backoff. `params` holds the template parameters and is
-- cleared once the mail is sent, so links with tokens do not linger.
CREATE TABLE mail_outbox (
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
    recipient TEXT NOT NULL,
    template TEXT NOT NULL,
    locale TEXT NOT NULL,
    params JSONB NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'sent', 'failed')),
    attempts BIGINT NOT NULL CHECK (attempts >= 0),
    next_attempt_at BIGINT NOT NULL,
    -- A worker that picked the mail owns it until then.
    locked_until BIGINT NOT NULL,
    last_error TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    sent_at BIGINT NOT NULL
);
CREATE INDEX mail_outbox_status_next_attempt_at ON mail_outbox (status, next_attempt_at);

-- Invitations to register on an instance whose registration is not open.
-- Only the SHA-256 hash of the token in the invitation link is stored.
CREATE TABLE instance_invites (
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
    email TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    invited_by TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    -- 0 until the invitation was used to create an account.
    used_at BIGINT NOT NULL
);
CREATE INDEX instance_invites_email ON instance_invites (email);

-- Audit log of instance administration. Each row hashes its content
-- together with the previous row's hash, so a changed or deleted row breaks
-- the chain; the `admin_event_seq` counter reveals deleted rows at the end.
-- `details` is TEXT, not JSONB: the hash covers its exact text.
CREATE TABLE admin_events (
    seq BIGINT PRIMARY KEY,
    id TEXT NOT NULL UNIQUE,
    actor_id TEXT NOT NULL,
    actor_email TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    details TEXT NOT NULL,
    ip TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);

-- --- Account recovery, emergency access, adding devices (wave C) ---------------------------
-- See docs/architecture/recovery.md.

-- Personal recovery code: a second OPAQUE record whose password is derived
-- from the code, and the account key wrapped with a key derived from it.
CREATE TABLE account_recovery (
    account_id TEXT PRIMARY KEY REFERENCES accounts (id) ON DELETE CASCADE,
    opaque_record BYTEA NOT NULL,
    wrapped_account_key BYTEA NOT NULL,
    created_at BIGINT NOT NULL
);

-- First round of a recovery-code login (like login_attempts). `account_id`
-- is NULL for unknown emails or accounts without a recovery code.
CREATE TABLE recovery_attempts (
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
    account_id TEXT REFERENCES accounts (id) ON DELETE CASCADE,
    state BYTEA NOT NULL,
    email TEXT NOT NULL,
    ip TEXT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE INDEX recovery_attempts_expires_at ON recovery_attempts (expires_at);

-- A proven recovery (by code or an approved organization request) that may
-- set new credentials. Only the SHA-256 of the token is stored; single use.
-- `method` is `code` or `org`; `source_id` names the organization request.
-- `two_factor_pending` is set while a recovery by code still needs the
-- account's second factor.
CREATE TABLE recovery_sessions (
    token_hash TEXT PRIMARY KEY CHECK (passbox.valid_hash(token_hash)),
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    method TEXT NOT NULL CHECK (method IN ('code', 'org')),
    source_id TEXT NOT NULL,
    two_factor_pending BOOLEAN NOT NULL,
    device_name TEXT NOT NULL,
    client_kind TEXT NOT NULL,
    ip TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE INDEX recovery_sessions_account_id ON recovery_sessions (account_id);

-- Organization recovery. The recovery public key is signed by an admin;
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
    sealed_key BYTEA NOT NULL,
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
    sealed_key BYTEA NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (org_id, account_id)
);
CREATE INDEX org_recovery_escrows_account_id ON org_recovery_escrows (account_id);

-- Requests from a device that lost access (expiry is checked with
-- `expires_at`). Only the SHA-256 of the device's request token is stored.
CREATE TABLE org_recovery_requests (
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    ephemeral_key TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'completed', 'cancelled')),
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

-- Emergency access. `status`: invited (by email), accepted (the grantee
-- accepted), confirmed (keys sealed for the grantee). A request releases
-- the sealed keys after `wait_days` unless the grantor declines;
-- `approved_at` releases them early. `vault_ids` is the JSON array of the
-- grantor's personal vaults named in the signed grant.
CREATE TABLE emergency_grants (
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
    grantor_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    grantee_email TEXT NOT NULL,
    grantee_id TEXT REFERENCES accounts (id) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    wait_days BIGINT NOT NULL CHECK (wait_days >= 0),
    status TEXT NOT NULL CHECK (status IN ('invited', 'accepted', 'confirmed')),
    vault_ids JSONB NOT NULL CHECK (jsonb_typeof(vault_ids) = 'array'),
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

-- Adding a device by code. The signed-in device opens a link; the new
-- device claims it with an ephemeral key and a MAC under the code's secret
-- (which the server never sees).
CREATE TABLE device_links (
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    short_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('open', 'claimed', 'approved')),
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
CREATE INDEX device_links_account_id ON device_links (account_id);

-- --- Organization administration (wave D) ----------------------------------------------------
-- See docs/architecture/administration.md.

-- Every version of an organization's policy, signed by an owner or admin.
-- `rules` holds the rules parsed from the signed policy, for the server's
-- own enforcement; clients only trust the signed policy.
CREATE TABLE org_policies (
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    version BIGINT NOT NULL,
    policy TEXT NOT NULL,
    signature TEXT NOT NULL,
    signer_id TEXT NOT NULL,
    rules JSONB NOT NULL,
    seq BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (org_id, version)
);

-- The head of each organization's audit log. Appends lock this row, so
-- entries get consecutive sequence numbers. Entries up to `pruned_seq` were
-- deleted by the retention setting; `pruned_hash` is the hash of entry
-- `pruned_seq`, which the first remaining entry links to.
CREATE TABLE org_audit_heads (
    org_id TEXT PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    seq BIGINT NOT NULL,
    hash TEXT NOT NULL,
    pruned_seq BIGINT NOT NULL,
    pruned_hash TEXT NOT NULL
);

-- The audit log of an organization, hash-chained per organization (see
-- passbox_core::audit). `client_event` and `client_signature` hold events
-- reported by members' apps, signed with their account key; `client_nonce`
-- drops duplicates. `details` is TEXT: the hash covers its exact text.
CREATE TABLE org_audit_events (
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    seq BIGINT NOT NULL,
    id TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_email TEXT NOT NULL,
    device_name TEXT NOT NULL,
    client_kind TEXT NOT NULL,
    ip TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    details TEXT NOT NULL,
    client_event TEXT NOT NULL,
    client_signature TEXT NOT NULL,
    client_nonce TEXT,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    PRIMARY KEY (org_id, seq)
);
CREATE INDEX org_audit_events_created_at ON org_audit_events (org_id, created_at);
CREATE INDEX org_audit_events_actor ON org_audit_events (org_id, actor_id, seq);
CREATE INDEX org_audit_events_action ON org_audit_events (org_id, action, seq);
CREATE UNIQUE INDEX org_audit_events_client_nonce ON org_audit_events (org_id, client_nonce);

-- Server-side settings of an organization (the name stays encrypted with
-- the organization key). `audit_retention_days` 0 keeps entries forever.
CREATE TABLE org_settings (
    org_id TEXT PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    audit_retention_days BIGINT NOT NULL CHECK (audit_retention_days >= 0),
    updated_by TEXT NOT NULL,
    updated_at BIGINT NOT NULL
);

-- Security aggregates a member's app reports: numbers only, never items or
-- passwords. `password_policy` is 1 if the master password met the
-- organization's minimum strength when last entered, 0 if not, -1 unknown.
CREATE TABLE org_security_reports (
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    score BIGINT NOT NULL,
    total BIGINT NOT NULL CHECK (total >= 0),
    weak BIGINT NOT NULL CHECK (weak >= 0),
    reused BIGINT NOT NULL CHECK (reused >= 0),
    unsecured BIGINT NOT NULL CHECK (unsecured >= 0),
    password_policy BIGINT NOT NULL CHECK (password_policy IN (-1, 0, 1)),
    reported_at BIGINT NOT NULL,
    PRIMARY KEY (org_id, account_id)
);

-- Tokens for the events API (SIEM pull). Only the SHA-256 of the token is
-- stored. `revoked_at` 0 means active.
CREATE TABLE org_event_tokens (
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    last_used_at BIGINT NOT NULL,
    revoked_at BIGINT NOT NULL
);
CREATE INDEX org_event_tokens_org_id ON org_event_tokens (org_id);

-- Webhooks that receive new audit entries (push). The secret signs each
-- delivery (HMAC-SHA256); `cursor_seq` is the last delivered entry.
CREATE TABLE org_webhooks (
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    active BOOLEAN NOT NULL,
    cursor_seq BIGINT NOT NULL,
    failures BIGINT NOT NULL CHECK (failures >= 0),
    next_attempt_at BIGINT NOT NULL,
    locked_until BIGINT NOT NULL,
    last_status BIGINT NOT NULL,
    last_error TEXT NOT NULL,
    last_delivery_at BIGINT NOT NULL,
    created_by TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX org_webhooks_org_id ON org_webhooks (org_id);

-- --- Single sign-on and SCIM (wave E) ------------------------------------------------------
-- See docs/architecture/sso.md.

-- OIDC configuration of an organization. The client secret is encrypted
-- with the server's `sso_key` (associated data names the organization).
-- `discovery` and `jwks` cache the provider's metadata and signing keys
-- ('' until fetched).
CREATE TABLE org_sso (
    org_id TEXT PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL,
    required BOOLEAN NOT NULL,
    allow_device_unlock BOOLEAN NOT NULL,
    provider TEXT NOT NULL,
    display_name TEXT NOT NULL,
    issuer TEXT NOT NULL,
    client_id TEXT NOT NULL,
    encrypted_client_secret TEXT NOT NULL,
    token_auth_method TEXT NOT NULL,
    scopes TEXT NOT NULL,
    email_claim TEXT NOT NULL,
    require_verified_email BOOLEAN NOT NULL,
    name_claim TEXT NOT NULL,
    groups_claim TEXT NOT NULL,
    allowed_domains TEXT NOT NULL,
    reauth_hours BIGINT NOT NULL CHECK (reauth_hours >= 0),
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
    domain TEXT PRIMARY KEY CHECK (domain = lower(domain)),
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE
);
CREATE INDEX sso_domains_org_id ON sso_domains (org_id);

-- Identity provider accounts linked to Passbox accounts (by `sub`).
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
CREATE INDEX sso_flows_expires_at ON sso_flows (expires_at);

-- Results of the provider's callback, redeemed once by the client that
-- started the flow (5 minutes). `outcome` is `ok` or an error code.
CREATE TABLE sso_tickets (
    ticket_hash TEXT PRIMARY KEY,
    binding_hash TEXT NOT NULL,
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    purpose TEXT NOT NULL,
    outcome TEXT NOT NULL,
    account_id TEXT REFERENCES accounts (id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    result TEXT NOT NULL,
    initiated_by TEXT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE INDEX sso_tickets_expires_at ON sso_tickets (expires_at);

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
CREATE INDEX sso_proofs_account_id ON sso_proofs (account_id);

-- Devices that unlock with SSO instead of the master password. The account
-- key is sealed to the device's X-Wing key; `grant_data` is signed with the
-- account's signing key.
CREATE TABLE trusted_devices (
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
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
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
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
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
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
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    external_id TEXT NOT NULL,
    user_name TEXT NOT NULL,
    user_name_key TEXT NOT NULL,
    email TEXT NOT NULL,
    display_name TEXT NOT NULL,
    given_name TEXT NOT NULL,
    family_name TEXT NOT NULL,
    active BOOLEAN NOT NULL,
    account_id TEXT REFERENCES accounts (id) ON DELETE SET NULL,
    suspended_from TEXT NOT NULL,
    version BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE (org_id, user_name_key)
);
CREATE INDEX scim_users_email ON scim_users (org_id, email);
CREATE INDEX scim_users_account_id ON scim_users (account_id);

CREATE TABLE scim_groups (
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
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

-- --- Service accounts and AI agents (wave F) ----------------------------------------------
-- See docs/architecture/service-accounts.md and docs/architecture/ai-agents.md.

-- A machine identity owned by an account. The server stores the hash of
-- the token's authentication key only; the private key is encrypted with a
-- key derived from the token's secret, which never reaches the server.
CREATE TABLE service_accounts (
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    public_key_signature TEXT NOT NULL,
    encrypted_private BYTEA NOT NULL,
    auth_hash TEXT NOT NULL UNIQUE,
    expires_at BIGINT NOT NULL,
    revoked_at BIGINT NOT NULL,
    last_used_at BIGINT NOT NULL,
    last_used_ip TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX service_accounts_account_id ON service_accounts (account_id);

-- Vault keys sealed to a service account and signed by its owner, one row
-- per vault and key epoch. Access is also limited to what the owner can
-- still do with the vault.
CREATE TABLE service_account_grants (
    service_account_id TEXT NOT NULL REFERENCES service_accounts (id) ON DELETE CASCADE,
    vault_id TEXT NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    key_epoch BIGINT NOT NULL,
    permission TEXT NOT NULL CHECK (permission IN ('read', 'write')),
    sealed_key BYTEA NOT NULL,
    grant_data TEXT NOT NULL,
    grant_signature TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (service_account_id, vault_id, key_epoch)
);
CREATE INDEX service_account_grants_vault_id ON service_account_grants (vault_id);

-- What a service account did (reads, writes), for its owner.
CREATE TABLE service_account_events (
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
    service_account_id TEXT NOT NULL REFERENCES service_accounts (id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    detail TEXT NOT NULL,
    ip TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX service_account_events_sa ON service_account_events (service_account_id, created_at);

-- Grant requests of AI agents (pbx mcp), relayed to the account's other
-- signed-in devices. `request` is the canonical request the agent's broker
-- made; `decision` and `decision_signature` come from the approving device.
-- `principal_kind` is `session` or `service`.
CREATE TABLE agent_grants (
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    principal_kind TEXT NOT NULL CHECK (principal_kind IN ('session', 'service')),
    principal_id TEXT NOT NULL,
    client_name TEXT NOT NULL,
    request TEXT NOT NULL,
    status TEXT NOT NULL,
    decision TEXT,
    decision_signature TEXT,
    decided_device TEXT NOT NULL,
    not_after BIGINT NOT NULL,
    ip TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    decided_at BIGINT NOT NULL
);
CREATE INDEX agent_grants_account_status ON agent_grants (account_id, status);

-- Agent actions reported by the broker. Never values: the command is
-- stored as its first word plus a SHA-256 hash.
CREATE TABLE agent_events (
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    grant_id TEXT NOT NULL,
    principal_kind TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    client_name TEXT NOT NULL,
    tool TEXT NOT NULL,
    item_ids TEXT NOT NULL,
    target TEXT NOT NULL,
    result TEXT NOT NULL,
    ip TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX agent_events_account ON agent_events (account_id, created_at);

-- --- Email breach monitoring -------------------------------------------------------------
-- Users opt in per email address after confirming it with a code sent to
-- that address. Only the address and the breach list are stored.

CREATE TABLE breach_monitor_emails (
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    email TEXT NOT NULL CHECK (email = lower(email)),
    -- 0 until the address is confirmed.
    verified_at BIGINT NOT NULL,
    -- SHA-256 (hex) of the pending confirmation code, '' when none.
    code_hash TEXT NOT NULL,
    code_expires_at BIGINT NOT NULL,
    code_attempts BIGINT NOT NULL CHECK (code_attempts >= 0),
    -- When the last confirmation mail was sent (resend limit).
    code_sent_at BIGINT NOT NULL,
    -- Last successful check (0 = never) and the last error, if any.
    checked_at BIGINT NOT NULL,
    check_error TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    UNIQUE (account_id, email)
);
CREATE INDEX breach_monitor_emails_due ON breach_monitor_emails (verified_at, checked_at);

-- Breaches a confirmed address was found in (Have I Been Pwned "breach
-- model"). `first_seen_at` is when this server first saw the address in the
-- breach; new rows after the first check are mailed to the user.
CREATE TABLE breach_monitor_results (
    email_id TEXT NOT NULL REFERENCES breach_monitor_emails (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    title TEXT NOT NULL,
    domain TEXT NOT NULL,
    breach_date TEXT NOT NULL,
    added_date TEXT NOT NULL,
    pwn_count BIGINT NOT NULL,
    data_classes JSONB NOT NULL CHECK (jsonb_typeof(data_classes) = 'array'),
    first_seen_at BIGINT NOT NULL,
    PRIMARY KEY (email_id, name)
);

-- --- Attachments, share links and access requests ---------------------------------------
-- See docs/architecture/sharing.md and docs/architecture/attachments.md.

-- Encrypted file attachments. The blob is stored outside the database
-- (PASSBOX_BLOB_DIR); its key, name and type are inside the encrypted
-- item. `owner_type`/`owner_id` is who the storage counts against: the
-- account for personal vaults, the organization for shared vaults.
CREATE TABLE attachments (
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
    item_id TEXT NOT NULL REFERENCES items (id) ON DELETE CASCADE,
    vault_id TEXT NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    uploaded_by TEXT NOT NULL,
    owner_type TEXT NOT NULL CHECK (owner_type IN ('account', 'org')),
    owner_id TEXT NOT NULL,
    size BIGINT NOT NULL CHECK (size >= 0),
    created_at BIGINT NOT NULL
);
CREATE INDEX attachments_item_id ON attachments (item_id);
CREATE INDEX attachments_vault_id ON attachments (vault_id);
CREATE INDEX attachments_owner ON attachments (owner_type, owner_id);

-- Share links to people without an account. The server stores the
-- encrypted snapshot and the hash of the access token; the key is only in
-- the link's fragment. `encrypted_label` is encrypted with the creator's
-- account key. `org_id`/`vault_id` name where the shared item came from,
-- for the organization's policy.
CREATE TABLE share_links (
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    org_id TEXT,
    vault_id TEXT,
    encrypted_label BYTEA NOT NULL,
    blob BYTEA NOT NULL,
    auth_hash TEXT NOT NULL,
    salt TEXT,
    expires_at BIGINT NOT NULL,
    max_views BIGINT NOT NULL CHECK (max_views >= 0),
    views BIGINT NOT NULL CHECK (views >= 0),
    failed_attempts BIGINT NOT NULL CHECK (failed_attempts >= 0),
    created_at BIGINT NOT NULL,
    last_viewed_at BIGINT NOT NULL
);
CREATE INDEX share_links_account_id ON share_links (account_id);
CREATE INDEX share_links_expires_at ON share_links (expires_at);
CREATE INDEX share_links_org_id ON share_links (org_id);

-- "Request access" to a shared vault. A manager approves by sharing the
-- vault (a signed manifest version, as always) or denies.
CREATE TABLE access_requests (
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
    vault_id TEXT NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('view', 'edit', 'manage')),
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'cancelled')),
    created_at BIGINT NOT NULL,
    decided_by TEXT,
    decided_at BIGINT NOT NULL
);
CREATE INDEX access_requests_vault ON access_requests (vault_id, status);
CREATE INDEX access_requests_account ON access_requests (account_id);
CREATE INDEX access_requests_org ON access_requests (org_id, status);
