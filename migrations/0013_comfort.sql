-- Moving items between vaults (B5), file attachments (G2), share links
-- (B7) and access requests (B9).
-- Portable SQL (SQLite and PostgreSQL): Base64url text for binary values,
-- Unix milliseconds for times (0 = not set), BIGINT for numbers and flags.
-- See docs/architecture/sharing.md and docs/architecture/attachments.md.

-- Where an item was before it moved to another vault, so devices of members
-- of the old vault learn that it left (sync sends a tombstone for the old
-- vault). The item itself keeps its ID, creation date and history.
CREATE TABLE item_moves (
    item_id TEXT NOT NULL,
    from_vault_id TEXT NOT NULL,
    to_vault_id TEXT NOT NULL,
    revision BIGINT NOT NULL,
    seq BIGINT NOT NULL,
    moved_at BIGINT NOT NULL
);
CREATE INDEX item_moves_from_vault ON item_moves (from_vault_id, seq);

-- Encrypted file attachments. The blob is stored outside the database
-- (PASSBOX_BLOB_DIR); its key, name and type are inside the encrypted
-- item. `owner_type`/`owner_id` is who the storage counts against: the
-- account for personal vaults, the organization for shared vaults.
CREATE TABLE attachments (
    id TEXT PRIMARY KEY,
    item_id TEXT NOT NULL REFERENCES items (id) ON DELETE CASCADE,
    vault_id TEXT NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    uploaded_by TEXT NOT NULL,
    owner_type TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    size BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX attachments_item_id ON attachments (item_id);
CREATE INDEX attachments_owner ON attachments (owner_type, owner_id);

-- Share links to people without an account. The server stores the
-- encrypted snapshot and the hash of the access token; the key is only in
-- the link's fragment. `encrypted_label` is encrypted with the creator's
-- account key (for their list of links). `org_id`/`vault_id` name where
-- the shared item came from, for the organization's policy (D2).
CREATE TABLE share_links (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    org_id TEXT,
    vault_id TEXT,
    encrypted_label TEXT NOT NULL,
    blob TEXT NOT NULL,
    auth_hash TEXT NOT NULL,
    salt TEXT,
    expires_at BIGINT NOT NULL,
    max_views BIGINT NOT NULL,
    views BIGINT NOT NULL,
    failed_attempts BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    last_viewed_at BIGINT NOT NULL
);
CREATE INDEX share_links_account_id ON share_links (account_id);
CREATE INDEX share_links_expires_at ON share_links (expires_at);

-- "Request access" to a shared vault. A manager approves by sharing the
-- vault (a signed manifest version, as always) or denies.
-- `status`: pending | approved | denied | cancelled.
CREATE TABLE access_requests (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    org_id TEXT NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    decided_by TEXT,
    decided_at BIGINT NOT NULL
);
CREATE INDEX access_requests_vault ON access_requests (vault_id, status);
CREATE INDEX access_requests_account ON access_requests (account_id);
