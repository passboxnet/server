-- Item version history ("Eintragsverlauf").
-- Portable SQL (SQLite and PostgreSQL): Base64url text for ciphertexts,
-- Unix milliseconds for times.
--
-- Every update of an item keeps the replaced row here, still encrypted and
-- bound to its own revision and key epoch. The server keeps the newest 20
-- versions per item; they disappear when the item is deleted permanently
-- (tombstone) or its vault is deleted.

-- The session (device) that wrote the current version; NULL for rows
-- written before this migration.
ALTER TABLE items ADD COLUMN updated_by TEXT;

CREATE TABLE item_versions (
    item_id TEXT NOT NULL REFERENCES items (id) ON DELETE CASCADE,
    revision BIGINT NOT NULL,
    key_epoch BIGINT NOT NULL,
    encrypted_data TEXT NOT NULL,
    updated_at BIGINT NOT NULL,
    updated_by TEXT,
    PRIMARY KEY (item_id, revision)
);
