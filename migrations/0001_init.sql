-- Portable SQL: runs unchanged on SQLite and PostgreSQL.
-- Binary values are stored as unpadded Base64url text, timestamps as Unix milliseconds.

CREATE TABLE server_secrets (
    name TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Global change counter. Every write takes the next value, and clients sync
-- everything with a higher value than their cursor.
CREATE TABLE counters (
    name TEXT PRIMARY KEY,
    value BIGINT NOT NULL
);
INSERT INTO counters (name, value) VALUES ('change_seq', 0);

CREATE TABLE accounts (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    opaque_record TEXT NOT NULL,
    kdf_salt TEXT NOT NULL,
    kdf_memory_kib BIGINT NOT NULL,
    kdf_iterations BIGINT NOT NULL,
    kdf_parallelism BIGINT NOT NULL,
    encrypted_account_key TEXT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE INDEX sessions_account_id ON sessions (account_id);

-- Pending OPAQUE logins between the start and finish requests.
CREATE TABLE login_attempts (
    id TEXT PRIMARY KEY,
    account_id TEXT,
    state TEXT NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE TABLE vaults (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    encrypted_key TEXT NOT NULL,
    encrypted_meta TEXT NOT NULL,
    revision BIGINT NOT NULL,
    seq BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE INDEX vaults_account_id_seq ON vaults (account_id, seq);

CREATE TABLE items (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    encrypted_data TEXT,
    revision BIGINT NOT NULL,
    deleted BIGINT NOT NULL,
    seq BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE INDEX items_vault_id_seq ON items (vault_id, seq);
