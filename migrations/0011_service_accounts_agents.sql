-- Service accounts (F2) and agent grants (F7).
-- Portable SQL (SQLite and PostgreSQL): Base64url text for binary values,
-- Unix milliseconds for times (0 = not set), BIGINT for numbers and flags.
-- See docs/architecture/service-accounts.md and docs/architecture/ai-agents.md.

-- A machine identity owned by an account. The server stores the hash of
-- the token's authentication key only; the private key is encrypted with a
-- key derived from the token's secret, which never reaches the server.
-- The name is visible to the server (like a device name).
CREATE TABLE service_accounts (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    public_key_signature TEXT NOT NULL,
    encrypted_private TEXT NOT NULL,
    auth_hash TEXT NOT NULL UNIQUE,
    expires_at BIGINT NOT NULL,
    revoked_at BIGINT NOT NULL,
    last_used_at BIGINT NOT NULL,
    last_used_ip TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX service_accounts_account_id ON service_accounts (account_id);

-- Vault keys sealed to a service account and signed by its owner, one row
-- per vault and key epoch. `permission` is `read` or `write`. Access is
-- also limited to what the owner can still do with the vault.
CREATE TABLE service_account_grants (
    service_account_id TEXT NOT NULL REFERENCES service_accounts (id) ON DELETE CASCADE,
    vault_id TEXT NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    key_epoch BIGINT NOT NULL,
    permission TEXT NOT NULL,
    sealed_key TEXT NOT NULL,
    grant_data TEXT NOT NULL,
    grant_signature TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (service_account_id, vault_id, key_epoch)
);
CREATE INDEX service_account_grants_vault_id ON service_account_grants (vault_id);

-- What a service account did (reads, writes), for its owner.
CREATE TABLE service_account_events (
    id TEXT PRIMARY KEY,
    service_account_id TEXT NOT NULL REFERENCES service_accounts (id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    detail TEXT NOT NULL,
    ip TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX service_account_events_sa ON service_account_events (service_account_id, created_at);

-- Grant requests of AI agents (pbx mcp), relayed to the account's other
-- signed-in devices. `request` is the canonical request the agent's broker
-- made; `decision` and `decision_signature` come from the approving
-- device (Ed25519, account key). `status`: pending | approved | denied.
-- `principal_kind` is `session` or `service`.
CREATE TABLE agent_grants (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    principal_kind TEXT NOT NULL,
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

-- Agent actions reported by the broker (K12). Never values: the command is
-- stored as its first word plus a SHA-256 hash.
CREATE TABLE agent_events (
    id TEXT PRIMARY KEY,
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
