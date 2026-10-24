-- Organization administration (wave D): signed policies, the
-- organization audit log, organization settings, security reports and the
-- events API with webhooks. Portable SQL (SQLite and PostgreSQL): Base64url
-- or hex text for binary values, Unix milliseconds for times (0 = not set),
-- BIGINT for numbers and flags. See docs/architecture/administration.md.

-- Every version of an organization's policy, signed by an owner or admin.
-- `rules` is the JSON of the rules parsed from the signed policy, for the
-- server's own enforcement; clients only trust the signed policy.
CREATE TABLE org_policies (
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    version BIGINT NOT NULL,
    policy TEXT NOT NULL,
    signature TEXT NOT NULL,
    signer_id TEXT NOT NULL,
    rules TEXT NOT NULL,
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
-- drops duplicates.
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
    audit_retention_days BIGINT NOT NULL,
    updated_by TEXT NOT NULL,
    updated_at BIGINT NOT NULL
);

-- Security aggregates a member's app reports (D6): numbers only, never
-- items or passwords. `password_policy` is 1 if the master password met the
-- organization's minimum strength when last entered, 0 if not, -1 unknown.
CREATE TABLE org_security_reports (
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    score BIGINT NOT NULL,
    total BIGINT NOT NULL,
    weak BIGINT NOT NULL,
    reused BIGINT NOT NULL,
    unsecured BIGINT NOT NULL,
    password_policy BIGINT NOT NULL,
    reported_at BIGINT NOT NULL,
    PRIMARY KEY (org_id, account_id)
);

-- Tokens for the events API (D5, SIEM pull). Only the SHA-256 of the token
-- is stored. `revoked_at` 0 means active.
CREATE TABLE org_event_tokens (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    last_used_at BIGINT NOT NULL,
    revoked_at BIGINT NOT NULL
);
CREATE INDEX org_event_tokens_org_id ON org_event_tokens (org_id);

-- Webhooks that receive new audit entries (D5, push). The secret signs
-- each delivery (HMAC-SHA256); `cursor_seq` is the last delivered entry.
CREATE TABLE org_webhooks (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    active BIGINT NOT NULL,
    cursor_seq BIGINT NOT NULL,
    failures BIGINT NOT NULL,
    next_attempt_at BIGINT NOT NULL,
    locked_until BIGINT NOT NULL,
    last_status BIGINT NOT NULL,
    last_error TEXT NOT NULL,
    last_delivery_at BIGINT NOT NULL,
    created_by TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX org_webhooks_org_id ON org_webhooks (org_id);
