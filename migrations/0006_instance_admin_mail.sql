-- Instance administration and outgoing mail.

-- Account flags. `instance_admin` is 0 or 1; `disabled_at` is 0 for active
-- accounts. `locale` is the account's language for mail ('' = instance
-- default); `notify_new_device` turns the new-device sign-in mail on (1) or
-- off (0).
ALTER TABLE accounts ADD COLUMN instance_admin BIGINT NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN disabled_at BIGINT NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN locale TEXT NOT NULL DEFAULT '';
ALTER TABLE accounts ADD COLUMN notify_new_device BIGINT NOT NULL DEFAULT 1;

-- Instance-wide state as named JSON documents: `settings` (registration
-- mode, instance name, ...) and `first_admin` (the account that became
-- instance admin by registering first; its unique name makes sure only one
-- account does, even when two register at the same time).
CREATE TABLE instance_state (
    name TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at BIGINT NOT NULL
);

-- Servers upgraded from an earlier version already have accounts: the
-- oldest one becomes instance admin.
UPDATE accounts SET instance_admin = 1
    WHERE id = (SELECT id FROM accounts ORDER BY created_at, id LIMIT 1);
INSERT INTO instance_state (name, value, updated_at)
    SELECT 'first_admin', id, created_at FROM accounts WHERE instance_admin = 1;

-- Mails waiting to be sent. A background task renders and sends them,
-- retrying with backoff. `params` holds the template parameters as JSON and
-- is cleared once the mail is sent, so links with tokens do not linger.
CREATE TABLE mail_outbox (
    id TEXT PRIMARY KEY,
    recipient TEXT NOT NULL,
    template TEXT NOT NULL,
    locale TEXT NOT NULL,
    params TEXT NOT NULL,
    -- pending, sent or failed (gave up after the last retry)
    status TEXT NOT NULL,
    attempts BIGINT NOT NULL,
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
    id TEXT PRIMARY KEY,
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
INSERT INTO counters (name, value) VALUES ('admin_event_seq', 0);
