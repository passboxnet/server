-- Sessions become visible and revocable per device, and accounts get an
-- activity log. Existing sessions are dropped; clients sign in again.
DELETE FROM sessions;
ALTER TABLE sessions ADD COLUMN id TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN device_name TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN client_kind TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN ip TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN last_used_at BIGINT NOT NULL DEFAULT 0;
CREATE UNIQUE INDEX sessions_id ON sessions (id);

-- Login attempts remember who started them, so failures can be logged.
ALTER TABLE login_attempts ADD COLUMN ip TEXT NOT NULL DEFAULT '';
ALTER TABLE login_attempts ADD COLUMN email TEXT NOT NULL DEFAULT '';

CREATE TABLE account_events (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    device_name TEXT NOT NULL,
    client_kind TEXT NOT NULL,
    ip TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX account_events_account_id_created_at ON account_events (account_id, created_at);
