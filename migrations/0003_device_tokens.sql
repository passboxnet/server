-- Device tokens identify devices that have signed in successfully before.
-- A login that presents a valid one is exempt from the per-email lockout, so
-- failed logins from elsewhere cannot lock a user out of their own devices.
-- Only SHA-256 hashes of the tokens are stored.
CREATE TABLE device_tokens (
    token_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE INDEX device_tokens_account_id ON device_tokens (account_id);

-- The device token issued together with a session, so a password change can
-- keep the current device's token while invalidating all others.
ALTER TABLE sessions ADD COLUMN device_token_hash TEXT NOT NULL DEFAULT '';

-- The valid device token a login was started with ('' for none), so a
-- failure is counted against the right limits.
ALTER TABLE login_attempts ADD COLUMN device_token_hash TEXT NOT NULL DEFAULT '';
