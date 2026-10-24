-- Login two-factor authentication: a second step after the OPAQUE login.
-- None of these values protects vault data; they protect server sessions.

-- The login TOTP of an account, encrypted with the server's two-factor key
-- (XChaCha20-Poly1305, bound to the account ID). `confirmed` is 0 while the
-- user has not yet entered a first code. `last_step` is the last accepted
-- time step, so a code cannot be used twice.
CREATE TABLE two_factor_totp (
    account_id TEXT PRIMARY KEY REFERENCES accounts (id) ON DELETE CASCADE,
    sealed_secret TEXT NOT NULL,
    confirmed BIGINT NOT NULL,
    last_step BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);

-- WebAuthn security keys and passkeys registered as a second factor.
CREATE TABLE webauthn_credentials (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL,
    public_key TEXT NOT NULL,
    algorithm BIGINT NOT NULL,
    sign_count BIGINT NOT NULL,
    rp_id TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    last_used_at BIGINT NOT NULL
);
CREATE UNIQUE INDEX webauthn_credentials_credential_id ON webauthn_credentials (credential_id);
CREATE INDEX webauthn_credentials_account_id ON webauthn_credentials (account_id);

-- One-time recovery codes, as SHA-256 hashes. A used code is deleted.
CREATE TABLE recovery_codes (
    code_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    created_at BIGINT NOT NULL
);
CREATE INDEX recovery_codes_account_id ON recovery_codes (account_id);

-- Pending second steps: a login waiting for its second factor, a WebAuthn
-- registration, or a check of a second factor (for example before turning
-- two-factor authentication off). Only SHA-256 hashes of the tokens are
-- stored; each one expires after a few minutes.
CREATE TABLE two_factor_challenges (
    token_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    purpose TEXT NOT NULL,
    webauthn_challenge TEXT NOT NULL,
    rp_id TEXT NOT NULL,
    device_name TEXT NOT NULL,
    client_kind TEXT NOT NULL,
    ip TEXT NOT NULL,
    device_token_hash TEXT NOT NULL,
    attempts BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);
CREATE INDEX two_factor_challenges_account_id ON two_factor_challenges (account_id);

-- "Remember this device": until this time (Unix ms) a login presenting this
-- device token skips the second step. 0 means not remembered.
ALTER TABLE device_tokens ADD COLUMN two_factor_until BIGINT NOT NULL DEFAULT 0;
