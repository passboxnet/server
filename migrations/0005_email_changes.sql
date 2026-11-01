-- Changing the account's email address. The new address is confirmed with a
-- code mailed to it before it replaces the old one; at most one change is
-- pending per account. The address is only a sign-in name: the OPAQUE
-- credentials are bound to the account ID, and no key is derived from it.

CREATE TABLE email_changes (
    account_id TEXT PRIMARY KEY REFERENCES accounts (id) ON DELETE CASCADE,
    new_email TEXT NOT NULL CHECK (new_email = lower(new_email) AND new_email LIKE '%_@_%'
                                   AND length(new_email) <= 254),
    -- SHA-256 (hex) of the confirmation code.
    code_hash TEXT NOT NULL CHECK (passbox.valid_hash(code_hash)),
    code_expires_at BIGINT NOT NULL,
    code_attempts BIGINT NOT NULL CHECK (code_attempts >= 0),
    -- When the code was mailed (resend limit).
    created_at BIGINT NOT NULL
);

ALTER TABLE email_changes ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON email_changes
    USING (account_id = passbox.account_id()) WITH CHECK (account_id = passbox.account_id());

DO $$
DECLARE
    can_bypass BOOLEAN;
BEGIN
    SELECT rolsuper OR rolbypassrls INTO can_bypass FROM pg_roles WHERE rolname = current_user;
    IF can_bypass THEN
        ALTER TABLE email_changes FORCE ROW LEVEL SECURITY;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'passbox_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON email_changes TO passbox_app;
    END IF;
END
$$;
