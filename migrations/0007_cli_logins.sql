-- Signing in a device without a session (`pbx login`) from a signed-in
-- browser (passboxnet/core: docs/architecture/recovery.md, "Signing in pbx
-- from the browser").
--
-- The requesting device registers a request without a session: an ID it
-- chose, its ephemeral public key, its name and a MAC under a secret that
-- only travels in the fragment of the link the user opens (the server never
-- sees it). It keeps a poll token; the server stores only its hash. A
-- signed-in account approves (uploading the account details sealed to the
-- ephemeral key) or denies. The requesting device receives the answer once,
-- then the row is deleted. Requests expire after 10 minutes.

CREATE TABLE cli_logins (
    id TEXT PRIMARY KEY CHECK (passbox.valid_id(id)),
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied')),
    -- Base64url X-Wing public key (1216 bytes) and HMAC-SHA256.
    ephemeral_key TEXT NOT NULL CHECK (length(ephemeral_key) BETWEEN 1 AND 2048),
    mac TEXT NOT NULL CHECK (length(mac) = 43),
    -- SHA-256 (hex) of the poll token the requesting device keeps.
    poll_token_hash TEXT NOT NULL UNIQUE CHECK (passbox.valid_hash(poll_token_hash)),
    device_name TEXT NOT NULL CHECK (length(device_name) <= 80),
    created_ip TEXT NOT NULL CHECK (length(created_ip) <= 64),
    -- The account that answered; NULL while pending.
    account_id TEXT REFERENCES accounts (id) ON DELETE CASCADE,
    approver_device_name TEXT NOT NULL DEFAULT '' CHECK (length(approver_device_name) <= 80),
    sealed_payload TEXT NOT NULL DEFAULT '' CHECK (length(sealed_payload) <= 16384),
    created_at BIGINT NOT NULL,
    decided_at BIGINT NOT NULL DEFAULT 0,
    expires_at BIGINT NOT NULL,
    CHECK ((status = 'pending') = (account_id IS NULL))
);
CREATE INDEX cli_logins_created_ip ON cli_logins (created_ip);
CREATE INDEX cli_logins_expires_at ON cli_logins (expires_at);

-- The requesting device creates, polls and cancels in the sign-in context.
-- Signed-in accounts never see the table directly: they read and answer one
-- pending request by its ID through the functions below.
ALTER TABLE cli_logins ENABLE ROW LEVEL SECURITY;
CREATE POLICY auth ON cli_logins USING (passbox.in_auth()) WITH CHECK (passbox.in_auth());

-- A pending request by ID, for a signed-in account that opened its link.
CREATE FUNCTION passbox.pending_cli_login(request TEXT, now BIGINT)
    RETURNS TABLE (id TEXT, device_name TEXT, created_ip TEXT, created_at BIGINT,
                   expires_at BIGINT, ephemeral_key TEXT, mac TEXT)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$
        SELECT c.id, c.device_name, c.created_ip, c.created_at, c.expires_at, c.ephemeral_key, c.mac
        FROM cli_logins c
        WHERE c.id = request AND c.status = 'pending' AND c.expires_at > now
          AND passbox.account_id() IS NOT NULL
    $$;

-- Approves (with the sealed payload) or denies a pending request for the
-- signed-in account. True if the request was still pending.
CREATE FUNCTION passbox.decide_cli_login(request TEXT, decision TEXT, sealed TEXT,
                                         approver TEXT, now BIGINT)
    RETURNS BOOLEAN
    LANGUAGE sql VOLATILE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$
        WITH decided AS (
            UPDATE cli_logins
            SET status = decision, account_id = passbox.account_id(), sealed_payload = sealed,
                approver_device_name = approver, decided_at = now
            WHERE id = request AND status = 'pending' AND expires_at > now
              AND decision IN ('approved', 'denied')
              AND passbox.account_id() IS NOT NULL
            RETURNING 1
        )
        SELECT EXISTS (SELECT 1 FROM decided)
    $$;

REVOKE EXECUTE ON FUNCTION passbox.pending_cli_login(TEXT, BIGINT) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION passbox.decide_cli_login(TEXT, TEXT, TEXT, TEXT, BIGINT) FROM PUBLIC;

DO $$
DECLARE
    can_bypass BOOLEAN;
BEGIN
    SELECT rolsuper OR rolbypassrls INTO can_bypass FROM pg_roles WHERE rolname = current_user;
    IF can_bypass THEN
        ALTER TABLE cli_logins FORCE ROW LEVEL SECURITY;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'passbox_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON cli_logins TO passbox_app;
        GRANT EXECUTE ON FUNCTION passbox.pending_cli_login(TEXT, BIGINT),
            passbox.decide_cli_login(TEXT, TEXT, TEXT, TEXT, BIGINT) TO passbox_app;
    END IF;
END
$$;
