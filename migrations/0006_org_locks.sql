-- Read-only organizations and the extension context (crate::ext).
--
-- An organization with a row in org_locks is read-only: members keep
-- reading, syncing and exporting, admins can still remove and suspend
-- members and delete the organization, but vault contents and the
-- organization's setup cannot change. The server itself never locks an
-- organization; an extension does (for example a hosting layer), and
-- `source` names which one, so each removes only its own lock.
--
-- The `ext` system context is for such extensions. It reads organizations,
-- their members and invitations, the email of accounts by ID (through
-- passbox.ext_accounts), and reads and writes org_locks. Nothing else.

CREATE TABLE org_locks (
    org_id TEXT PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    -- Shown to members, for example "the subscription ended".
    reason TEXT NOT NULL CHECK (length(reason) <= 500),
    -- Who set the lock, for example "billing".
    source TEXT NOT NULL CHECK (length(source) BETWEEN 1 AND 100),
    locked_at BIGINT NOT NULL CHECK (locked_at >= 0)
);

ALTER TABLE org_locks ENABLE ROW LEVEL SECURITY;
CREATE POLICY member_read ON org_locks FOR SELECT
    USING (passbox.is_org_member(org_id) OR passbox.in_org_context(org_id, ARRAY['scim', 'sso', 'org_events']));
CREATE POLICY ext ON org_locks FOR ALL
    USING (passbox.system() = 'ext') WITH CHECK (passbox.system() = 'ext');

-- The extension context reads the organizations with members and
-- invitations (no writes).
CREATE POLICY ext_read ON organizations FOR SELECT USING (passbox.system() = 'ext');
CREATE POLICY ext_read ON org_members FOR SELECT USING (passbox.system() = 'ext');
CREATE POLICY ext_read ON org_invitations FOR SELECT USING (passbox.system() = 'ext');

-- ID and email of accounts, for the extension context only.
CREATE FUNCTION passbox.ext_accounts(ids TEXT[])
    RETURNS TABLE (id TEXT, email TEXT)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$ SELECT id, email FROM accounts WHERE id = ANY (ids) AND passbox.system() = 'ext' $$;

-- The numbers of an organization that limits are checked against, and its
-- lock. `seats` counts owners, admins and members in any status; `people`
-- adds pending invitations that are not for guests (one per email, none for
-- people who are members already). Guests never count. Answers for members,
-- for invitees (who are not members yet), for the SCIM and SSO contexts of
-- the organization and for the extension context.
CREATE FUNCTION passbox.org_facts(org TEXT, now BIGINT)
    RETURNS TABLE (kind TEXT, owner_id TEXT, seats BIGINT, people BIGINT,
                   lock_reason TEXT, lock_source TEXT)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$
        WITH seats AS (
            SELECT count(*) AS n FROM org_members WHERE org_id = org AND role <> 'guest'
        ), invited AS (
            SELECT count(DISTINCT i.email) AS n FROM org_invitations i
            WHERE i.org_id = org AND i.status = 'pending' AND i.expires_at > now AND i.role <> 'guest'
              AND NOT EXISTS (
                  SELECT 1 FROM org_members m JOIN accounts a ON a.id = m.account_id
                  WHERE m.org_id = org AND a.email = i.email)
        )
        SELECT o.kind, o.owner_id, seats.n, seats.n + invited.n, l.reason, l.source
        FROM organizations o CROSS JOIN seats CROSS JOIN invited
        LEFT JOIN org_locks l ON l.org_id = o.id
        WHERE o.id = org
          AND (passbox.is_org_member(org) OR passbox.may_join(org)
               OR passbox.in_org_context(org, ARRAY['scim', 'sso']) OR passbox.system() = 'ext')
    $$;

REVOKE EXECUTE ON FUNCTION passbox.ext_accounts(TEXT[]) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION passbox.org_facts(TEXT, BIGINT) FROM PUBLIC;

DO $$
DECLARE
    can_bypass BOOLEAN;
BEGIN
    SELECT rolsuper OR rolbypassrls INTO can_bypass FROM pg_roles WHERE rolname = current_user;
    IF can_bypass THEN
        ALTER TABLE org_locks FORCE ROW LEVEL SECURITY;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'passbox_app') THEN
        GRANT SELECT, INSERT, DELETE ON org_locks TO passbox_app;
        GRANT EXECUTE ON FUNCTION passbox.ext_accounts(TEXT[]), passbox.org_facts(TEXT, BIGINT)
            TO passbox_app;
    END IF;
END
$$;
