-- Row level security, helper functions and grants.
--
-- Defence in depth behind the application's own checks (see
-- docs/architecture/database-security.md). Every transaction of the server
-- starts by naming its context with transaction-local settings
-- (crate::db):
--
--   passbox.account_id  a signed-in account
--   passbox.context     'auth' | 'meta' | 'share_link' (signed out),
--                       'admin' (an instance admin, with account_id),
--                       'scim' | 'sso' | 'org_events' (an organization's
--                       machine credential or SSO integration, with
--                       passbox.org_id)
--   passbox.org_id      the organization of 'scim', 'sso' and 'org_events'
--   passbox.system      'secrets' | 'outbox' | 'metrics' | 'worker:<job>'
--
-- Without any of them a statement sees no tenant rows at all.
--
-- The helper functions below are SECURITY DEFINER, owned by the migration
-- role, with a fixed search_path. Policies call them for membership checks,
-- so policies stay fast (sets are computed once per statement) and never
-- recurse into each other. They bypass row level security as the table
-- owner; with FORCE ROW LEVEL SECURITY that needs BYPASSRLS on the
-- migration role (crates/server/sql/roles.sql), see the end of this file.

-- --- Context ----------------------------------------------------------------------

CREATE FUNCTION passbox.account_id() RETURNS TEXT
    LANGUAGE sql STABLE PARALLEL SAFE
    RETURN NULLIF(current_setting('passbox.account_id', true), '');

CREATE FUNCTION passbox.context() RETURNS TEXT
    LANGUAGE sql STABLE PARALLEL SAFE
    RETURN NULLIF(current_setting('passbox.context', true), '');

-- The organization of a machine context ('scim', 'sso', 'org_events').
CREATE FUNCTION passbox.org_id() RETURNS TEXT
    LANGUAGE sql STABLE PARALLEL SAFE
    RETURN CASE WHEN passbox.context() IN ('scim', 'sso', 'org_events')
        THEN NULLIF(current_setting('passbox.org_id', true), '') END;

CREATE FUNCTION passbox.system() RETURNS TEXT
    LANGUAGE sql STABLE PARALLEL SAFE
    RETURN NULLIF(current_setting('passbox.system', true), '');

-- Whether the transaction named any context at all.
CREATE FUNCTION passbox.has_context() RETURNS BOOLEAN
    LANGUAGE sql STABLE PARALLEL SAFE
    RETURN passbox.account_id() IS NOT NULL OR passbox.context() IS NOT NULL
        OR passbox.system() IS NOT NULL;

-- Signed-out flows that verify credentials (sign-up, sign-in, second
-- factor, recovery, SSO sign-in, new devices).
CREATE FUNCTION passbox.in_auth() RETURNS BOOLEAN
    LANGUAGE sql STABLE PARALLEL SAFE
    RETURN coalesce(passbox.context() = 'auth', false);

-- The organization `org` in one of the machine contexts `kinds`.
CREATE FUNCTION passbox.in_org_context(org TEXT, kinds TEXT[]) RETURNS BOOLEAN
    LANGUAGE sql STABLE PARALLEL SAFE
    RETURN coalesce(passbox.org_id() = org AND passbox.context() = ANY (kinds), false);

-- An instance admin (the server checked the account flag or
-- PASSBOX_ADMIN_EMAILS before setting the context).
CREATE FUNCTION passbox.is_instance_admin() RETURNS BOOLEAN
    LANGUAGE sql STABLE PARALLEL SAFE
    RETURN coalesce(passbox.context() = 'admin' AND passbox.account_id() IS NOT NULL, false);

CREATE FUNCTION passbox.now_ms() RETURNS BIGINT
    LANGUAGE sql STABLE PARALLEL SAFE
    RETURN (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT;

-- --- Membership (SECURITY DEFINER) -------------------------------------------------

-- The current account's email (invitations and emergency grants are
-- addressed by email before the invitee has an account link).
CREATE FUNCTION passbox.my_email() RETURNS TEXT
    LANGUAGE sql STABLE SECURITY DEFINER PARALLEL SAFE
    SET search_path = pg_catalog, public
    AS $$ SELECT email FROM accounts WHERE id = passbox.account_id() $$;

-- Organizations the current account belongs to (any membership status).
CREATE FUNCTION passbox.my_orgs() RETURNS SETOF TEXT
    LANGUAGE sql STABLE SECURITY DEFINER PARALLEL SAFE
    SET search_path = pg_catalog, public
    AS $$ SELECT org_id FROM org_members WHERE account_id = passbox.account_id() $$;

CREATE FUNCTION passbox.is_org_member(org TEXT) RETURNS BOOLEAN
    LANGUAGE sql STABLE SECURITY DEFINER PARALLEL SAFE
    SET search_path = pg_catalog, public
    AS $$
        SELECT EXISTS (
            SELECT 1 FROM org_members WHERE org_id = org AND account_id = passbox.account_id()
        )
    $$;

-- A confirmed owner or admin of the organization.
CREATE FUNCTION passbox.is_org_admin(org TEXT) RETURNS BOOLEAN
    LANGUAGE sql STABLE SECURITY DEFINER PARALLEL SAFE
    SET search_path = pg_catalog, public
    AS $$
        SELECT EXISTS (
            SELECT 1 FROM org_members WHERE org_id = org AND account_id = passbox.account_id()
            AND status = 'confirmed' AND role IN ('owner', 'admin')
        )
    $$;

-- Whether the current account may join the organization: it owns it (just
-- created) or an invitation for its email is open or was just accepted.
CREATE FUNCTION passbox.may_join(org TEXT) RETURNS BOOLEAN
    LANGUAGE sql STABLE SECURITY DEFINER PARALLEL SAFE
    SET search_path = pg_catalog, public
    AS $$
        SELECT EXISTS (SELECT 1 FROM organizations WHERE id = org AND owner_id = passbox.account_id())
            OR EXISTS (SELECT 1 FROM org_invitations i WHERE i.org_id = org
                       AND i.email = passbox.my_email() AND i.status IN ('pending', 'accepted'))
    $$;

-- Whether the current context manages the account `target`: an instance
-- admin, a confirmed owner or admin of an organization the target belongs
-- to, or the SCIM or SSO context of such an organization. Used for ending
-- sessions (offboarding, disabling) and the security status in reports.
CREATE FUNCTION passbox.manages_account(target TEXT) RETURNS BOOLEAN
    LANGUAGE sql STABLE SECURITY DEFINER PARALLEL SAFE
    SET search_path = pg_catalog, public
    AS $$
        SELECT passbox.is_instance_admin()
            OR EXISTS (
                SELECT 1 FROM org_members me JOIN org_members them ON them.org_id = me.org_id
                WHERE me.account_id = passbox.account_id() AND me.status = 'confirmed'
                  AND me.role IN ('owner', 'admin') AND them.account_id = target)
            OR EXISTS (
                SELECT 1 FROM org_members them
                WHERE them.org_id = passbox.org_id() AND passbox.context() IN ('scim', 'sso')
                  AND them.account_id = target)
    $$;

-- Vaults whose rows (items, keys, members, attachments) the current
-- account may read: its personal vaults, the vaults of its organizations,
-- and the personal vaults of accounts that confirmed emergency access for
-- it. Finer rules (vault membership, roles, the waiting period) are the
-- application's.
CREATE FUNCTION passbox.my_vaults() RETURNS SETOF TEXT
    LANGUAGE sql STABLE SECURITY DEFINER PARALLEL SAFE
    SET search_path = pg_catalog, public
    AS $$
        SELECT id FROM vaults WHERE account_id = passbox.account_id() AND org_id IS NULL
        UNION ALL
        SELECT v.id FROM vaults v WHERE v.org_id IN (SELECT passbox.my_orgs())
        UNION ALL
        SELECT v.id FROM vaults v JOIN emergency_grants g ON g.grantor_id = v.account_id
        WHERE v.org_id IS NULL AND g.grantee_id = passbox.account_id() AND g.status = 'confirmed'
    $$;

-- Vaults the current account may change: as above, without emergency access.
CREATE FUNCTION passbox.my_writable_vaults() RETURNS SETOF TEXT
    LANGUAGE sql STABLE SECURITY DEFINER PARALLEL SAFE
    SET search_path = pg_catalog, public
    AS $$
        SELECT id FROM vaults WHERE account_id = passbox.account_id() AND org_id IS NULL
        UNION ALL
        SELECT v.id FROM vaults v WHERE v.org_id IN (SELECT passbox.my_orgs())
    $$;

-- Accounts the current context may know about (ID, email, language):
-- itself, members of its organizations, both sides of its emergency grants
-- (also before the grantee accepted), the members of the organization of a
-- machine context, and for instance admins every account.
CREATE FUNCTION passbox.related_accounts() RETURNS SETOF TEXT
    LANGUAGE sql STABLE SECURITY DEFINER PARALLEL SAFE
    SET search_path = pg_catalog, public
    AS $$
        SELECT passbox.account_id() WHERE passbox.account_id() IS NOT NULL
        UNION
        SELECT m.account_id FROM org_members m
        WHERE m.org_id IN (SELECT passbox.my_orgs()) OR m.org_id = passbox.org_id()
        UNION
        SELECT grantee_id FROM emergency_grants
        WHERE grantor_id = passbox.account_id() AND grantee_id IS NOT NULL
        UNION
        SELECT grantor_id FROM emergency_grants
        WHERE grantee_id = passbox.account_id()
           OR (grantee_id IS NULL AND grantee_email = passbox.my_email())
        UNION
        SELECT id FROM accounts WHERE passbox.is_instance_admin()
    $$;

-- Whether an invitation token is pending for this email (sign-up with an
-- organization invitation; signed-out requests cannot read invitations).
CREATE FUNCTION passbox.org_invitation_pending(token TEXT, invitee TEXT, now BIGINT) RETURNS BOOLEAN
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$
        SELECT EXISTS (
            SELECT 1 FROM org_invitations
            WHERE token_hash = token AND email = invitee AND status = 'pending' AND expires_at > now
        )
    $$;

-- What an invitation link is for, before signing in (one token only).
CREATE FUNCTION passbox.invitation_preview(token TEXT, now BIGINT)
    RETURNS TABLE (org_id TEXT, org_kind TEXT, email TEXT, role TEXT, expires_at BIGINT,
                   inviter_email TEXT, recovery BOOLEAN, rules JSONB)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$
        SELECT i.org_id, o.kind, i.email, i.role, i.expires_at, a.email,
               EXISTS (SELECT 1 FROM org_recovery_keys k WHERE k.org_id = i.org_id),
               (SELECT p.rules FROM org_policies p WHERE p.org_id = i.org_id
                ORDER BY p.version DESC LIMIT 1)
        FROM org_invitations i
        JOIN organizations o ON o.id = i.org_id
        JOIN accounts a ON a.id = i.created_by
        WHERE i.token_hash = token AND i.status = 'pending' AND i.expires_at > now
    $$;

-- The open invitation of a link token (the token is the capability).
CREATE FUNCTION passbox.invitation_by_token(token TEXT, now BIGINT)
    RETURNS TABLE (id TEXT, org_id TEXT, email TEXT, role TEXT, created_by TEXT)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$
        SELECT id, org_id, email, role, created_by FROM org_invitations
        WHERE token_hash = token AND status = 'pending' AND expires_at > now
    $$;

-- Makes the current account instance admin if it is the first account of
-- the server. The only way to set `accounts.instance_admin`: the app role
-- has no UPDATE privilege on that column.
CREATE FUNCTION passbox.claim_first_admin(now BIGINT) RETURNS BOOLEAN
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$
    DECLARE
        me TEXT := passbox.account_id();
    BEGIN
        IF me IS NULL THEN
            RETURN false;
        END IF;
        INSERT INTO instance_state (name, value, updated_at)
            VALUES ('first_admin', to_jsonb(me), now)
            ON CONFLICT (name) DO NOTHING;
        IF NOT FOUND THEN
            RETURN false;
        END IF;
        UPDATE accounts SET instance_admin = true WHERE id = me;
        RETURN true;
    END
    $$;

-- The address and language of an account, for queueing mail to it.
CREATE FUNCTION passbox.mail_recipient(account TEXT, OUT email TEXT, OUT locale TEXT)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$ SELECT email, locale FROM accounts WHERE id = account $$;

-- Resolves a bearer token (its SHA-256) to a live session of an active
-- account. Signed-out requests cannot read sessions.
CREATE FUNCTION passbox.session_by_token(token TEXT, now BIGINT)
    RETURNS TABLE (account_id TEXT, id TEXT, device_name TEXT, client_kind TEXT,
                   created_at BIGINT, last_used_at BIGINT)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$
        SELECT s.account_id, s.id, s.device_name, s.client_kind, s.created_at, s.last_used_at
        FROM sessions s JOIN accounts a ON a.id = s.account_id
        WHERE s.token_hash = token AND s.expires_at > now AND a.disabled_at = 0
    $$;

-- Resolves a service account token's ID to what authentication needs.
CREATE FUNCTION passbox.service_account_by_id(sa TEXT)
    RETURNS TABLE (account_id TEXT, name TEXT, auth_hash TEXT, expires_at BIGINT,
                   revoked_at BIGINT, last_used_at BIGINT)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$
        SELECT s.account_id, s.name, s.auth_hash, s.expires_at, s.revoked_at, s.last_used_at
        FROM service_accounts s JOIN accounts a ON a.id = s.account_id
        WHERE s.id = sa AND a.disabled_at = 0
    $$;

-- Resolves an organization's machine token (SHA-256) to its organization.
CREATE FUNCTION passbox.scim_token(token TEXT, now BIGINT)
    RETURNS TABLE (id TEXT, org_id TEXT, created_by TEXT, last_used_at BIGINT)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$
        SELECT id, org_id, created_by, last_used_at FROM scim_tokens
        WHERE token_hash = token AND expires_at > now
    $$;

CREATE FUNCTION passbox.org_event_token(token TEXT)
    RETURNS TABLE (id TEXT, org_id TEXT, last_used_at BIGINT)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$
        SELECT id, org_id, last_used_at FROM org_event_tokens
        WHERE token_hash = token AND revoked_at = 0
    $$;

-- Share links for the signed-out viewer, one link ID at a time. The viewer's
-- context has no access to the share_links table itself.
CREATE FUNCTION passbox.share_link_info(link TEXT, now BIGINT)
    RETURNS TABLE (salt TEXT, expires_at BIGINT, max_views BIGINT, views BIGINT)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$
        SELECT salt, expires_at, max_views, views FROM share_links
        WHERE id = link AND expires_at > now
    $$;

-- Locks the link for the rest of the transaction.
CREATE FUNCTION passbox.share_link_for_open(link TEXT, now BIGINT)
    RETURNS TABLE (blob BYTEA, auth_hash TEXT, expires_at BIGINT, max_views BIGINT,
                   views BIGINT, failed_attempts BIGINT)
    LANGUAGE sql VOLATILE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$
        SELECT blob, auth_hash, expires_at, max_views, views, failed_attempts FROM share_links
        WHERE id = link AND expires_at > now
        FOR UPDATE
    $$;

-- A wrong access token: counts it, or deletes the link after too many.
CREATE FUNCTION passbox.share_link_failed(link TEXT, remove BOOLEAN) RETURNS VOID
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$
    BEGIN
        IF remove THEN
            DELETE FROM share_links WHERE id = link;
        ELSE
            UPDATE share_links SET failed_attempts = failed_attempts + 1 WHERE id = link;
        END IF;
    END
    $$;

-- A view with the right access token: counts it, or deletes the link after
-- its last allowed view.
CREATE FUNCTION passbox.share_link_viewed(link TEXT, presented TEXT, new_views BIGINT,
                                          remove BOOLEAN, now BIGINT) RETURNS VOID
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$
    BEGIN
        IF remove THEN
            DELETE FROM share_links WHERE id = link AND auth_hash = presented;
        ELSE
            UPDATE share_links SET views = new_views, last_viewed_at = now
            WHERE id = link AND auth_hash = presented;
        END IF;
    END
    $$;

CREATE FUNCTION passbox.purge_expired_share_links(now BIGINT) RETURNS VOID
    LANGUAGE sql VOLATILE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$ DELETE FROM share_links WHERE expires_at <= now $$;

-- Organization recovery from a signed-out device (docs/architecture/recovery.md).
-- The organization that holds an escrow of the account with this email.
CREATE FUNCTION passbox.org_recovery_target(member_email TEXT, org TEXT)
    RETURNS TABLE (org_id TEXT, account_id TEXT)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$
        SELECT e.org_id, a.id FROM org_recovery_escrows e
        JOIN accounts a ON a.id = e.account_id
        JOIN org_members m ON m.org_id = e.org_id AND m.account_id = e.account_id
        JOIN org_recovery_keys k ON k.org_id = e.org_id AND k.key_version = e.key_version
        WHERE a.email = member_email AND a.disabled_at = 0 AND m.status = 'confirmed'
          AND (e.org_id = org OR org = '')
        ORDER BY e.created_at LIMIT 1
    $$;

-- Opens a request, replacing an open one of the same account.
CREATE FUNCTION passbox.org_recovery_open_request(request TEXT, org TEXT, account TEXT, token TEXT,
                                                  ephemeral TEXT, device TEXT, from_ip TEXT,
                                                  now BIGINT, expires BIGINT) RETURNS VOID
    LANGUAGE sql VOLATILE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$
        UPDATE org_recovery_requests SET status = 'cancelled'
        WHERE account_id = account AND status IN ('pending', 'approved');
        INSERT INTO org_recovery_requests (id, org_id, account_id, token_hash, ephemeral_key, status,
            approval, approval_signature, sealed_key, request_code, decided_by, decided_at,
            device_name, ip, created_at, expires_at)
        VALUES (request, org, account, token, ephemeral, 'pending', '', '', '', '', '', 0,
            device, from_ip, now, expires);
    $$;

-- The requesting device's view of its request (it compares the token).
CREATE FUNCTION passbox.org_recovery_request(request TEXT)
    RETURNS TABLE (account_id TEXT, token_hash TEXT, status TEXT, approval TEXT,
                   approval_signature TEXT, sealed_key TEXT, decided_by TEXT, device_name TEXT,
                   expires_at BIGINT, org_id TEXT)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$
        SELECT account_id, token_hash, status, approval, approval_signature, sealed_key,
               decided_by, device_name, expires_at, org_id
        FROM org_recovery_requests WHERE id = request
    $$;

CREATE FUNCTION passbox.org_recovery_cancel(request TEXT, token TEXT) RETURNS VOID
    LANGUAGE sql VOLATILE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$
        UPDATE org_recovery_requests SET status = 'cancelled'
        WHERE id = request AND token_hash = token AND status IN ('pending', 'approved')
    $$;

-- Admins (confirmed owners and admins) who hold the current recovery key,
-- to notify them.
CREATE FUNCTION passbox.org_recovery_admins(org TEXT) RETURNS SETOF TEXT
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$
        SELECT g.account_id FROM org_recovery_grants g
        JOIN org_members m ON m.org_id = g.org_id AND m.account_id = g.account_id
        WHERE g.org_id = org AND m.status = 'confirmed' AND m.role IN ('owner', 'admin')
          AND g.key_version = (SELECT max(key_version) FROM org_recovery_keys WHERE org_id = org)
        ORDER BY g.account_id
    $$;

-- Which organization's identity provider signs in this email domain.
CREATE FUNCTION passbox.sso_discover(email_domain TEXT)
    RETURNS TABLE (org_id TEXT, display_name TEXT, provider TEXT, required BOOLEAN,
                   allow_device_unlock BOOLEAN)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$
        SELECT s.org_id, s.display_name, s.provider, s.required, s.allow_device_unlock
        FROM sso_domains d JOIN org_sso s ON s.org_id = d.org_id
        WHERE d.domain = email_domain AND s.enabled
    $$;

-- Whether another organization signs in this email domain already.
CREATE FUNCTION passbox.sso_domain_taken(email_domain TEXT) RETURNS BOOLEAN
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$ SELECT EXISTS (SELECT 1 FROM sso_domains WHERE domain = email_domain) $$;

-- The account with a (verified) email, for linking an SSO identity on its
-- first sign-in. Only the ID and whether it is disabled.
CREATE FUNCTION passbox.account_by_email(address TEXT)
    RETURNS TABLE (id TEXT, disabled_at BIGINT)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$ SELECT id, disabled_at FROM accounts WHERE email = address $$;

-- Codes for adding a device are unique among open links of all accounts.
CREATE FUNCTION passbox.device_link_short_id_taken(code TEXT) RETURNS BOOLEAN
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$ SELECT EXISTS (SELECT 1 FROM device_links WHERE short_id = code) $$;

CREATE FUNCTION passbox.purge_expired_device_links(now BIGINT) RETURNS VOID
    LANGUAGE sql VOLATILE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$ DELETE FROM device_links WHERE expires_at < now $$;

-- What the instance holds, for the instance administration (numbers only).
-- Guests, AI agents and service accounts are never billable members.
CREATE FUNCTION passbox.instance_usage(now BIGINT, OUT accounts BIGINT, OUT organizations BIGINT,
                                       OUT members BIGINT, OUT guests BIGINT,
                                       OUT service_accounts BIGINT)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$
        SELECT (SELECT count(*) FROM accounts WHERE created_at <= now),
               (SELECT count(*) FROM organizations WHERE created_at <= now),
               (SELECT count(DISTINCT account_id) FROM org_members
                WHERE status = 'confirmed' AND role <> 'guest' AND created_at <= now),
               (SELECT count(DISTINCT g.account_id) FROM org_members g
                WHERE g.status = 'confirmed' AND g.role = 'guest' AND g.created_at <= now
                  AND NOT EXISTS (SELECT 1 FROM org_members m WHERE m.account_id = g.account_id
                                  AND m.status = 'confirmed' AND m.role <> 'guest')),
               (SELECT count(*) FROM service_accounts
                WHERE revoked_at = 0 AND (expires_at = 0 OR expires_at > now))
        WHERE passbox.is_instance_admin()
    $$;

-- Active service accounts of an organization's confirmed members (not
-- guests), for the fair-use pool. Members see the number, not the rows.
CREATE FUNCTION passbox.org_service_account_count(org TEXT, now BIGINT) RETURNS BIGINT
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$
        SELECT count(*) FROM service_accounts sa
        WHERE sa.revoked_at = 0 AND (sa.expires_at = 0 OR sa.expires_at > now)
          AND sa.account_id IN (SELECT account_id FROM org_members WHERE org_id = org
                                AND status = 'confirmed' AND role <> 'guest')
          AND (passbox.is_org_member(org) OR passbox.is_instance_admin())
    $$;

-- The hash of an admin audit entry, to chain the next one to it (accounts
-- append entries about themselves without reading the log).
CREATE FUNCTION passbox.admin_event_hash(entry BIGINT) RETURNS TEXT
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$ SELECT hash FROM admin_events WHERE seq = entry $$;

-- Ends everything that lets an account in (sessions, device tokens,
-- proofs, trusted devices), for whoever manages the account (SCIM
-- deprovisioning). Their rows stay invisible to that context otherwise.
CREATE FUNCTION passbox.end_access(target TEXT) RETURNS VOID
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$
    BEGIN
        IF NOT passbox.manages_account(target) THEN
            RAISE EXCEPTION 'not allowed to end the access of this account'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
        DELETE FROM sessions WHERE account_id = target;
        DELETE FROM device_tokens WHERE account_id = target;
        DELETE FROM sso_proofs WHERE account_id = target;
        DELETE FROM trusted_devices WHERE account_id = target;
        DELETE FROM trusted_device_requests WHERE account_id = target;
    END
    $$;

-- Queue depths for /metrics (numbers only).
CREATE FUNCTION passbox.queue_depths(now BIGINT, OUT mail_pending BIGINT, OUT mail_failed BIGINT,
                                     OUT webhooks_due BIGINT)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$
        SELECT (SELECT count(*) FROM mail_outbox WHERE status = 'pending'),
               (SELECT count(*) FROM mail_outbox WHERE status = 'failed'),
               (SELECT count(*) FROM org_webhooks WHERE active AND next_attempt_at <= now)
    $$;

-- --- Directory ----------------------------------------------------------------------

-- What an account may learn about other accounts (ID, email, language,
-- status), without their credentials. The view runs with its owner's
-- rights and filters itself; the accounts table shows only the own row.
CREATE VIEW account_directory WITH (security_barrier) AS
    SELECT id, email, locale, disabled_at, created_at
    FROM accounts
    WHERE id IN (SELECT passbox.related_accounts());

-- The key directory: every account's public key bundles, without the
-- encrypted private keys (which only their owner reads from account_keys).
CREATE VIEW public_keys WITH (security_barrier) AS
    SELECT account_id, key_version, bundle, bundle_signature, bundle_hash, log_seq, created_at
    FROM account_keys
    WHERE passbox.account_id() IS NOT NULL OR passbox.org_id() IS NOT NULL;

-- --- Policies -----------------------------------------------------------------------
--
-- Abbreviations in the comments: "own" = rows of the current account,
-- "member" = the account belongs to the row's organization, "auth" = the
-- signed-out sign-in context. Policies of one table are OR-ed. Tables
-- without tenant data (counters) have no row level security; a test checks
-- that every other table has it enabled and forced.

-- Server secrets: only the 'secrets' context (server start, SSO key).
ALTER TABLE server_secrets ENABLE ROW LEVEL SECURITY;
CREATE POLICY secrets ON server_secrets
    USING (passbox.system() = 'secrets') WITH CHECK (passbox.system() = 'secrets');

-- Instance settings are readable in every named context (they are published
-- in /meta); only instance admins change them. `first_admin` is written by
-- passbox.claim_first_admin().
ALTER TABLE instance_state ENABLE ROW LEVEL SECURITY;
CREATE POLICY read ON instance_state FOR SELECT USING (passbox.has_context());
CREATE POLICY admin ON instance_state
    USING (passbox.is_instance_admin()) WITH CHECK (passbox.is_instance_admin());

-- Accounts: the own row; the sign-in context looks accounts up by email and
-- creates them; instance admins read and disable them. Others' emails come
-- from account_directory, public keys from public_keys.
ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON accounts USING (id = passbox.account_id()) WITH CHECK (id = passbox.account_id());
CREATE POLICY auth_read ON accounts FOR SELECT USING (passbox.in_auth());
CREATE POLICY auth_create ON accounts FOR INSERT WITH CHECK (passbox.in_auth());
CREATE POLICY admin_read ON accounts FOR SELECT USING (passbox.is_instance_admin());
CREATE POLICY admin_update ON accounts FOR UPDATE
    USING (passbox.is_instance_admin()) WITH CHECK (passbox.is_instance_admin());

-- Sessions: own; ended by whoever manages the account (instance admins,
-- organization admins offboarding a member, SCIM deprovisioning). Bearer
-- tokens are resolved by passbox.session_by_token().
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON sessions
    USING (account_id = passbox.account_id()) WITH CHECK (account_id = passbox.account_id());
CREATE POLICY managed_read ON sessions FOR SELECT USING (passbox.manages_account(account_id));
CREATE POLICY managed_end ON sessions FOR DELETE USING (passbox.manages_account(account_id));

ALTER TABLE login_attempts ENABLE ROW LEVEL SECURITY;
CREATE POLICY auth ON login_attempts USING (passbox.in_auth()) WITH CHECK (passbox.in_auth());

-- The activity log: own (also failed sign-ins, written for the account);
-- read by whoever manages the account (last sign-in in reports).
ALTER TABLE account_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON account_events
    USING (account_id = passbox.account_id()) WITH CHECK (account_id = passbox.account_id());
CREATE POLICY managed_read ON account_events FOR SELECT USING (passbox.manages_account(account_id));

ALTER TABLE device_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON device_tokens
    USING (account_id = passbox.account_id()) WITH CHECK (account_id = passbox.account_id());
CREATE POLICY auth_read ON device_tokens FOR SELECT USING (passbox.in_auth());

ALTER TABLE two_factor_totp ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON two_factor_totp
    USING (account_id = passbox.account_id()) WITH CHECK (account_id = passbox.account_id());
CREATE POLICY managed_read ON two_factor_totp FOR SELECT USING (passbox.manages_account(account_id));

ALTER TABLE webauthn_credentials ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON webauthn_credentials
    USING (account_id = passbox.account_id()) WITH CHECK (account_id = passbox.account_id());
CREATE POLICY managed_read ON webauthn_credentials FOR SELECT
    USING (passbox.manages_account(account_id));

ALTER TABLE recovery_codes ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON recovery_codes
    USING (account_id = passbox.account_id()) WITH CHECK (account_id = passbox.account_id());

ALTER TABLE two_factor_challenges ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON two_factor_challenges
    USING (account_id = passbox.account_id()) WITH CHECK (account_id = passbox.account_id());
CREATE POLICY auth ON two_factor_challenges USING (passbox.in_auth()) WITH CHECK (passbox.in_auth());

-- Private keys: own only (bundles of others through public_keys).
ALTER TABLE account_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON account_keys
    USING (account_id = passbox.account_id()) WITH CHECK (account_id = passbox.account_id());

-- The key directory log is public to signed-in accounts and machine
-- contexts; an account appends its own entries. Rows are never changed.
ALTER TABLE key_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY read ON key_log FOR SELECT
    USING (passbox.account_id() IS NOT NULL OR passbox.org_id() IS NOT NULL);
CREATE POLICY append ON key_log FOR INSERT WITH CHECK (account_id = passbox.account_id());

-- Vaults and everything in them: readable within passbox.my_vaults(),
-- changeable within passbox.my_writable_vaults(). New vaults belong to the
-- creating account, shared ones to an organization it belongs to.
ALTER TABLE vaults ENABLE ROW LEVEL SECURITY;
CREATE POLICY read ON vaults FOR SELECT USING (id IN (SELECT passbox.my_vaults()));
CREATE POLICY creator ON vaults FOR INSERT WITH CHECK (
    account_id = passbox.account_id() AND (org_id IS NULL OR passbox.is_org_member(org_id)));
CREATE POLICY change ON vaults FOR UPDATE
    USING (id IN (SELECT passbox.my_writable_vaults()))
    WITH CHECK (id IN (SELECT passbox.my_writable_vaults()));
CREATE POLICY remove ON vaults FOR DELETE USING (id IN (SELECT passbox.my_writable_vaults()));

ALTER TABLE items ENABLE ROW LEVEL SECURITY;
CREATE POLICY read ON items FOR SELECT USING (vault_id IN (SELECT passbox.my_vaults()));
CREATE POLICY write ON items FOR INSERT WITH CHECK (vault_id IN (SELECT passbox.my_writable_vaults()));
CREATE POLICY change ON items FOR UPDATE
    USING (vault_id IN (SELECT passbox.my_writable_vaults()))
    WITH CHECK (vault_id IN (SELECT passbox.my_writable_vaults()));
CREATE POLICY remove ON items FOR DELETE USING (vault_id IN (SELECT passbox.my_writable_vaults()));

-- Versions follow their item (the items policy applies inside the check).
ALTER TABLE item_versions ENABLE ROW LEVEL SECURITY;
CREATE POLICY via_item ON item_versions
    USING (EXISTS (SELECT 1 FROM items i WHERE i.id = item_id))
    WITH CHECK (EXISTS (SELECT 1 FROM items i WHERE i.id = item_id
                        AND i.vault_id IN (SELECT passbox.my_writable_vaults())));

ALTER TABLE item_moves ENABLE ROW LEVEL SECURITY;
CREATE POLICY read ON item_moves FOR SELECT USING (
    from_vault_id IN (SELECT passbox.my_vaults()) OR to_vault_id IN (SELECT passbox.my_vaults()));
CREATE POLICY record ON item_moves FOR INSERT
    WITH CHECK (to_vault_id IN (SELECT passbox.my_writable_vaults()));

-- Attachments: like items; the cleanup worker sees every row, so it never
-- takes the blob of a live attachment for an orphan.
ALTER TABLE attachments ENABLE ROW LEVEL SECURITY;
CREATE POLICY read ON attachments FOR SELECT USING (vault_id IN (SELECT passbox.my_vaults()));
CREATE POLICY write ON attachments FOR INSERT
    WITH CHECK (vault_id IN (SELECT passbox.my_writable_vaults()));
CREATE POLICY change ON attachments FOR UPDATE
    USING (vault_id IN (SELECT passbox.my_writable_vaults()))
    WITH CHECK (vault_id IN (SELECT passbox.my_writable_vaults()));
CREATE POLICY remove ON attachments FOR DELETE
    USING (vault_id IN (SELECT passbox.my_writable_vaults()));
CREATE POLICY sweeper ON attachments FOR SELECT USING (passbox.system() = 'worker:attachments');

ALTER TABLE vault_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY read ON vault_members FOR SELECT USING (vault_id IN (SELECT passbox.my_vaults()));
CREATE POLICY write ON vault_members
    USING (vault_id IN (SELECT passbox.my_writable_vaults()))
    WITH CHECK (vault_id IN (SELECT passbox.my_writable_vaults()));

ALTER TABLE vault_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY read ON vault_keys FOR SELECT USING (vault_id IN (SELECT passbox.my_vaults()));
CREATE POLICY write ON vault_keys
    USING (vault_id IN (SELECT passbox.my_writable_vaults()))
    WITH CHECK (vault_id IN (SELECT passbox.my_writable_vaults()));

ALTER TABLE vault_manifests ENABLE ROW LEVEL SECURITY;
CREATE POLICY read ON vault_manifests FOR SELECT USING (vault_id IN (SELECT passbox.my_vaults()));
CREATE POLICY write ON vault_manifests
    USING (vault_id IN (SELECT passbox.my_writable_vaults()))
    WITH CHECK (vault_id IN (SELECT passbox.my_writable_vaults()));

-- Organizations: members; the owner creates it; machine contexts read
-- their own organization.
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
CREATE POLICY member ON organizations
    USING (passbox.is_org_member(id)) WITH CHECK (passbox.is_org_member(id));
CREATE POLICY creator ON organizations FOR INSERT WITH CHECK (owner_id = passbox.account_id());
CREATE POLICY machine ON organizations FOR SELECT
    USING (passbox.in_org_context(id, ARRAY['scim', 'sso', 'org_events']));

-- Members: the roster is visible to members; new rows come from admins,
-- from accounts joining by invitation (or creating the organization), and
-- from the SCIM and SSO contexts of the organization.
ALTER TABLE org_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY member ON org_members
    USING (passbox.is_org_member(org_id) OR account_id = passbox.account_id()
           OR passbox.in_org_context(org_id, ARRAY['scim', 'sso']))
    WITH CHECK (passbox.is_org_member(org_id) OR passbox.in_org_context(org_id, ARRAY['scim', 'sso']));
CREATE POLICY join_org ON org_members FOR INSERT
    WITH CHECK (account_id = passbox.account_id() AND passbox.may_join(org_id));

ALTER TABLE org_invitations ENABLE ROW LEVEL SECURITY;
CREATE POLICY member ON org_invitations
    USING (passbox.is_org_member(org_id) OR passbox.in_org_context(org_id, ARRAY['scim', 'sso']))
    WITH CHECK (passbox.is_org_member(org_id) OR passbox.in_org_context(org_id, ARRAY['scim', 'sso']));
CREATE POLICY invitee ON org_invitations FOR SELECT USING (email = passbox.my_email());
CREATE POLICY invitee_accept ON org_invitations FOR UPDATE
    USING (email = passbox.my_email()) WITH CHECK (email = passbox.my_email());

ALTER TABLE org_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY member ON org_keys
    USING (passbox.is_org_member(org_id)) WITH CHECK (passbox.is_org_member(org_id));

ALTER TABLE org_groups ENABLE ROW LEVEL SECURITY;
CREATE POLICY member ON org_groups
    USING (passbox.is_org_member(org_id)) WITH CHECK (passbox.is_org_member(org_id));

-- Group rows follow their group (the org_groups policy applies inside).
ALTER TABLE group_versions ENABLE ROW LEVEL SECURITY;
CREATE POLICY via_group ON group_versions
    USING (EXISTS (SELECT 1 FROM org_groups g WHERE g.id = group_id))
    WITH CHECK (EXISTS (SELECT 1 FROM org_groups g WHERE g.id = group_id));

ALTER TABLE group_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY via_group ON group_members
    USING (EXISTS (SELECT 1 FROM org_groups g WHERE g.id = group_id))
    WITH CHECK (EXISTS (SELECT 1 FROM org_groups g WHERE g.id = group_id));

-- Mail: anyone may queue a mail; only the mail worker reads and updates the
-- queue (recipients and links with tokens); admins see the delivery status.
ALTER TABLE mail_outbox ENABLE ROW LEVEL SECURITY;
CREATE POLICY queue ON mail_outbox FOR INSERT WITH CHECK (passbox.has_context());
CREATE POLICY worker ON mail_outbox
    USING (passbox.system() = 'worker:mail') WITH CHECK (passbox.system() = 'worker:mail');
CREATE POLICY admin_read ON mail_outbox FOR SELECT USING (passbox.is_instance_admin());

-- Instance invitations: admins; sign-up checks and uses them.
ALTER TABLE instance_invites ENABLE ROW LEVEL SECURITY;
CREATE POLICY admin ON instance_invites
    USING (passbox.is_instance_admin()) WITH CHECK (passbox.is_instance_admin());
CREATE POLICY auth_read ON instance_invites FOR SELECT USING (passbox.in_auth());
CREATE POLICY auth_use ON instance_invites FOR UPDATE
    USING (passbox.in_auth()) WITH CHECK (passbox.in_auth());

-- The admin audit log: admins read it; an account appends entries about
-- itself (the first admin, a used invitation). Rows are never changed.
ALTER TABLE admin_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY admin_read ON admin_events FOR SELECT USING (passbox.is_instance_admin());
CREATE POLICY append ON admin_events FOR INSERT
    WITH CHECK (passbox.is_instance_admin() OR actor_id = passbox.account_id());

-- Recovery by code: the record is the account's; the sign-in context reads
-- it by email for the recovery login.
ALTER TABLE account_recovery ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON account_recovery
    USING (account_id = passbox.account_id()) WITH CHECK (account_id = passbox.account_id());
CREATE POLICY auth_read ON account_recovery FOR SELECT USING (passbox.in_auth());

ALTER TABLE recovery_attempts ENABLE ROW LEVEL SECURITY;
CREATE POLICY auth ON recovery_attempts USING (passbox.in_auth()) WITH CHECK (passbox.in_auth());

ALTER TABLE recovery_sessions ENABLE ROW LEVEL SECURITY;
CREATE POLICY auth ON recovery_sessions USING (passbox.in_auth()) WITH CHECK (passbox.in_auth());
CREATE POLICY own ON recovery_sessions
    USING (account_id = passbox.account_id()) WITH CHECK (account_id = passbox.account_id());

-- Organization recovery: the organization's members (admins approve); the
-- requesting device goes through the passbox.org_recovery_* functions.
ALTER TABLE org_recovery_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY member ON org_recovery_keys
    USING (passbox.is_org_member(org_id)) WITH CHECK (passbox.is_org_member(org_id));

ALTER TABLE org_recovery_grants ENABLE ROW LEVEL SECURITY;
CREATE POLICY member ON org_recovery_grants
    USING (passbox.is_org_member(org_id)) WITH CHECK (passbox.is_org_member(org_id));

ALTER TABLE org_recovery_escrows ENABLE ROW LEVEL SECURITY;
CREATE POLICY member ON org_recovery_escrows
    USING (passbox.is_org_member(org_id)) WITH CHECK (passbox.is_org_member(org_id));

ALTER TABLE org_recovery_requests ENABLE ROW LEVEL SECURITY;
CREATE POLICY member ON org_recovery_requests
    USING (passbox.is_org_member(org_id) OR account_id = passbox.account_id())
    WITH CHECK (passbox.is_org_member(org_id) OR account_id = passbox.account_id());

-- Emergency access: both sides; a grantee before accepting by email.
ALTER TABLE emergency_grants ENABLE ROW LEVEL SECURITY;
CREATE POLICY parties ON emergency_grants
    USING (grantor_id = passbox.account_id() OR grantee_id = passbox.account_id()
           OR (grantee_id IS NULL AND grantee_email = passbox.my_email()))
    WITH CHECK (grantor_id = passbox.account_id() OR grantee_id = passbox.account_id());

-- Adding a device by code: the account's links; the new device claims and
-- polls in the sign-in context.
ALTER TABLE device_links ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON device_links
    USING (account_id = passbox.account_id()) WITH CHECK (account_id = passbox.account_id());
CREATE POLICY auth ON device_links USING (passbox.in_auth()) WITH CHECK (passbox.in_auth());

-- Organization administration.
ALTER TABLE org_policies ENABLE ROW LEVEL SECURITY;
CREATE POLICY member_read ON org_policies FOR SELECT USING (passbox.is_org_member(org_id));
CREATE POLICY admin ON org_policies FOR INSERT WITH CHECK (passbox.is_org_admin(org_id));

-- The audit log: members append (apps report events; actions are logged
-- for the acting member), read access is checked by the application
-- (admins); the events API, the webhook worker and retention read it.
ALTER TABLE org_audit_heads ENABLE ROW LEVEL SECURITY;
CREATE POLICY member ON org_audit_heads
    USING (passbox.is_org_member(org_id) OR passbox.in_org_context(org_id, ARRAY['scim', 'sso', 'org_events']))
    WITH CHECK (passbox.is_org_member(org_id) OR passbox.in_org_context(org_id, ARRAY['scim', 'sso']));
CREATE POLICY workers ON org_audit_heads
    USING (passbox.system() IN ('worker:webhooks', 'worker:audit_retention'))
    WITH CHECK (passbox.system() = 'worker:audit_retention');

ALTER TABLE org_audit_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY member ON org_audit_events
    USING (passbox.is_org_member(org_id) OR passbox.in_org_context(org_id, ARRAY['scim', 'sso', 'org_events']))
    WITH CHECK (passbox.is_org_member(org_id) OR passbox.in_org_context(org_id, ARRAY['scim', 'sso']));
CREATE POLICY workers ON org_audit_events FOR SELECT
    USING (passbox.system() IN ('worker:webhooks', 'worker:audit_retention'));
CREATE POLICY retention ON org_audit_events FOR DELETE
    USING (passbox.system() = 'worker:audit_retention');

ALTER TABLE org_settings ENABLE ROW LEVEL SECURITY;
CREATE POLICY member_read ON org_settings FOR SELECT USING (passbox.is_org_member(org_id));
CREATE POLICY admin ON org_settings
    USING (passbox.is_org_admin(org_id)) WITH CHECK (passbox.is_org_admin(org_id));
CREATE POLICY retention ON org_settings FOR SELECT
    USING (passbox.system() = 'worker:audit_retention');

ALTER TABLE org_security_reports ENABLE ROW LEVEL SECURITY;
CREATE POLICY member ON org_security_reports
    USING (passbox.is_org_member(org_id)) WITH CHECK (passbox.is_org_member(org_id));

ALTER TABLE org_event_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY member ON org_event_tokens
    USING (passbox.is_org_member(org_id)) WITH CHECK (passbox.is_org_member(org_id));
CREATE POLICY events ON org_event_tokens
    USING (passbox.in_org_context(org_id, ARRAY['org_events']))
    WITH CHECK (passbox.in_org_context(org_id, ARRAY['org_events']));

ALTER TABLE org_webhooks ENABLE ROW LEVEL SECURITY;
CREATE POLICY member ON org_webhooks
    USING (passbox.is_org_member(org_id)) WITH CHECK (passbox.is_org_member(org_id));
CREATE POLICY worker ON org_webhooks
    USING (passbox.system() = 'worker:webhooks') WITH CHECK (passbox.system() = 'worker:webhooks');

-- Single sign-on.
ALTER TABLE org_sso ENABLE ROW LEVEL SECURITY;
CREATE POLICY member_read ON org_sso FOR SELECT USING (passbox.is_org_member(org_id));
CREATE POLICY admin ON org_sso
    USING (passbox.is_org_admin(org_id)) WITH CHECK (passbox.is_org_admin(org_id));
CREATE POLICY sso ON org_sso
    USING (passbox.in_org_context(org_id, ARRAY['sso']))
    WITH CHECK (passbox.in_org_context(org_id, ARRAY['sso']));

ALTER TABLE sso_domains ENABLE ROW LEVEL SECURITY;
CREATE POLICY member_read ON sso_domains FOR SELECT USING (passbox.is_org_member(org_id));
CREATE POLICY admin ON sso_domains
    USING (passbox.is_org_admin(org_id)) WITH CHECK (passbox.is_org_admin(org_id));

ALTER TABLE sso_identities ENABLE ROW LEVEL SECURITY;
CREATE POLICY member ON sso_identities
    USING (passbox.is_org_member(org_id) OR passbox.in_org_context(org_id, ARRAY['sso', 'scim']))
    WITH CHECK (passbox.is_org_member(org_id) OR passbox.in_org_context(org_id, ARRAY['sso']));

-- Flows in progress: the signed-out sign-in context.
ALTER TABLE sso_flows ENABLE ROW LEVEL SECURITY;
CREATE POLICY auth ON sso_flows USING (passbox.in_auth()) WITH CHECK (passbox.in_auth());

ALTER TABLE sso_tickets ENABLE ROW LEVEL SECURITY;
CREATE POLICY auth ON sso_tickets USING (passbox.in_auth()) WITH CHECK (passbox.in_auth());

ALTER TABLE sso_proofs ENABLE ROW LEVEL SECURITY;
CREATE POLICY auth ON sso_proofs USING (passbox.in_auth()) WITH CHECK (passbox.in_auth());
CREATE POLICY own ON sso_proofs
    USING (account_id = passbox.account_id()) WITH CHECK (account_id = passbox.account_id());

ALTER TABLE trusted_devices ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON trusted_devices
    USING (account_id = passbox.account_id()) WITH CHECK (account_id = passbox.account_id());

ALTER TABLE trusted_device_requests ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON trusted_device_requests
    USING (account_id = passbox.account_id()) WITH CHECK (account_id = passbox.account_id());
CREATE POLICY auth_read ON trusted_device_requests FOR SELECT USING (passbox.in_auth());

-- SCIM: the organization's members (admins manage tokens) and its SCIM
-- context; SSO links provisioned users to accounts.
ALTER TABLE scim_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY member ON scim_tokens
    USING (passbox.is_org_member(org_id)) WITH CHECK (passbox.is_org_member(org_id));
CREATE POLICY scim ON scim_tokens
    USING (passbox.in_org_context(org_id, ARRAY['scim']))
    WITH CHECK (passbox.in_org_context(org_id, ARRAY['scim']));

ALTER TABLE scim_users ENABLE ROW LEVEL SECURITY;
CREATE POLICY member ON scim_users
    USING (passbox.is_org_member(org_id) OR passbox.in_org_context(org_id, ARRAY['scim', 'sso']))
    WITH CHECK (passbox.is_org_member(org_id) OR passbox.in_org_context(org_id, ARRAY['scim', 'sso']));

ALTER TABLE scim_groups ENABLE ROW LEVEL SECURITY;
CREATE POLICY member ON scim_groups
    USING (passbox.is_org_member(org_id) OR passbox.in_org_context(org_id, ARRAY['scim']))
    WITH CHECK (passbox.is_org_member(org_id) OR passbox.in_org_context(org_id, ARRAY['scim']));

ALTER TABLE scim_group_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY via_group ON scim_group_members
    USING (EXISTS (SELECT 1 FROM scim_groups g WHERE g.id = group_id))
    WITH CHECK (EXISTS (SELECT 1 FROM scim_groups g WHERE g.id = group_id));

-- Service accounts act with their owner's rights; organizations count their
-- members' service accounts for the fair-use pool.
ALTER TABLE service_accounts ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON service_accounts
    USING (account_id = passbox.account_id()) WITH CHECK (account_id = passbox.account_id());
CREATE POLICY managed_read ON service_accounts FOR SELECT USING (passbox.manages_account(account_id));

ALTER TABLE service_account_grants ENABLE ROW LEVEL SECURITY;
CREATE POLICY via_owner ON service_account_grants
    USING (EXISTS (SELECT 1 FROM service_accounts s WHERE s.id = service_account_id
                   AND s.account_id = passbox.account_id()))
    WITH CHECK (EXISTS (SELECT 1 FROM service_accounts s WHERE s.id = service_account_id
                        AND s.account_id = passbox.account_id()));

ALTER TABLE service_account_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY via_owner ON service_account_events
    USING (EXISTS (SELECT 1 FROM service_accounts s WHERE s.id = service_account_id
                   AND s.account_id = passbox.account_id()))
    WITH CHECK (EXISTS (SELECT 1 FROM service_accounts s WHERE s.id = service_account_id
                        AND s.account_id = passbox.account_id()));

ALTER TABLE agent_grants ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON agent_grants
    USING (account_id = passbox.account_id()) WITH CHECK (account_id = passbox.account_id());

ALTER TABLE agent_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON agent_events
    USING (account_id = passbox.account_id()) WITH CHECK (account_id = passbox.account_id());

-- Breach monitoring: own; the monitoring job checks every confirmed address.
ALTER TABLE breach_monitor_emails ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON breach_monitor_emails
    USING (account_id = passbox.account_id()) WITH CHECK (account_id = passbox.account_id());
CREATE POLICY worker ON breach_monitor_emails
    USING (passbox.system() = 'worker:breach') WITH CHECK (passbox.system() = 'worker:breach');

ALTER TABLE breach_monitor_results ENABLE ROW LEVEL SECURITY;
CREATE POLICY via_email ON breach_monitor_results
    USING (EXISTS (SELECT 1 FROM breach_monitor_emails e WHERE e.id = email_id))
    WITH CHECK (EXISTS (SELECT 1 FROM breach_monitor_emails e WHERE e.id = email_id));

-- Share links: own; the signed-out viewer goes through passbox.share_link_*.
ALTER TABLE share_links ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON share_links
    USING (account_id = passbox.account_id()) WITH CHECK (account_id = passbox.account_id());

-- Access requests: the requester and the vault's organization.
ALTER TABLE access_requests ENABLE ROW LEVEL SECURITY;
CREATE POLICY parties ON access_requests
    USING (account_id = passbox.account_id() OR passbox.is_org_member(org_id))
    WITH CHECK (account_id = passbox.account_id() OR passbox.is_org_member(org_id));

-- --- Forcing RLS on the owner -------------------------------------------------------
--
-- FORCE makes the policies apply to the table owner too. The owner's helper
-- functions above then need BYPASSRLS, which only a superuser can grant
-- (roles.sql gives it to passbox_migrator). Without it (a single role that
-- owns the schema and serves requests) the tables are not forced: the owner
-- bypasses the policies, and the server warns at start.
DO $$
DECLARE
    can_bypass BOOLEAN;
    t TEXT;
BEGIN
    SELECT rolsuper OR rolbypassrls INTO can_bypass FROM pg_roles WHERE rolname = current_user;
    FOR t IN
        SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relrowsecurity
    LOOP
        IF can_bypass THEN
            EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        END IF;
    END LOOP;
    IF NOT can_bypass THEN
        RAISE WARNING 'role % has no BYPASSRLS: row level security is not forced for the owner; '
            'run crates/server/sql/roles.sql and use passbox_app for PASSBOX_DATABASE_URL', current_user;
    END IF;
END
$$;

-- --- Grants ---------------------------------------------------------------------------
--
-- passbox_app serves requests: every table (row level security decides the
-- rows), except changing accounts.instance_admin. passbox_worker runs the
-- background jobs: only their tables. Both may run the passbox functions;
-- nobody else may. The roles exist when crates/server/sql/roles.sql ran.

REVOKE ALL ON SCHEMA passbox FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA passbox FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'passbox_app') THEN
        GRANT USAGE ON SCHEMA passbox TO passbox_app;
        GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA passbox TO passbox_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO passbox_app;
        REVOKE UPDATE ON accounts FROM passbox_app;
        GRANT UPDATE (email, opaque_record, kdf_salt, kdf_memory_kib, kdf_iterations, kdf_parallelism,
                      encrypted_account_key, disabled_at, locale, notify_new_device)
            ON accounts TO passbox_app;
        GRANT SELECT ON account_directory, public_keys TO passbox_app;
        IF to_regclass('public._sqlx_migrations') IS NOT NULL THEN
            GRANT SELECT ON _sqlx_migrations TO passbox_app;
        END IF;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'passbox_worker') THEN
        GRANT USAGE ON SCHEMA passbox TO passbox_worker;
        GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA passbox TO passbox_worker;
        GRANT SELECT ON instance_state, counters TO passbox_worker;
        GRANT SELECT, INSERT, UPDATE, DELETE ON mail_outbox TO passbox_worker;
        GRANT SELECT, UPDATE ON org_webhooks, org_audit_heads TO passbox_worker;
        GRANT SELECT, DELETE ON org_audit_events TO passbox_worker;
        GRANT SELECT ON org_settings, attachments TO passbox_worker;
        GRANT SELECT, UPDATE ON breach_monitor_emails TO passbox_worker;
        GRANT SELECT, INSERT ON breach_monitor_results TO passbox_worker;
        IF to_regclass('public._sqlx_migrations') IS NOT NULL THEN
            GRANT SELECT ON _sqlx_migrations TO passbox_worker;
        END IF;
    END IF;
END
$$;
