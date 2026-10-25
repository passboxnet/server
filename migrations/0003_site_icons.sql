-- Website icons shared by all users of the instance (crate::api::icons,
-- docs/architecture/item-extras.md#website-icons).
--
-- Not tenant data: a row says "the website example.com has this icon" (or
-- "had none when we last looked") and nothing about who asked. There is no
-- account, session, organization or IP column, and none may be added: the
-- table is shared by every account, so a link to one would tell everyone
-- with database access which sites that account keeps logins for.
--
-- Row level security is enabled and forced anyway, so the table follows the
-- same rules as every other one (docs/architecture/database-security.md):
-- every named context may read it, only the icon contexts write it.
--
--   icons          request handlers (app pool, passbox_app) after a fetch
--   worker:icons   the refresh job (worker pool, passbox_worker)

CREATE TABLE site_icons (
    -- Lower-case ASCII (punycode) host name, validated by the server
    -- (api::icons::normalize_domain).
    domain TEXT PRIMARY KEY
        CHECK (char_length(domain) BETWEEN 3 AND 253 AND domain = lower(domain)
               AND domain ~ '^[a-z0-9.-]+$' AND domain LIKE '%_._%'),
    -- The icon, NULL for a miss (no usable icon found).
    image BYTEA CHECK (octet_length(image) BETWEEN 1 AND 204800),
    content_type TEXT
        CHECK (content_type IN ('image/png', 'image/x-icon', 'image/jpeg', 'image/gif', 'image/webp')),
    -- SHA-256 of `image`, for change detection and ETags towards clients.
    sha256 BYTEA CHECK (octet_length(sha256) = 32),
    -- Where the icon came from and its validators, for conditional refresh
    -- requests (If-None-Match / If-Modified-Since).
    source_url TEXT CHECK (char_length(source_url) <= 2048 AND source_url LIKE 'https://%'),
    etag TEXT CHECK (char_length(etag) <= 512),
    last_modified TEXT CHECK (char_length(last_modified) <= 128),
    -- When the icon (or the miss) was last confirmed (Unix ms).
    fetched_at BIGINT NOT NULL CHECK (fetched_at >= 0),
    -- When a client last asked for it (Unix ms, updated at most daily).
    -- Entries nobody asked for in a long time are removed.
    last_requested_at BIGINT NOT NULL CHECK (last_requested_at >= 0),
    -- Misses: when to look again. Hits: NULL.
    retry_after BIGINT CHECK (retry_after >= 0),
    -- Failed refreshes in a row (a hit stays until it fails repeatedly).
    failures INTEGER NOT NULL DEFAULT 0 CHECK (failures >= 0),
    -- A refresh job holds the row until then (several servers share the
    -- table; each picks rows nobody holds).
    claimed_until BIGINT NOT NULL DEFAULT 0 CHECK (claimed_until >= 0),
    CHECK ((image IS NULL) = (content_type IS NULL) AND (image IS NULL) = (sha256 IS NULL)),
    CHECK (image IS NOT NULL OR retry_after IS NOT NULL)
);

-- The refresh job looks for due rows by these.
CREATE INDEX site_icons_fetched_at ON site_icons (fetched_at) WHERE image IS NOT NULL;
CREATE INDEX site_icons_retry_after ON site_icons (retry_after) WHERE image IS NULL;
CREATE INDEX site_icons_last_requested_at ON site_icons (last_requested_at);

ALTER TABLE site_icons ENABLE ROW LEVEL SECURITY;
CREATE POLICY read ON site_icons FOR SELECT USING (passbox.has_context());
CREATE POLICY write ON site_icons
    USING (passbox.system() IN ('icons', 'worker:icons'))
    WITH CHECK (passbox.system() IN ('icons', 'worker:icons'));

-- Forced like every other table (see the end of 0002_rls.sql): only when
-- the migrating role may bypass row level security for its definer
-- functions.
DO $$
BEGIN
    IF (SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user) THEN
        ALTER TABLE site_icons FORCE ROW LEVEL SECURITY;
    END IF;
END
$$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'passbox_app') THEN
        GRANT SELECT, INSERT, UPDATE ON site_icons TO passbox_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'passbox_worker') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON site_icons TO passbox_worker;
    END IF;
END
$$;
