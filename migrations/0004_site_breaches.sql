-- The breach catalogue: public breach metadata from Have I Been Pwned
-- (https://haveibeenpwned.com/api/v3/breaches, CC BY 4.0), refreshed by the
-- `worker:breach_catalog` job and served to clients as one document
-- (`GET /api/v1/breaches/catalog`). Clients match it against their own
-- decrypted logins; the server never learns who has an account where.
--
-- Global data without tenants: every named context may read it, only the
-- catalogue job writes it (docs/architecture/database-security.md).

CREATE TABLE site_breaches (
    -- Have I Been Pwned's stable name ("Adobe").
    name TEXT PRIMARY KEY CHECK (length(name) BETWEEN 1 AND 200),
    title TEXT NOT NULL CHECK (length(title) <= 300),
    -- Lower-case host name of the breached site ('' for breaches of no
    -- single site, such as combo lists; those are not served).
    domain TEXT NOT NULL CHECK (length(domain) <= 253 AND domain = lower(domain)),
    -- When the breach happened (YYYY-MM-DD, as published; may be empty).
    breach_date TEXT NOT NULL CHECK (breach_date = '' OR breach_date ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'),
    -- When it was published in and last changed at Have I Been Pwned (Unix ms).
    added_date BIGINT NOT NULL CHECK (added_date >= 0),
    modified_date BIGINT NOT NULL CHECK (modified_date >= 0),
    pwn_count BIGINT NOT NULL CHECK (pwn_count >= 0),
    data_classes JSONB NOT NULL CHECK (jsonb_typeof(data_classes) = 'array' AND jsonb_array_length(data_classes) <= 200),
    is_verified BOOLEAN NOT NULL,
    is_sensitive BOOLEAN NOT NULL,
    is_spam_list BOOLEAN NOT NULL,
    is_fabricated BOOLEAN NOT NULL,
    is_retired BOOLEAN NOT NULL,
    -- When this server stored the current version of the row (Unix ms).
    updated_at BIGINT NOT NULL
);

CREATE INDEX site_breaches_domain ON site_breaches (domain);

-- State of the catalogue (one row): the version clients compare and what
-- the last fetch did.
CREATE TABLE site_breach_catalog (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    -- Changes whenever the served content changes (hash of the entries).
    version TEXT NOT NULL CHECK (length(version) <= 100),
    -- Newest added or modified date of the entries (Unix ms).
    updated_at BIGINT NOT NULL CHECK (updated_at >= 0),
    entries BIGINT NOT NULL CHECK (entries >= 0),
    -- Validator of the last upstream response, if it sent one.
    etag TEXT NOT NULL CHECK (length(etag) <= 500),
    -- Last successful fetch and last attempt (Unix ms).
    fetched_at BIGINT NOT NULL,
    checked_at BIGINT NOT NULL,
    -- Why the last attempt failed ('' when it worked).
    error TEXT NOT NULL CHECK (length(error) <= 500)
);

-- Per-breach counts in a member's security aggregate for an organization:
-- [{ "name": "Adobe", "title": "Adobe", "open": 1, "fixed": 2 }] with
-- numbers of the member's items only, never item details.
ALTER TABLE org_security_reports
    ADD COLUMN site_breaches JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(site_breaches) = 'array' AND jsonb_array_length(site_breaches) <= 500);

ALTER TABLE site_breaches ENABLE ROW LEVEL SECURITY;
CREATE POLICY read ON site_breaches FOR SELECT USING (passbox.has_context());
CREATE POLICY worker ON site_breaches
    USING (passbox.system() = 'worker:breach_catalog')
    WITH CHECK (passbox.system() = 'worker:breach_catalog');

ALTER TABLE site_breach_catalog ENABLE ROW LEVEL SECURITY;
CREATE POLICY read ON site_breach_catalog FOR SELECT USING (passbox.has_context());
CREATE POLICY worker ON site_breach_catalog
    USING (passbox.system() = 'worker:breach_catalog')
    WITH CHECK (passbox.system() = 'worker:breach_catalog');

DO $$
DECLARE
    can_bypass BOOLEAN;
BEGIN
    SELECT rolsuper OR rolbypassrls INTO can_bypass FROM pg_roles WHERE rolname = current_user;
    IF can_bypass THEN
        ALTER TABLE site_breaches FORCE ROW LEVEL SECURITY;
        ALTER TABLE site_breach_catalog FORCE ROW LEVEL SECURITY;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'passbox_app') THEN
        GRANT SELECT ON site_breaches, site_breach_catalog TO passbox_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'passbox_worker') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON site_breaches, site_breach_catalog TO passbox_worker;
    END IF;
END
$$;
