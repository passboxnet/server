-- Database roles of Passbox (docs/architecture/database-security.md).
--
-- Run as a superuser, connected to the Passbox database, before the first
-- `passbox-server migrate`:
--
--   psql "postgres://postgres@db/passbox" -v ON_ERROR_STOP=1 -f roles.sql
--
-- Idempotent: running it again changes nothing but restores the attributes
-- and grants below. It does not set passwords; set them afterwards, for
-- example with `ALTER ROLE passbox_app PASSWORD '...'` (or use certificate
-- or peer authentication in pg_hba.conf).
--
--   passbox_migrator  owns the schema and runs migrations
--                     (PASSBOX_MIGRATION_DATABASE_URL). BYPASSRLS, because
--                     the row level security helper functions run as the
--                     owner and the tables force row level security.
--   passbox_app       serves requests (PASSBOX_DATABASE_URL). Not an owner,
--                     NOBYPASSRLS: every query is subject to the policies.
--   passbox_worker    runs background jobs (PASSBOX_WORKER_DATABASE_URL):
--                     NOBYPASSRLS, and only the tables of its jobs.
--
-- The migrations grant table privileges to passbox_app and passbox_worker
-- when these roles exist.

DO $$
DECLARE
    spec RECORD;
BEGIN
    FOR spec IN
        SELECT * FROM (VALUES
            ('passbox_migrator', 'LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS'),
            ('passbox_app', 'LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'),
            ('passbox_worker', 'LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS')
        ) AS r (name, attributes)
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = spec.name) THEN
            BEGIN
                EXECUTE format('CREATE ROLE %I %s', spec.name, spec.attributes);
            EXCEPTION WHEN duplicate_object OR unique_violation THEN
                -- Created concurrently (another provisioning run).
                NULL;
            END;
        END IF;
        EXECUTE format('ALTER ROLE %I %s', spec.name, spec.attributes);
    END LOOP;
END
$$;

-- This database: only the Passbox roles connect; the migrator creates the
-- schema objects.
DO $$
BEGIN
    EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database());
    EXECUTE format('GRANT CONNECT, TEMPORARY, CREATE ON DATABASE %I TO passbox_migrator',
                   current_database());
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO passbox_app, passbox_worker',
                   current_database());
END
$$;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO passbox_migrator;
GRANT USAGE ON SCHEMA public TO passbox_app, passbox_worker;
