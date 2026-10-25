#!/bin/sh
# Creates the Passbox database and its three roles (see
# docs/self-hosting.md#database-roles). Runs once, when the postgres container
# initializes an empty data directory, and so before the `migrate` service
# applies the first migration.
#
# The roles come from crates/server/sql/roles.sql (mounted at
# /passbox/roles.sql), the same script every other installation and the
# tests run:
#
#   passbox_migrator  owns the schema and runs migrations; BYPASSRLS
#   passbox_app       the API server; NOBYPASSRLS, row level security applies
#   passbox_worker    background jobs; NOBYPASSRLS, narrow grants
#
# This script adds the passwords and statement timeouts. Table privileges
# are granted by the migrations themselves.
set -eu

roles=/passbox/roles.sql
if [ ! -r "$roles" ]; then
  echo "10-passbox-roles.sh: $roles is missing (mount crates/server/sql/roles.sql there)" >&2
  exit 1
fi
for var in PASSBOX_MIGRATOR_DB_PASSWORD PASSBOX_APP_DB_PASSWORD PASSBOX_WORKER_DB_PASSWORD; do
  eval "value=\${$var:-}"
  if [ -z "$value" ]; then
    echo "10-passbox-roles.sh: $var is not set" >&2
    exit 1
  fi
done

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -c "CREATE DATABASE passbox ENCODING 'UTF8' TEMPLATE template0"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname passbox -f "$roles"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname passbox \
  -v migrator_pw="$PASSBOX_MIGRATOR_DB_PASSWORD" \
  -v app_pw="$PASSBOX_APP_DB_PASSWORD" \
  -v worker_pw="$PASSBOX_WORKER_DB_PASSWORD" <<'SQL'
SET password_encryption = 'scram-sha-256';
ALTER ROLE passbox_migrator PASSWORD :'migrator_pw';
ALTER ROLE passbox_app PASSWORD :'app_pw';
ALTER ROLE passbox_worker PASSWORD :'worker_pw';
ALTER ROLE passbox_app SET statement_timeout = '30s';
ALTER ROLE passbox_worker SET statement_timeout = '5min';
-- The migrator owns the database (and with it the public schema), as after
-- a restore (backup/restore.sh).
ALTER DATABASE passbox OWNER TO passbox_migrator;
SQL
