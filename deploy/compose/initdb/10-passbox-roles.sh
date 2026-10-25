#!/bin/sh
# Creates the Passbox database and its three roles (see
# docs/self-hosting.md#database-roles). Runs once, when the postgres container
# initializes an empty data directory.
#
#   passbox_migrator  owns the schema and runs migrations (DDL)
#   passbox_app       the API server; no BYPASSRLS, row-level security applies
#   passbox_worker    background jobs; no BYPASSRLS, narrow grants
#
# Table privileges are granted by the migrations themselves.
set -eu

for var in PASSBOX_MIGRATOR_DB_PASSWORD PASSBOX_APP_DB_PASSWORD PASSBOX_WORKER_DB_PASSWORD; do
  eval "value=\${$var:-}"
  if [ -z "$value" ]; then
    echo "10-passbox-roles.sh: $var is not set" >&2
    exit 1
  fi
done

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v migrator_pw="$PASSBOX_MIGRATOR_DB_PASSWORD" \
  -v app_pw="$PASSBOX_APP_DB_PASSWORD" \
  -v worker_pw="$PASSBOX_WORKER_DB_PASSWORD" <<'SQL'
SET password_encryption = 'scram-sha-256';
CREATE ROLE passbox_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD :'migrator_pw';
CREATE ROLE passbox_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD :'app_pw';
CREATE ROLE passbox_worker LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD :'worker_pw';
ALTER ROLE passbox_app SET statement_timeout = '30s';
ALTER ROLE passbox_worker SET statement_timeout = '5min';

CREATE DATABASE passbox OWNER passbox_migrator ENCODING 'UTF8' TEMPLATE template0;
REVOKE ALL ON DATABASE passbox FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE passbox TO passbox_migrator;
GRANT CONNECT ON DATABASE passbox TO passbox_app, passbox_worker;

\connect passbox
REVOKE ALL ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO passbox_migrator;
GRANT USAGE ON SCHEMA public TO passbox_app, passbox_worker;
SQL
