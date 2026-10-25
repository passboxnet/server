#!/bin/sh
# PostgreSQL databases for test servers that run as a separate process (the
# e2e suites, the Android and iOS host tests):
#
#   scripts/test-database.sh create NAME   empty database NAME (an old one of
#                                          the same name is dropped first),
#                                          with the roles of sql/roles.sql
#   scripts/test-database.sh drop NAME     drops NAME
#
# PASSBOX_TEST_DATABASE_URL is a superuser connection, for example
# postgres://postgres:postgres@localhost:5432/postgres. Needs psql.
#
# The server then connects through that superuser URL with the database
# path replaced by NAME and `options=-c role=passbox_app` (and
# passbox_worker, passbox_migrator) appended, so row level security applies
# as in production and no role passwords are needed. It migrates the
# database itself at start (PASSBOX_AUTO_MIGRATE).
#
# Names of the form passbox_test_<unix seconds>_<suffix> are dropped by the
# server's own test runs once they are older than half an hour, so a test
# process that dies without dropping its database leaves nothing behind
# for long.
set -eu
: "${PASSBOX_TEST_DATABASE_URL:?set PASSBOX_TEST_DATABASE_URL to a PostgreSQL superuser URL, for example postgres://postgres:postgres@localhost:5432/postgres (see CONTRIBUTING.md)}"
command="${1:-}"
name="${2:-}"
case "$name" in
  "" | *[!a-z0-9_]*)
    echo "usage: $0 create|drop NAME (lower-case letters, digits and _)" >&2
    exit 2
    ;;
esac
roles="$(dirname "$0")/../crates/server/sql/roles.sql"

case "$command" in
  create)
    # Roles are cluster-wide: the lock on pg_authid serializes provisioning
    # between test servers that start at the same time.
    psql "$PASSBOX_TEST_DATABASE_URL" -X -q -v ON_ERROR_STOP=1 \
      -c "SET client_min_messages = warning" \
      -c "DROP DATABASE IF EXISTS $name WITH (FORCE)" \
      -c "CREATE DATABASE $name" \
      -c "\\connect $name" \
      -c "SET client_min_messages = warning" \
      -c "BEGIN" \
      -c "LOCK TABLE pg_catalog.pg_authid IN EXCLUSIVE MODE" \
      -f "$roles" \
      -c "COMMIT" > /dev/null
    ;;
  drop)
    psql "$PASSBOX_TEST_DATABASE_URL" -X -q -v ON_ERROR_STOP=1 \
      -c "SET client_min_messages = warning" \
      -c "DROP DATABASE IF EXISTS $name WITH (FORCE)" > /dev/null
    ;;
  *)
    echo "usage: $0 create|drop NAME" >&2
    exit 2
    ;;
esac
