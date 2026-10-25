#!/bin/bash
# Restores a backup made by backup.sh into the (stopped) Passbox stack.
#
#   restore.sh <timestamp>      e.g. 20261025T030000Z
#
# Needs the age private key at /run/secrets/age-key (mount it read-only) and
# write access to the blob volume at /data/blobs. The passbox and migrate
# services must be stopped. See docs/self-hosting.md#restore.
set -euo pipefail

ts="${1:?usage: restore.sh <timestamp>}"
# Paths inside the container; overridable for tests.
key="${BACKUP_AGE_KEY:-/run/secrets/age-key}"
in="${BACKUP_OUT_DIR:-/backups}"
data="${BLOB_PARENT_DIR:-/data}"
dump="$in/passbox-$ts.dump.age"
blobs="$in/blobs-$ts.tar.age"
: "${PGDATABASE:=passbox}"

for f in "$key" "$dump" "$blobs"; do
  [ -r "$f" ] || { echo "restore: cannot read $f" >&2; exit 1; }
done

echo "restore: recreating database $PGDATABASE (all current data in it is replaced)"
psql -v ON_ERROR_STOP=1 --dbname postgres <<SQL
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$PGDATABASE' AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS "$PGDATABASE";
CREATE DATABASE "$PGDATABASE" OWNER passbox_migrator ENCODING 'UTF8' TEMPLATE template0;
REVOKE ALL ON DATABASE "$PGDATABASE" FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE "$PGDATABASE" TO passbox_migrator;
GRANT CONNECT ON DATABASE "$PGDATABASE" TO passbox_app, passbox_worker;
SQL

echo "restore: loading $dump"
age --decrypt --identity "$key" "$dump" \
  | pg_restore --dbname "$PGDATABASE" --no-owner --role=passbox_migrator --exit-on-error

echo "restore: replacing attachment blobs"
find "$data/blobs" -mindepth 1 -delete
age --decrypt --identity "$key" "$blobs" | tar --extract --no-same-owner --directory "$data"
if [ "$(id -u)" = 0 ]; then
  chown -R 65532:65532 "$data/blobs"
fi
chmod 0700 "$data/blobs"

echo "restore: done. Start Passbox again: docker compose up -d"
