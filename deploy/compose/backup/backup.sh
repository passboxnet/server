#!/bin/bash
# Periodic encrypted backups of the Passbox database and attachment blobs.
#
# Every BACKUP_INTERVAL_HOURS it writes to /backups:
#   passbox-<UTC time>.dump.age   pg_dump custom format, encrypted with age
#   blobs-<UTC time>.tar.age      the attachment blobs, encrypted with age
#   last-success                  UTC time of the last complete backup
# and deletes backups older than BACKUP_KEEP_DAYS.
#
# `backup.sh once` makes one backup and exits (for cron or a manual run).
set -euo pipefail

: "${BACKUP_AGE_RECIPIENT:?BACKUP_AGE_RECIPIENT (age public key) is required}"
: "${PGDATABASE:=passbox}"
interval_hours="${BACKUP_INTERVAL_HOURS:-24}"
keep_days="${BACKUP_KEEP_DAYS:-14}"
# Paths inside the container; overridable for tests.
out="${BACKUP_OUT_DIR:-/backups}"
data="${BLOB_PARENT_DIR:-/data}"

log() { printf '%s backup: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

backup_once() {
  local ts tmp
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  tmp="$(mktemp -d "$out/.tmp.XXXXXX")" || return 1
  trap 'rm -rf "$tmp"' RETURN

  log "dumping database $PGDATABASE"
  # Callers run this in `if`, where `set -e` does not apply: check each step.
  pg_dump --format=custom --compress=6 --no-password "$PGDATABASE" \
    | age --encrypt --recipient "$BACKUP_AGE_RECIPIENT" --output "$tmp/passbox-$ts.dump.age" \
    || return 1

  log "archiving attachment blobs"
  tar --create --directory "$data" blobs \
    | age --encrypt --recipient "$BACKUP_AGE_RECIPIENT" --output "$tmp/blobs-$ts.tar.age" \
    || return 1

  mv "$tmp/passbox-$ts.dump.age" "$tmp/blobs-$ts.tar.age" "$out/" || return 1
  date -u +%Y-%m-%dT%H:%M:%SZ > "$out/last-success" || return 1
  log "wrote passbox-$ts.dump.age and blobs-$ts.tar.age"

  find "$out" -maxdepth 1 -type f \( -name 'passbox-*.dump.age' -o -name 'blobs-*.tar.age' \) \
    -mtime "+$keep_days" -print -delete
}

if [ "${1:-}" = "once" ]; then
  backup_once || { log "FAILED"; exit 1; }
  exit 0
fi

# Wait for the first backup until the database has been migrated.
sleep 300
while true; do
  if ! backup_once; then
    log "FAILED; retrying in 15 minutes"
    sleep 900
    continue
  fi
  sleep "$((interval_hours * 3600))"
done
