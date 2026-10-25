# Backup sidecar for the Docker Compose setup: pg_dump (same major version as
# the database) and age for public-key encryption.
FROM docker.io/library/postgres:17.10-bookworm@sha256:9b18b78397054fce88a9552e9d5a3ad5bb7fd258c5b3cc1c5028e46373d6ea8f
# age is in Debian bookworm (1.1.x); pin the major Debian release via the base.
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends age \
    && rm -rf /var/lib/apt/lists/*
COPY --chmod=0755 backup.sh restore.sh /usr/local/bin/
# Same user as the Passbox image, so it can read the attachment blobs.
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/backup.sh"]
