# syntax=docker/dockerfile:1.7

# Passbox server image: the API server with the web client embedded as static
# files. PostgreSQL only; there is no bundled database.
#
#   docker build -t passbox .
#   docker buildx build --platform linux/amd64,linux/arm64 -t passbox .
#
# The image is multi-arch. The Rust build always runs on the build machine's
# architecture and cross-compiles for the target (no slow QEMU emulation), and
# the web client is built once, because it does not depend on the target.
#
# Runtime:
# - distroless "cc" (glibc, CA certificates, no shell), user 65532 (nonroot).
# - Works with a read-only root filesystem: the only writable path the server
#   needs is PASSBOX_BLOB_DIR (/data/blobs, a volume).
# - No HEALTHCHECK instruction: distroless has no shell or curl. Use the
#   orchestrator's HTTP checks instead: GET /health (liveness) and GET /ready
#   (database reachable and migrations at the expected version), see
#   docs/self-hosting.md.
#
# Base images are pinned by digest (multi-arch index). Update tag and digest
# together, for example with Renovate or `docker buildx imagetools inspect`.

ARG NODE_IMAGE=docker.io/library/node:22.22-bookworm-slim@sha256:e21fc383b50d5347dc7a9f1cae45b8f4e2f0d39f7ade28e4eef7d2934522b752
ARG RUST_IMAGE=docker.io/library/rust:1.97.0-bookworm@sha256:8fa55b2f3ddf97471ab6a767bfa3f37e6bad0986ba823e75fea57e2a2a5c3073
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f

FROM --platform=$BUILDPLATFORM ${NODE_IMAGE} AS node

# ---------------------------------------------------------------------------
# Toolchain shared by the web and server builds (build platform only).
FROM --platform=$BUILDPLATFORM ${RUST_IMAGE} AS toolchain
ARG WASM_BINDGEN_VERSION=0.2.129
# rust-toolchain.toml says "stable"; pin the toolchain of the base image so
# builds are reproducible and do not download a newer compiler.
ENV RUSTUP_TOOLCHAIN=1.97.0 \
    CARGO_TERM_COLOR=never \
    CARGO_INCREMENTAL=0
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s /usr/local/lib/node_modules/corepack/dist/corepack.js /usr/local/bin/corepack \
    && corepack enable pnpm \
    && rustup target add wasm32-unknown-unknown \
    && cargo install wasm-bindgen-cli --version "${WASM_BINDGEN_VERSION}" --locked
WORKDIR /src

# ---------------------------------------------------------------------------
# Web client (architecture independent, built once).
FROM toolchain AS web
COPY . .
RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    --mount=type=cache,target=/usr/local/cargo/registry \
    pnpm install --frozen-lockfile \
    && pnpm build:wasm \
    && pnpm --filter @passbox/web build

# ---------------------------------------------------------------------------
# Server binary, cross-compiled for TARGETARCH.
FROM toolchain AS server
ARG TARGETARCH
# The cross toolchain comes from the Debian release of the pinned base image;
# it only exists in this build stage.
# hadolint ignore=DL3008
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) echo x86_64-unknown-linux-gnu > /rust-target ;; \
      arm64) echo aarch64-unknown-linux-gnu > /rust-target \
             && apt-get update \
             && apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
             && rm -rf /var/lib/apt/lists/* ;; \
      *) echo "unsupported TARGETARCH ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    rustup target add "$(cat /rust-target)"
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar \
    SQLX_OFFLINE=true
# SQLX_OFFLINE: the queries are checked against the committed .sqlx cache, so
# the build needs no database.
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,id=passbox-target-${TARGETARCH} \
    target="$(cat /rust-target)" \
    && cargo build --release --locked --package passbox-server --target "${target}" \
    && install -D -m 0755 "target/${target}/release/passbox-server" /out/passbox-server \
    && install -d -o 65532 -g 65532 -m 0700 /out/data/blobs

# ---------------------------------------------------------------------------
FROM ${RUNTIME_IMAGE}
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown
LABEL org.opencontainers.image.title="Passbox server" \
      org.opencontainers.image.description="End-to-end encrypted password manager: API server and web vault" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="Passbox" \
      org.opencontainers.image.source="https://github.com/relationsoftware/passbox" \
      org.opencontainers.image.documentation="https://github.com/relationsoftware/passbox/blob/master/docs/self-hosting.md" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"
COPY --from=server /out/passbox-server /usr/local/bin/passbox-server
COPY --from=web /src/apps/web/dist /usr/share/passbox/web
COPY --from=server --chown=65532:65532 /out/data /data
# PASSBOX_DATABASE_URL has no default: it must point to PostgreSQL.
ENV PASSBOX_BIND=0.0.0.0:8080 \
    PASSBOX_BLOB_DIR=/data/blobs \
    PASSBOX_WEB_DIR=/usr/share/passbox/web \
    PASSBOX_LOG_FORMAT=json
VOLUME /data
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/passbox-server"]
