# syntax=docker/dockerfile:1

# Builds the Passbox server with the web client embedded as static files.
#   docker build -t passbox .
#   docker run -p 8080:8080 passbox

FROM node:22-bookworm-slim AS node

FROM rust:1.97-bookworm AS build
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s /usr/local/lib/node_modules/corepack/dist/corepack.js /usr/local/bin/corepack \
    && corepack enable pnpm \
    && rustup target add wasm32-unknown-unknown \
    && cargo install wasm-bindgen-cli --version 0.2.129 --locked

WORKDIR /src
COPY . .
RUN pnpm install --frozen-lockfile \
    && pnpm build:wasm \
    && pnpm --filter @passbox/web build \
    && cargo build --release --locked --package passbox-server \
    && mkdir -p /data

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/passbox-server /usr/local/bin/passbox-server
COPY --from=build /src/apps/web/dist /usr/share/passbox/web
COPY --from=build --chown=65532:65532 /data /data
ENV PASSBOX_BIND=0.0.0.0:8080 \
    PASSBOX_DATABASE_URL=sqlite:///data/passbox.db?mode=rwc \
    PASSBOX_BLOB_DIR=/data/blobs \
    PASSBOX_WEB_DIR=/usr/share/passbox/web \
    PASSBOX_LOG_FORMAT=json
VOLUME /data
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/usr/local/bin/passbox-server"]
