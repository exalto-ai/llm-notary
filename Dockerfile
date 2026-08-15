# Keep the build and runtime stages on the same Debian release. The floating
# `slim` tag may move to a newer glibc before the runtime images do.
FROM rust:1.95-slim-bookworm AS chef

WORKDIR /app

# Keep dependency compilation in a layer whose inputs are the Cargo manifests,
# rather than the application source. A source-only change should therefore
# rebuild the small application crate instead of all TLSNotary dependencies.
RUN cargo install cargo-chef --version 0.1.77 --locked

FROM chef AS planner

# Keep the Rust build cache independent of the SPA, deployment files, and docs.
# This image needs only the Rust workspace packages and vendored TLSNotary dependencies.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# Cargo metadata must be able to load every workspace member, even though the
# production targets do not compile the desktop crate.
COPY js/desktop/src-tauri/Cargo.toml ./js/desktop/src-tauri/Cargo.toml
RUN mkdir -p js/desktop/src-tauri/src && touch js/desktop/src-tauri/src/lib.rs
COPY vendor/tlsn ./vendor/tlsn
COPY vendor/tlsn-utils ./vendor/tlsn-utils
COPY migrations-postgres ./migrations-postgres
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder

# Cook the dependency graph before copying application source into this stage.
# The flags deliberately match the production build below, so BuildKit can
# reuse the compiled dependencies on normal source-only changes.
COPY --from=planner /app/recipe.json recipe.json
COPY --from=planner /app/vendor/tlsn ./vendor/tlsn
COPY --from=planner /app/vendor/tlsn-utils ./vendor/tlsn-utils
RUN cargo chef cook --release --recipe-path recipe.json --package llm-notary-server --package llm-notary-platform

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY js/desktop/src-tauri/Cargo.toml ./js/desktop/src-tauri/Cargo.toml
RUN mkdir -p js/desktop/src-tauri/src && touch js/desktop/src-tauri/src/lib.rs
COPY vendor/tlsn ./vendor/tlsn
COPY vendor/tlsn-utils ./vendor/tlsn-utils
COPY migrations-postgres ./migrations-postgres
# The API and notary share a dependency graph. Building both here lets BuildKit
# reuse one compilation for the two final images.
RUN cargo build --release \
    -p llm-notary-server --bin llm-notary-server \
    -p llm-notary-platform --bin llm-notary-api --bin llm-notary-api-migrate

# Opt-in target for the split-process resource benchmark. It deliberately is
# not part of the production image: the test client also hosts a local TLS
# fixture while the notary runs in a separate, memory-limited container.
FROM builder AS profile
RUN cargo test --release -p llm-notary-core --test proxy_tls_split_profile --no-run

FROM debian:bookworm-slim AS api

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/llm-notary-api /usr/local/bin/llm-notary-api
COPY --from=builder /app/target/release/llm-notary-api-migrate /usr/local/bin/llm-notary-api-migrate
RUN ldd /usr/local/bin/llm-notary-api >/dev/null

EXPOSE 8080
CMD ["llm-notary-api"]

FROM debian:bookworm-slim AS notary

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/llm-notary-server /usr/local/bin/llm-notary-server
RUN llm-notary-server --help >/dev/null

EXPOSE 7047
ENTRYPOINT ["/bin/sh", "-ec", "key_file=${NOTARY_SIGNING_KEY_FILE:-/run/secrets/notary_signing_key}; if ! test -r \"$key_file\"; then echo 'notary signing key file is required and must be readable' >&2; exit 1; fi; exec llm-notary-server --listen 0.0.0.0:7047 --signing-key \"$key_file\" --allow-host api.openai.com --allow-host chatgpt.com --allow-host api.anthropic.com --allow-host api.deepseek.com --allow-host openrouter.ai \"$@\"", "--"]

# The local daemon is intentionally separate from the hosted API/notary
# runtime images. Cook only its dependency graph so an E2E build does not also
# compile the hosted PostgreSQL/S3 stack.
FROM chef AS daemon-builder

COPY --from=planner /app/recipe.json recipe.json
COPY --from=planner /app/vendor/tlsn ./vendor/tlsn
COPY --from=planner /app/vendor/tlsn-utils ./vendor/tlsn-utils
RUN cargo chef cook --release --recipe-path recipe.json --package llm-notary-client

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY js/desktop/src-tauri/Cargo.toml ./js/desktop/src-tauri/Cargo.toml
RUN mkdir -p js/desktop/src-tauri/src && touch js/desktop/src-tauri/src/lib.rs
COPY vendor/tlsn ./vendor/tlsn
COPY vendor/tlsn-utils ./vendor/tlsn-utils
COPY config/updater-public-key.txt ./config/updater-public-key.txt
COPY skills/llm-notary ./skills/llm-notary
RUN cargo build --release \
    -p llm-notary-client \
    --bin llm-notaryd --bin llm-notary

# The private-root hook and raw notary fixture exist only in this opt-in E2E
# build. The production `daemon` stage below still copies the feature-free
# binaries from `daemon-builder`.
FROM daemon-builder AS daemon-e2e-builder
RUN cargo build --release -p llm-notary-client --features daemon-e2e \
    --bin llm-notaryd --bin llm-notary \
    --bin llm-notary-e2e-notary

FROM debian:bookworm-slim AS daemon

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=daemon-builder /app/target/release/llm-notaryd /usr/local/bin/llm-notaryd
COPY --from=daemon-builder /app/target/release/llm-notary /usr/local/bin/llm-notary
RUN llm-notaryd --help >/dev/null \
    && llm-notary --help >/dev/null

ENTRYPOINT ["llm-notaryd"]

# Production multi-replica runtime. Operators mount a read-only explicit
# configuration and secret files, while the pre-provisioned vault lives on a
# shared read-only volume. The process never needs root or a privileged port.
FROM daemon AS daemon-cluster

RUN groupadd --gid 10001 llm-notary \
    && useradd --uid 10001 --gid 10001 --system --no-create-home llm-notary \
    && mkdir -p /var/lib/llm-notary/config /var/lib/llm-notary/data \
    && chown -R 10001:10001 /var/lib/llm-notary
ENV XDG_CONFIG_HOME=/var/lib/llm-notary/config \
    XDG_DATA_HOME=/var/lib/llm-notary/data
USER 10001:10001
EXPOSE 8787 8788

# Diagnostics live only in the E2E image. They let the harness inspect the
# loopback-only service and seed deterministic persistence fixtures without
# weakening the daemon's production listener or exposing a host port.
FROM daemon AS daemon-e2e

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl jq openssl python3 sqlite3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=daemon-e2e-builder /app/target/release/llm-notaryd /usr/local/bin/llm-notaryd
COPY --from=daemon-e2e-builder /app/target/release/llm-notary /usr/local/bin/llm-notary
COPY --from=daemon-e2e-builder /app/target/release/llm-notary-e2e-notary /usr/local/bin/llm-notary-e2e-notary
COPY deploy/daemon-e2e/config.toml /etc/llm-notary/config.toml
RUN cp /etc/llm-notary/config.toml /etc/llm-notary/config-s3.toml \
    && sed -i 's/backend = "filesystem"/backend = "s3"/' /etc/llm-notary/config-s3.toml \
    && printf '%s\n' \
        '' \
        '[storage.s3]' \
        'bucket = "llm-notary-daemon-e2e"' \
        'region = "us-east-1"' \
        'endpoint = "http://minio:9000"' \
        'prefix = "daemon-e2e/artifacts"' \
        'force_path_style = true' \
        'allow_insecure_http = true' \
        'connect_timeout_seconds = 3' \
        'operation_timeout_seconds = 10' \
        >> /etc/llm-notary/config-s3.toml \
    && cp /etc/llm-notary/config.toml /etc/llm-notary/config-postgres.toml \
    && sed -i 's/backend = "sqlite"/backend = "postgres"/' /etc/llm-notary/config-postgres.toml \
    && printf '%s\n' \
        '' \
        '[catalog.postgres]' \
        'ssl_mode = "disable"' \
        'max_connections = 8' \
        'connect_timeout_seconds = 3' \
        'acquire_timeout_seconds = 3' \
        'migration_lock_timeout_seconds = 5' \
        >> /etc/llm-notary/config-postgres.toml \
    && cp /etc/llm-notary/config-postgres.toml /etc/llm-notary/config-postgres-lock-timeout.toml \
    && sed -i 's/migration_lock_timeout_seconds = 5/migration_lock_timeout_seconds = 1/' /etc/llm-notary/config-postgres-lock-timeout.toml \
    && cp /etc/llm-notary/config-postgres.toml /etc/llm-notary/config-postgres-s3.toml \
    && sed -i 's/backend = "filesystem"/backend = "s3"/' /etc/llm-notary/config-postgres-s3.toml \
    && sed -n '/^\[storage.s3\]/,$p' /etc/llm-notary/config-s3.toml \
        >> /etc/llm-notary/config-postgres-s3.toml \
    && cp /etc/llm-notary/config-postgres-s3.toml /etc/llm-notary/config-cluster-template.toml \
    && sed -i 's/127.0.0.1:8787/0.0.0.0:8787/' /etc/llm-notary/config-cluster-template.toml \
    && sed -i 's/127.0.0.1:8788/0.0.0.0:8788/' /etc/llm-notary/config-cluster-template.toml \
    && printf '%s\n' \
        '' \
        '[cluster]' \
        'enabled = true' \
        'instance_id = "__INSTANCE_ID__"' \
        'heartbeat_interval_seconds = 2' \
        'lease_seconds = 8' \
        'claim_max_runtime_seconds = 60' \
        'withdrawal_delay_seconds = 4' \
        'shutdown_grace_seconds = 45' \
        'trusted_ingress = true' \
        'vault_compatibility_sha256 = "__VAULT_COMPATIBILITY__"' \
        '' \
        '[admin.auth]' \
        'username = "cluster-admin"' \
        'password_hash = "$argon2id$v=19$m=19456,t=2,p=1$Y2x1c3Rlci1lMmUtc2FsdA$e5miUzfGBUsUELcxECEyngoD2trkyo28hZ794hQ9bO8"' \
        >> /etc/llm-notary/config-cluster-template.toml
COPY deploy/daemon-e2e/provider.py /usr/local/libexec/llm-notary-e2e-provider.py
COPY deploy/daemon-e2e/share.py /usr/local/libexec/llm-notary-e2e-share.py
