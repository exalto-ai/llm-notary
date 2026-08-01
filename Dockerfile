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
# This image needs only the Rust workspace packages and vendored TLSNotary dependency.
COPY Cargo.toml Cargo.lock build.rs ./
COPY crates ./crates
COPY vendor/tlsn ./vendor/tlsn
COPY src ./src
COPY migrations-postgres ./migrations-postgres
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder

# Cook the dependency graph before copying application source into this stage.
# The flags deliberately match the production build below, so BuildKit can
# reuse the compiled dependencies on normal source-only changes.
COPY --from=planner /app/recipe.json recipe.json
COPY --from=planner /app/vendor/tlsn ./vendor/tlsn
RUN cargo chef cook --release --no-default-features --features api --recipe-path recipe.json

COPY Cargo.toml Cargo.lock build.rs ./
COPY crates ./crates
COPY vendor/tlsn ./vendor/tlsn
COPY src ./src
COPY migrations-postgres ./migrations-postgres
# The API and notary share a dependency graph. Building both here lets BuildKit
# reuse one compilation for the two final images.
RUN cargo build --release --no-default-features --features api --bin llm-notary-server --bin llm-notary-api --bin llm-notary-api-migrate

# Opt-in target for the split-process resource benchmark. It deliberately is
# not part of the production image: the test client also hosts a local TLS
# fixture while the notary runs in a separate, memory-limited container.
FROM builder AS profile
COPY tests ./tests
RUN cargo test --release --no-default-features --test proxy_tls_split_profile --no-run

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
ENTRYPOINT ["/bin/sh", "-ec", "key_file=${NOTARY_SIGNING_KEY_FILE:-/run/secrets/notary_signing_key}; if ! test -r \"$key_file\"; then echo 'notary signing key file is required and must be readable' >&2; exit 1; fi; exec llm-notary-server --listen 0.0.0.0:7047 --signing-key \"$key_file\" --allow-host api.openai.com --allow-host api.anthropic.com --allow-host api.deepseek.com --allow-host openrouter.ai \"$@\"", "--"]
