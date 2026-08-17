FROM rust:1.95-slim-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY runtime ./runtime
COPY platform ./platform
COPY js/desktop/src-tauri/Cargo.toml ./js/desktop/src-tauri/Cargo.toml
COPY js/desktop/src-tauri/src/lib.rs ./js/desktop/src-tauri/src/lib.rs
RUN cargo build --locked --release \
    -p llm-notary-hosted-server --bin llm-notary-hosted-server \
    -p notary-api --bin notary-api

FROM debian:bookworm-slim AS api

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/notary-api /usr/local/bin/notary-api
RUN ldd /usr/local/bin/notary-api >/dev/null
EXPOSE 8080
CMD ["notary-api", "serve"]

FROM debian:bookworm-slim AS notary

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/llm-notary-hosted-server /usr/local/bin/llm-notary-server
RUN llm-notary-server --help >/dev/null
EXPOSE 7047
ENTRYPOINT ["/bin/sh", "-ec", "key_file=${NOTARY_SIGNING_KEY_FILE:-/run/secrets/notary_signing_key}; if ! test -r \"$key_file\"; then echo 'notary signing key file is required and must be readable' >&2; exit 1; fi; exec llm-notary-server --listen 0.0.0.0:7047 --signing-key \"$key_file\" --allow-host api.openai.com --allow-host chatgpt.com --allow-host api.anthropic.com --allow-host api.deepseek.com --allow-host openrouter.ai \"$@\"", "--"]
