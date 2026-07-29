# Keep the build and runtime stages on the same Debian release. The floating
# `slim` tag may move to a newer glibc before the runtime images do.
FROM rust:1.95-slim-bookworm AS builder

WORKDIR /app
# Keep the Rust build cache independent of the SPA, deployment files, and docs.
# This image needs only the Rust package and its vendored TLSNotary dependency.
COPY Cargo.toml Cargo.lock ./
COPY vendor/tlsn ./vendor/tlsn
COPY src ./src
COPY migrations ./migrations
# `llm-notary-api` embeds the reviewed public collection manifest at compile
# time. Keep task fixtures and run notes out of the production image context.
COPY examples/production-seed/publications.json ./examples/production-seed/publications.json
# The API and notary share a dependency graph. Building both here lets BuildKit
# reuse one compilation for the two final images.
RUN cargo build --release --no-default-features --features api --bin certified-notary --bin llm-notary-api

# Opt-in target for the split-process resource benchmark. It deliberately is
# not part of the production image: the test client also hosts a local TLS
# fixture while the notary runs in a separate, memory-limited container.
FROM builder AS profile
COPY tests ./tests
RUN cargo test --release --no-default-features --test proxy_tls_split_profile --no-run

FROM debian:bookworm-slim AS api

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/llm-notary-api /usr/local/bin/llm-notary-api
RUN ldd /usr/local/bin/llm-notary-api >/dev/null

EXPOSE 8080
ENTRYPOINT ["llm-notary-api"]

FROM debian:bookworm-slim AS notary

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/certified-notary /usr/local/bin/certified-notary
RUN certified-notary --help >/dev/null

EXPOSE 7047
ENTRYPOINT ["/bin/sh", "-ec", "key_file=${NOTARY_SIGNING_KEY_FILE:-}; if [ -n \"$key_file\" ]; then test -r \"$key_file\"; cp \"$key_file\" /tmp/notary.key; elif [ -n \"${NOTARY_SIGNING_KEY:-}\" ]; then printf '%s' \"$NOTARY_SIGNING_KEY\" > /tmp/notary.key; else echo 'NOTARY_SIGNING_KEY_FILE or NOTARY_SIGNING_KEY is required' >&2; exit 1; fi; chmod 600 /tmp/notary.key; exec certified-notary --listen 0.0.0.0:7047 --signing-key /tmp/notary.key --allow-host api.openai.com --allow-host api.anthropic.com --allow-host api.deepseek.com \"$@\"", "--"]
