FROM rust:1.95-slim AS builder

WORKDIR /app
COPY . .
RUN cargo build --release --bin certified-notary

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/certified-notary /usr/local/bin/certified-notary

EXPOSE 7047
ENTRYPOINT ["/bin/sh", "-ec", "key_file=${NOTARY_SIGNING_KEY_FILE:-}; if [ -n \"$key_file\" ]; then test -r \"$key_file\"; cp \"$key_file\" /tmp/notary.key; elif [ -n \"${NOTARY_SIGNING_KEY:-}\" ]; then printf '%s' \"$NOTARY_SIGNING_KEY\" > /tmp/notary.key; else echo 'NOTARY_SIGNING_KEY_FILE or NOTARY_SIGNING_KEY is required' >&2; exit 1; fi; chmod 600 /tmp/notary.key; exec certified-notary --listen 0.0.0.0:7047 --signing-key /tmp/notary.key --allow-host api.openai.com --allow-host api.anthropic.com --allow-host api.deepseek.com"]
