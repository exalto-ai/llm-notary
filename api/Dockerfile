FROM rust:1.95-slim AS builder

WORKDIR /app
COPY . .
RUN cargo build --release --bin llm-notary-api

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/llm-notary-api /usr/local/bin/llm-notary-api

EXPOSE 8080
ENTRYPOINT ["llm-notary-api"]
