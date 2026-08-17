FROM rust:1.95-slim-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY runtime ./runtime
COPY platform ./platform
COPY js/desktop/src-tauri/Cargo.toml ./js/desktop/src-tauri/Cargo.toml
COPY js/desktop/src-tauri/src/lib.rs ./js/desktop/src-tauri/src/lib.rs
RUN cargo build --locked --release \
    -p notary-server-platform-adapter --bin notary-server \
    -p notary-api --bin notary-api

FROM debian:bookworm-slim AS notary-api

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
COPY --from=builder /app/target/release/notary-server /usr/local/bin/notary-server
RUN notary-server --help >/dev/null
EXPOSE 7047
ENTRYPOINT ["notary-server"]
CMD ["serve"]
