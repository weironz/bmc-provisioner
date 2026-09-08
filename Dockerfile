FROM oven/bun:1 AS ui-build
WORKDIR /src/ui
COPY ui/package.json ui/bun.lock ./
RUN bun install --frozen-lockfile
COPY ui/ ./
RUN bun run build

FROM rust:1.98-bookworm AS service-build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=service-build /src/target/release/bmc-provisionerd /usr/local/bin/bmc-provisionerd
COPY --from=ui-build /src/ui/dist /app/ui
ENV BMC_PROVISIONER_BIND=0.0.0.0:6770
ENV BMC_PROVISIONER_UI_DIR=/app/ui
EXPOSE 6770
ENTRYPOINT ["/usr/local/bin/bmc-provisionerd"]
