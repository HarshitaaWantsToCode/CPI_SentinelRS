# Build stage
FROM rust:1.80-slim AS builder

WORKDIR /usr/src/sentinelrs
COPY . .

RUN cargo build --release -p sentinel-server

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /usr/src/sentinelrs/target/release/sentinel-server /app/sentinel-server

ENV PORT=8080
ENV RUST_LOG=info
EXPOSE 8080

CMD ["/app/sentinel-server"]
