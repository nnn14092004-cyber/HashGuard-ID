# Stage 1: Build stage with SHA-NI / SSE4.2 hardware acceleration flags
FROM rust:1.85-alpine AS builder

RUN apk add --no-cache musl-dev gcc

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY src/ src/

ENV RUSTFLAGS="-C target-cpu=native -C opt-level=3"
RUN cargo build --release --bin gateway

# Stage 2: Minimalist Distroless Runtime
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /
COPY --from=builder /app/target/release/gateway /gateway

USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["/gateway"]