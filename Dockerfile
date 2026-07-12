FROM rust:1-slim AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/messenger /app/messenger
COPY static ./static
ENV PORT=8000
EXPOSE 8000
CMD ["/app/messenger"]
