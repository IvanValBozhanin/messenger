FROM node:20-slim AS frontend
WORKDIR /fe
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/tsconfig.json ./
COPY frontend/src ./src
RUN npx esbuild src/main.ts --bundle --minify --outfile=app.js

FROM rust:1-slim AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/messenger /app/messenger
COPY static ./static
COPY --from=frontend /fe/app.js ./static/app.js
ENV PORT=8000
EXPOSE 8000
CMD ["/app/messenger"]
