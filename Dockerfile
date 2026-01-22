FROM rust:1.79-bookworm AS builder

WORKDIR /app
ARG APP_NAME={{project-name}}

COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release

COPY . .
RUN cargo build --release --bin ${APP_NAME}

FROM debian:bookworm-slim AS runtime

ARG APP_NAME={{project-name}}
ENV HTTP_HOST=0.0.0.0
ENV HTTP_PORT=3000

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/${APP_NAME} /usr/local/bin/app

EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/app"]
