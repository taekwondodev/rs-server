ARG RUST_VERSION=1.92.0
ARG APP_NAME=rs-server

################################################################################
FROM rust:${RUST_VERSION}-alpine AS build
ARG APP_NAME
WORKDIR /app

RUN apk add --no-cache \
    clang \
    curl \
    git \
    lld \
    musl-dev \
    openssl-dev \
    openssl-libs-static \
    pkgconfig

COPY Cargo.toml Cargo.lock ./

RUN mkdir src && echo "fn main() {}" > src/main.rs

RUN --mount=type=cache,target=/app/target/ \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/usr/local/cargo/registry/ \
    cargo build --locked --release && \
    rm src/main.rs

COPY src ./src

RUN --mount=type=cache,target=/app/target/ \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/usr/local/cargo/registry/ \
    cargo build --locked --release && \
    cp ./target/release/"${APP_NAME}" /bin/server

################################################################################

FROM alpine:3.19 AS final

ARG UID=10001
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    appuser

COPY --from=build /bin/server /bin/server

RUN chmod +x /bin/server

USER appuser

EXPOSE 8080

CMD ["/bin/server"]
