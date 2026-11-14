FROM --platform=$BUILDPLATFORM rust:1.91-bookworm AS build
ARG TARGETARCH
WORKDIR /src

RUN mkdir -p .cargo && \
    case "$TARGETARCH" in \
      amd64) echo "x86_64-unknown-linux-gnu" > /tmp/rust_target ;; \
      arm64) echo "aarch64-unknown-linux-gnu" > /tmp/rust_target ;; \
      *) echo "Unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac && \
    TARGET="$(cat /tmp/rust_target)" && \
    rustup target add "$TARGET" && \
    HOST_ARCH="$(uname -m)" && \
    if [ "$TARGET" = "aarch64-unknown-linux-gnu" ] && [ "$HOST_ARCH" != "aarch64" ]; then \
      apt-get update && apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu libc6-dev-arm64-cross && rm -rf /var/lib/apt/lists/*; \
      printf '[target.aarch64-unknown-linux-gnu]\nlinker = "aarch64-linux-gnu-gcc"\n' > .cargo/config.toml; \
    elif [ "$TARGET" = "x86_64-unknown-linux-gnu" ] && [ "$HOST_ARCH" != "x86_64" ]; then \
      apt-get update && apt-get install -y --no-install-recommends gcc-x86-64-linux-gnu libc6-dev-amd64-cross && rm -rf /var/lib/apt/lists/*; \
      printf '[target.x86_64-unknown-linux-gnu]\nlinker = "x86_64-linux-gnu-gcc"\n' > .cargo/config.toml; \
    fi

COPY Cargo.toml Cargo.lock ./
COPY crates/lumzel-frame/Cargo.toml crates/lumzel-frame/Cargo.toml
RUN mkdir -p src crates/lumzel-frame/src && \
    printf 'fn main() {}\n' > src/main.rs && \
    touch src/lib.rs crates/lumzel-frame/src/lib.rs && \
    cargo build --release --locked --target "$(cat /tmp/rust_target)" && \
    rm -rf src crates/lumzel-frame/src

COPY crates/lumzel-frame/src crates/lumzel-frame/src
COPY src src
RUN TARGET="$(cat /tmp/rust_target)" && \
    rm -f "target/$TARGET/release/lumzel-relay" \
          "target/$TARGET/release/liblumzel_relay"* \
          "target/$TARGET/release/deps/lumzel_relay"* \
          "target/$TARGET/release/deps/lumzel_frame"* && \
    find src crates/lumzel-frame/src -name '*.rs' -exec touch {} + && \
    cargo build --release --locked --target "$TARGET" && \
    cp "target/$TARGET/release/lumzel-relay" /tmp/lumzel-relay

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /tmp/lumzel-relay /usr/local/bin/lumzel-relay

EXPOSE 8080 3478/udp 3479/udp
ENV RELAY_BIND=0.0.0.0:8080
USER nobody
CMD ["lumzel-relay"]
