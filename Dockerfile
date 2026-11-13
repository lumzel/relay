FROM rust:1.91-bookworm AS build
WORKDIR /src

COPY crates/lumzel-frame/Cargo.toml crates/lumzel-frame/Cargo.toml
COPY crates/lumzel-frame/src crates/lumzel-frame/src
COPY Cargo.toml Cargo.lock ./
COPY src src

RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/lumzel-relay /usr/local/bin/lumzel-relay

EXPOSE 8080 3478/udp 3479/udp
ENV RELAY_BIND=0.0.0.0:8080
USER nobody
CMD ["lumzel-relay"]
