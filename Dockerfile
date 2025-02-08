FROM rust:1.84.1-slim-bookworm AS build
COPY . .
RUN rustup default nightly
RUN cargo build -p rapimt_cli --release

FROM alpine:latest AS runtime
COPY --from=build ./target/release/ib_server /usr/local/bin/ib_server

