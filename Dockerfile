FROM --platform=$BUILDPLATFORM rust:1.84 AS build
COPY . .
RUN cargo build -p rapimt_cli --release

FROM alpine:latest AS runtime
COPY --from=build ./target/release/ib_server /usr/local/bin/ib_server

