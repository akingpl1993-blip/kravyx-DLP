# kravyx-policy: Rust engine (static lib) + Go service, distroless runtime, non-root.
# Build from the repository root:  docker build -f deploy/docker/policy.Dockerfile .
# Pin base images by digest in the release pipeline.
FROM rust:1.80-bookworm AS engine
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY core ./core
COPY tests ./tests
RUN cargo build --release --locked -p kravyx-ffi

FROM golang:1.23-bookworm AS service
WORKDIR /src
COPY go.mod ./
COPY internal ./internal
COPY services ./services
COPY core/ffi/include ./core/ffi/include
COPY --from=engine /src/target/release/libkravyx_ffi.a ./target/release/
ARG VERSION=dev
RUN CGO_ENABLED=1 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/kravyx-policy ./services/policy/cmd/kravyx-policy

# glibc is required by the cgo build; distroless/base provides it without a shell.
FROM gcr.io/distroless/base-debian12:nonroot
COPY --from=service /out/kravyx-policy /usr/local/bin/kravyx-policy
USER nonroot:nonroot
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/kravyx-policy"]
