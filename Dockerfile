# Hardened multi-stage build (REQ-CON-001/002). The runtime stage is distroless: no
# shell, no package manager, no build toolchain; non-root UID; the rootfs is mounted
# read-only at runtime (compose/k8s) and the binary needs no write access. Secrets are
# injected at runtime (env / tmpfs), never baked into a layer.
FROM rust:1.96.0-slim AS build
ENV CARGO_HTTP_CHECK_REVOKE=false
WORKDIR /src
COPY . .
RUN cargo build --release --bin overlay-broadcast

# Minimal, non-root runtime. `:nonroot` runs as UID 65532 with no shell.
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime
WORKDIR /app
COPY --from=build /src/target/release/overlay-broadcast /app/overlay-broadcast
USER nonroot:nonroot
# Liveness via the CLI selftest (the api /health endpoint is wired in compose).
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["/app/overlay-broadcast", "selftest"]
ENTRYPOINT ["/app/overlay-broadcast"]
CMD ["selftest"]
