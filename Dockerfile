# Vellaveto Multi-Stage Dockerfile
# Builds optimized production binaries for the MCP firewall
#
# Usage:
#   docker build -t vellaveto:latest .
#   docker run -p 3000:3000 vellaveto:latest serve --config /etc/vellaveto/config.toml

# Build stage: Compile Rust binaries with musl for static linking
FROM rust:1.93-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig

# Create a non-root user for the build
WORKDIR /build

# Copy workspace manifests first for layer caching
COPY Cargo.toml Cargo.lock ./
COPY vellaveto-types/Cargo.toml vellaveto-types/
COPY vellaveto-engine/Cargo.toml vellaveto-engine/
COPY vellaveto-audit/Cargo.toml vellaveto-audit/
COPY vellaveto-config/Cargo.toml vellaveto-config/
COPY vellaveto-canonical/Cargo.toml vellaveto-canonical/
COPY vellaveto-mcp/Cargo.toml vellaveto-mcp/
COPY vellaveto-approval/Cargo.toml vellaveto-approval/
COPY vellaveto-cluster/Cargo.toml vellaveto-cluster/
COPY vellaveto-server/Cargo.toml vellaveto-server/
COPY vellaveto-http-proxy/Cargo.toml vellaveto-http-proxy/
COPY vellaveto-proxy/Cargo.toml vellaveto-proxy/
COPY vellaveto-integration/Cargo.toml vellaveto-integration/

# Create dummy src files for dependency caching
RUN mkdir -p vellaveto-types/src vellaveto-engine/src vellaveto-audit/src \
    vellaveto-config/src vellaveto-canonical/src vellaveto-mcp/src \
    vellaveto-approval/src vellaveto-cluster/src vellaveto-server/src \
    vellaveto-http-proxy/src vellaveto-proxy/src vellaveto-integration/src \
    && echo "pub fn dummy() {}" > vellaveto-types/src/lib.rs \
    && echo "pub fn dummy() {}" > vellaveto-engine/src/lib.rs \
    && echo "pub fn dummy() {}" > vellaveto-audit/src/lib.rs \
    && echo "pub fn dummy() {}" > vellaveto-config/src/lib.rs \
    && echo "pub fn dummy() {}" > vellaveto-canonical/src/lib.rs \
    && echo "pub fn dummy() {}" > vellaveto-mcp/src/lib.rs \
    && echo "pub fn dummy() {}" > vellaveto-approval/src/lib.rs \
    && echo "pub fn dummy() {}" > vellaveto-cluster/src/lib.rs \
    && echo "fn main() {}" > vellaveto-server/src/main.rs \
    && echo "fn main() {}" > vellaveto-http-proxy/src/main.rs \
    && echo "fn main() {}" > vellaveto-proxy/src/main.rs \
    && echo "" > vellaveto-integration/src/lib.rs

# Build dependencies only (for layer caching)
RUN cargo build --release --target x86_64-unknown-linux-musl \
    --bin vellaveto --bin vellaveto-http-proxy || true

# Copy actual source code
COPY vellaveto-types/src vellaveto-types/src/
COPY vellaveto-engine/src vellaveto-engine/src/
COPY vellaveto-engine/benches vellaveto-engine/benches/
COPY vellaveto-audit/src vellaveto-audit/src/
COPY vellaveto-audit/benches vellaveto-audit/benches/
COPY vellaveto-config/src vellaveto-config/src/
COPY vellaveto-canonical/src vellaveto-canonical/src/
COPY vellaveto-mcp/src vellaveto-mcp/src/
COPY vellaveto-mcp/benches vellaveto-mcp/benches/
COPY vellaveto-approval/src vellaveto-approval/src/
COPY vellaveto-cluster/src vellaveto-cluster/src/
COPY vellaveto-server/src vellaveto-server/src/
COPY vellaveto-http-proxy/src vellaveto-http-proxy/src/
COPY vellaveto-proxy/src vellaveto-proxy/src/

# Touch source files to invalidate cache
RUN find . -name "*.rs" -exec touch {} \;

# Build release binaries
RUN cargo build --release --target x86_64-unknown-linux-musl \
    --bin vellaveto --bin vellaveto-http-proxy

# Verify binaries exist and are executable (musl target guarantees static linking)
RUN test -x /build/target/x86_64-unknown-linux-musl/release/vellaveto \
    && test -x /build/target/x86_64-unknown-linux-musl/release/vellaveto-http-proxy

# Runtime stage: Minimal Alpine image
FROM alpine:3.21

LABEL org.opencontainers.image.title="Vellaveto" \
      org.opencontainers.image.description="Runtime security engine for AI agent tool calls" \
      org.opencontainers.image.source="https://github.com/paolovella/vellaveto" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.vendor="Paolo Vella"

# Security: Run as non-root user
RUN addgroup -S vellaveto && adduser -S vellaveto -G vellaveto

# Install runtime dependencies (CA certs for HTTPS)
RUN apk add --no-cache ca-certificates tzdata

# Create config and data directories
RUN mkdir -p /etc/vellaveto /var/lib/vellaveto /var/log/vellaveto \
    && chown -R vellaveto:vellaveto /var/lib/vellaveto /var/log/vellaveto

# Copy binaries from builder
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/vellaveto /usr/local/bin/
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/vellaveto-http-proxy /usr/local/bin/

# Copy example configs
COPY examples/*.toml /etc/vellaveto/examples/

# Switch to non-root user
USER vellaveto

# Default port for HTTP API server
EXPOSE 3000

# Health check (assumes /health endpoint)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

# Default command: run the API server
ENTRYPOINT ["vellaveto"]
CMD ["serve", "--config", "/etc/vellaveto/config.toml"]
