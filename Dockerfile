# Sentinel Multi-Stage Dockerfile
# Builds optimized production binaries for the MCP firewall
#
# Usage:
#   docker build -t sentinel:latest .
#   docker run -p 3000:3000 sentinel:latest serve --config /etc/sentinel/config.toml

# Build stage: Compile Rust binaries with musl for static linking
FROM rust:1.82-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig

# Create a non-root user for the build
WORKDIR /build

# Copy workspace manifests first for layer caching
COPY Cargo.toml Cargo.lock ./
COPY sentinel-types/Cargo.toml sentinel-types/
COPY sentinel-engine/Cargo.toml sentinel-engine/
COPY sentinel-audit/Cargo.toml sentinel-audit/
COPY sentinel-config/Cargo.toml sentinel-config/
COPY sentinel-canonical/Cargo.toml sentinel-canonical/
COPY sentinel-mcp/Cargo.toml sentinel-mcp/
COPY sentinel-approval/Cargo.toml sentinel-approval/
COPY sentinel-cluster/Cargo.toml sentinel-cluster/
COPY sentinel-server/Cargo.toml sentinel-server/
COPY sentinel-http-proxy/Cargo.toml sentinel-http-proxy/
COPY sentinel-proxy/Cargo.toml sentinel-proxy/
COPY sentinel-integration/Cargo.toml sentinel-integration/

# Create dummy src files for dependency caching
RUN mkdir -p sentinel-types/src sentinel-engine/src sentinel-audit/src \
    sentinel-config/src sentinel-canonical/src sentinel-mcp/src \
    sentinel-approval/src sentinel-cluster/src sentinel-server/src \
    sentinel-http-proxy/src sentinel-proxy/src sentinel-integration/src \
    && echo "pub fn dummy() {}" > sentinel-types/src/lib.rs \
    && echo "pub fn dummy() {}" > sentinel-engine/src/lib.rs \
    && echo "pub fn dummy() {}" > sentinel-audit/src/lib.rs \
    && echo "pub fn dummy() {}" > sentinel-config/src/lib.rs \
    && echo "pub fn dummy() {}" > sentinel-canonical/src/lib.rs \
    && echo "pub fn dummy() {}" > sentinel-mcp/src/lib.rs \
    && echo "pub fn dummy() {}" > sentinel-approval/src/lib.rs \
    && echo "pub fn dummy() {}" > sentinel-cluster/src/lib.rs \
    && echo "fn main() {}" > sentinel-server/src/main.rs \
    && echo "fn main() {}" > sentinel-http-proxy/src/main.rs \
    && echo "fn main() {}" > sentinel-proxy/src/main.rs \
    && echo "" > sentinel-integration/src/lib.rs

# Build dependencies only (for layer caching)
RUN cargo build --release --target x86_64-unknown-linux-musl \
    --bin sentinel --bin sentinel-http-proxy || true

# Copy actual source code
COPY sentinel-types/src sentinel-types/src/
COPY sentinel-engine/src sentinel-engine/src/
COPY sentinel-engine/benches sentinel-engine/benches/
COPY sentinel-audit/src sentinel-audit/src/
COPY sentinel-config/src sentinel-config/src/
COPY sentinel-canonical/src sentinel-canonical/src/
COPY sentinel-mcp/src sentinel-mcp/src/
COPY sentinel-approval/src sentinel-approval/src/
COPY sentinel-cluster/src sentinel-cluster/src/
COPY sentinel-server/src sentinel-server/src/
COPY sentinel-http-proxy/src sentinel-http-proxy/src/
COPY sentinel-proxy/src sentinel-proxy/src/

# Touch source files to invalidate cache
RUN find . -name "*.rs" -exec touch {} \;

# Build release binaries
RUN cargo build --release --target x86_64-unknown-linux-musl \
    --bin sentinel --bin sentinel-http-proxy

# Verify binaries are statically linked
RUN file /build/target/x86_64-unknown-linux-musl/release/sentinel | grep -q "statically linked"

# Runtime stage: Minimal Alpine image
FROM alpine:3.21

# Security: Run as non-root user
RUN addgroup -S sentinel && adduser -S sentinel -G sentinel

# Install runtime dependencies (CA certs for HTTPS)
RUN apk add --no-cache ca-certificates tzdata

# Create config and data directories
RUN mkdir -p /etc/sentinel /var/lib/sentinel /var/log/sentinel \
    && chown -R sentinel:sentinel /var/lib/sentinel /var/log/sentinel

# Copy binaries from builder
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/sentinel /usr/local/bin/
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/sentinel-http-proxy /usr/local/bin/

# Copy example configs
COPY examples/*.toml /etc/sentinel/examples/

# Switch to non-root user
USER sentinel

# Default port for HTTP API server
EXPOSE 3000

# Health check (assumes /health endpoint)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

# Default command: run the API server
ENTRYPOINT ["sentinel"]
CMD ["serve", "--config", "/etc/sentinel/config.toml"]
