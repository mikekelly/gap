# Multi-stage build for Agent Credential Proxy (ACP)
# Produces a minimal runtime image with acp and acp-server binaries

# Build stage
# Using nightly for edition2024 support (required by base64ct 1.8.2)
FROM rustlang/rust:nightly-slim AS builder

# Install build dependencies
RUN apt-get update && \
    apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy workspace manifest first for better caching
COPY Cargo.toml Cargo.lock ./

# Copy all crate manifests
COPY acp/Cargo.toml ./acp/
COPY acp-server/Cargo.toml ./acp-server/
COPY acp-lib/Cargo.toml ./acp-lib/

# Create dummy source files to build dependencies
RUN mkdir -p acp/src acp-server/src acp-lib/src && \
    echo "fn main() {}" > acp/src/main.rs && \
    echo "fn main() {}" > acp-server/src/main.rs && \
    echo "pub fn dummy() {}" > acp-lib/src/lib.rs

# Build dependencies (this layer will be cached)
RUN cargo build --release && \
    rm -rf acp/src acp-server/src acp-lib/src

# Copy actual source code
COPY acp ./acp
COPY acp-server ./acp-server
COPY acp-lib ./acp-lib

# Build release binaries
# Touch to ensure rebuild even if timestamps are weird
RUN touch acp/src/main.rs acp-server/src/main.rs acp-lib/src/lib.rs && \
    cargo build --release --bins

# Runtime stage
# Must match builder's Debian version for GLIBC compatibility
FROM debian:trixie-slim

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for running the service
RUN groupadd -r acp && \
    useradd -r -g acp -d /var/lib/acp -s /bin/bash acp

# Create data directory with appropriate permissions
RUN mkdir -p /var/lib/acp && \
    chown -R acp:acp /var/lib/acp

# Copy binaries from builder
COPY --from=builder /build/target/release/acp /usr/local/bin/acp
COPY --from=builder /build/target/release/acp-server /usr/local/bin/acp-server

# Copy entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Ensure binaries and entrypoint are executable
RUN chmod +x /usr/local/bin/acp /usr/local/bin/acp-server /usr/local/bin/docker-entrypoint.sh

# Note: We intentionally do NOT declare VOLUME here.
# The entrypoint script enforces that a volume must be explicitly mounted.
# This prevents accidental loss of secrets when the container is removed.

# Switch to non-root user
USER acp
WORKDIR /var/lib/acp

# Expose proxy port (9443) and management API port (9080)
EXPOSE 9443 9080

# Health check for the management API
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9080/status || exit 1

# Entrypoint validates volume mount before starting
ENTRYPOINT ["docker-entrypoint.sh"]

# Default command runs the server with data directory set
CMD ["acp-server", "--data-dir", "/var/lib/acp"]
