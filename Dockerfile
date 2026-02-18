# Multi-stage build for GAP (Gated Agent Proxy)
# Produces a minimal runtime image with gap and gap-server binaries

# Build stage
# Using nightly for edition2024 support (required by base64ct 1.8.2)
FROM rustlang/rust:nightly-slim AS builder

# Install build dependencies
RUN apt-get update && \
    apt-get install -y \
    pkg-config \
    libssl-dev \
    perl \
    make \
    cmake \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy workspace manifest first for better caching
COPY Cargo.toml Cargo.lock ./

# Copy all crate manifests
COPY gap/Cargo.toml ./gap/
COPY gap-server/Cargo.toml ./gap-server/
COPY gap-lib/Cargo.toml ./gap-lib/

# Create dummy source files to build dependencies
RUN mkdir -p gap/src gap-server/src gap-lib/src && \
    echo "fn main() {}" > gap/src/main.rs && \
    echo "fn main() {}" > gap-server/src/main.rs && \
    echo "pub fn dummy() {}" > gap-lib/src/lib.rs

# Build dependencies (this layer will be cached)
RUN cargo build --release && \
    rm -rf gap/src gap-server/src gap-lib/src

# Copy actual source code
COPY gap ./gap
COPY gap-server ./gap-server
COPY gap-lib ./gap-lib

# Build release binaries
# Touch to ensure rebuild even if timestamps are weird
RUN touch gap/src/main.rs gap-server/src/main.rs gap-lib/src/lib.rs && \
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
RUN groupadd -r gap && \
    useradd -r -g gap -d /var/lib/gap -s /bin/bash gap

# Create data directory with appropriate permissions
RUN mkdir -p /var/lib/gap && \
    chown -R gap:gap /var/lib/gap

# Copy binaries from builder
COPY --from=builder /build/target/release/gap /usr/local/bin/gap
COPY --from=builder /build/target/release/gap-server /usr/local/bin/gap-server

# Copy entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Ensure binaries and entrypoint are executable
RUN chmod +x /usr/local/bin/gap /usr/local/bin/gap-server /usr/local/bin/docker-entrypoint.sh

# Note: We intentionally do NOT declare VOLUME here.
# The entrypoint script enforces that a volume must be explicitly mounted.
# This prevents accidental loss of secrets when the container is removed.

# Switch to non-root user
USER gap
WORKDIR /var/lib/gap

# Expose proxy port (9443) and management API port (9080)
EXPOSE 9443 9080

# Health check for the management API
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fk https://localhost:9080/status || exit 1

# Entrypoint validates volume mount before starting
ENTRYPOINT ["docker-entrypoint.sh"]

# Default command runs the server with data directory set
CMD ["gap-server", "--data-dir", "/var/lib/gap", "--bind-address", "0.0.0.0"]
