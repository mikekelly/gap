#!/usr/bin/env bash
# Smoke test for Docker build and deployment
# Tests that the Docker container builds and runs correctly

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}✓${NC} $1"
}

log_fail() {
    echo -e "${RED}✗${NC} $1"
    exit 1
}

# Check if docker is available
if ! command -v docker &> /dev/null; then
    log_warn "Docker not found, skipping Docker smoke tests"
    exit 0
fi

# Clean up function
cleanup() {
    log_info "Cleaning up test containers and images..."
    docker compose -f /Users/mike/code/agent-credential-proxy/docker-compose.yml down -v 2>/dev/null || true
    docker rmi agent-credential-proxy-gap-server 2>/dev/null || true
}

# Register cleanup on exit
trap cleanup EXIT

log_info "Starting Docker smoke tests..."
echo ""

# Test 1: Docker build
echo "Test 1: Docker build"
echo "===================="

cd /Users/mike/code/agent-credential-proxy

if docker build -t gap-test:latest .; then
    log_pass "Docker build succeeded"
else
    log_fail "Docker build failed"
fi

# Test 2: Verify binaries in image
echo ""
echo "Test 2: Verify binaries in image"
echo "================================="

if docker run --rm gap-test:latest gap --version; then
    log_pass "gap binary works in container"
else
    log_fail "gap binary failed in container"
fi

if docker run --rm gap-test:latest gap-server --version; then
    log_pass "gap-server binary works in container"
else
    log_fail "gap-server binary failed in container"
fi

# Test 3: Docker Compose
echo ""
echo "Test 3: Docker Compose"
echo "======================"

if docker compose -f docker-compose.yml config > /dev/null; then
    log_pass "docker-compose.yml is valid"
else
    log_fail "docker-compose.yml validation failed"
fi

# Test 4: Start services
echo ""
echo "Test 4: Start services"
echo "======================"

log_info "Starting services with docker-compose..."
if docker compose up -d; then
    log_pass "Services started"
else
    log_fail "Failed to start services"
fi

# Wait for services to be healthy
log_info "Waiting for services to be ready..."
sleep 10

# Test 5: Health check
echo ""
echo "Test 5: Health check"
echo "===================="

if curl -f http://localhost:9080/status 2>/dev/null; then
    log_pass "Management API health check passed"
else
    log_fail "Management API health check failed"
fi

# Test 6: Verify mock API
echo ""
echo "Test 6: Verify mock API"
echo "======================="

if curl -f http://localhost:8080/get 2>/dev/null | grep -q "httpbin"; then
    log_pass "Mock API is accessible"
else
    log_fail "Mock API is not accessible"
fi

echo ""
echo -e "${GREEN}All Docker smoke tests passed!${NC}"
echo ""
log_info "Stopping services..."
docker compose down
