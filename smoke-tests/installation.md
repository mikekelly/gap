# Installation Smoke Tests

This directory contains smoke tests for ACP installation methods.

## Test Scripts

### test-install.sh
Tests the `install.sh` script:
- Platform detection (macOS/Linux, x86_64/aarch64)
- Build from source installation
- Binary verification (existence, executability, --version)
- Help output

**Requirements:**
- Rust/Cargo (for build-from-source test)

**Usage:**
```bash
./test-install.sh
```

### test-docker.sh
Tests Docker deployment:
- Docker image build
- Binary verification in container
- docker-compose.yml validation
- Service startup and health checks
- Mock API accessibility

**Requirements:**
- Docker
- docker-compose (or Docker Compose v2)

**Usage:**
```bash
./test-docker.sh
```

## Running All Tests

To run all installation tests:

```bash
cd smoke-tests
./test-install.sh
./test-docker.sh
```

## Test Coverage

### install.sh
- ✅ Platform detection (macOS, Linux)
- ✅ Architecture detection (x86_64, aarch64)
- ✅ Build from source
- ✅ Binary installation to custom prefix
- ✅ Executable permissions
- ✅ Version verification
- ✅ Help output
- ⚠️  Binary download (skipped - requires GitHub releases)

### Dockerfile
- ✅ Multi-stage build
- ✅ Dependency caching
- ✅ Binary inclusion
- ✅ Non-root user setup
- ✅ Health check
- ✅ Volume configuration

### docker-compose.yml
- ✅ Configuration validation
- ✅ Service orchestration
- ✅ Port mapping
- ✅ Volume persistence
- ✅ Network isolation
- ✅ Health checks
- ✅ Mock API integration

## Expected Behavior

### Successful Install
When installation succeeds, you should see:
1. Platform detection output
2. Build/download progress
3. Installation confirmation
4. Next steps instructions
5. Binaries at specified location

### Failed Install
Common failure scenarios:
- **No Rust/Cargo**: Install from https://rustup.rs/
- **No Docker**: Install from https://docker.com/
- **Permission denied**: Use sudo or change --prefix
- **Network error**: Check internet connection

## CI Integration

These smoke tests are designed to run in CI pipelines:

```yaml
# Example GitHub Actions
- name: Test install script
  run: |
    chmod +x smoke-tests/test-install.sh
    smoke-tests/test-install.sh

- name: Test Docker
  run: |
    chmod +x smoke-tests/test-docker.sh
    smoke-tests/test-docker.sh
```

## Manual Testing

### Test install.sh on macOS
```bash
# Build from source to /usr/local
./install.sh --build-from-source

# Build from source to custom location
./install.sh --build-from-source --prefix ~/acp-test

# Download binary (when releases available)
./install.sh
```

### Test install.sh on Linux
```bash
# Same commands as macOS
./install.sh --build-from-source --prefix ~/acp-test
```

### Test Docker locally
```bash
# Build and run
docker build -t acp-local .
docker run --rm acp-local acp --version

# Full stack with compose
docker compose up -d
curl http://localhost:9080/status
docker compose down
```

## Debugging

### Install Script Issues
Add debugging output:
```bash
bash -x ./install.sh --build-from-source --prefix /tmp/acp-test
```

### Docker Build Issues
Check build logs:
```bash
docker build --progress=plain -t acp-debug .
```

### Container Runtime Issues
Check logs:
```bash
docker compose logs acp-server
docker compose logs mock-api
```

Inspect running container:
```bash
docker compose exec acp-server /bin/bash
```

## Notes

- Install script supports both macOS and Linux
- Docker image uses Debian Bookworm (stable)
- All tests clean up after themselves
- Tests can run in parallel (different temp directories)
- Platform detection is automatic
