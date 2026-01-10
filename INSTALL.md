# Installing ACP

Agent Credential Proxy (ACP) can be installed on macOS and Linux using several methods.

## Quick Install

### Option 1: Install Script (Recommended)

Build from source:
```bash
curl -fsSL https://raw.githubusercontent.com/yourusername/agent-credential-proxy/main/install.sh | bash -s -- --build-from-source
```

Or download prebuilt binary (when releases are available):
```bash
curl -fsSL https://raw.githubusercontent.com/yourusername/agent-credential-proxy/main/install.sh | bash
```

### Option 2: Manual Build

```bash
# Clone repository
git clone https://github.com/yourusername/agent-credential-proxy.git
cd agent-credential-proxy

# Build release binaries
cargo build --release

# Install to /usr/local/bin (requires sudo)
sudo cp target/release/acp /usr/local/bin/
sudo cp target/release/acp-server /usr/local/bin/
```

### Option 3: Docker

```bash
# Pull image (when available)
docker pull yourusername/acp:latest

# Or build locally
docker build -t acp:latest .

# Run with docker-compose
docker compose up -d
```

## Installation Options

### install.sh Options

```bash
./install.sh [OPTIONS]

Options:
  --prefix PATH           Installation prefix (default: /usr/local)
  --build-from-source     Build from source instead of downloading binary
  --version VERSION       Install specific version (default: latest)
  --help                  Show help message
```

### Custom Installation Prefix

Install to a custom location without sudo:

```bash
./install.sh --build-from-source --prefix ~/.local
```

Then add `~/.local/bin` to your PATH:

```bash
# Add to ~/.bashrc or ~/.zshrc
export PATH="$HOME/.local/bin:$PATH"
```

## Platform Support

### macOS

**Supported:**
- macOS 10.15 (Catalina) or later
- Intel (x86_64) and Apple Silicon (aarch64)

**Installation:**
```bash
./install.sh --build-from-source
```

**Keychain Integration:**
- ACP uses macOS Keychain for secure storage
- First run may prompt for keychain access

### Linux

**Supported:**
- Any modern Linux distribution
- x86_64 and aarch64 architectures

**Installation:**
```bash
./install.sh --build-from-source
```

**Storage:**
- Uses file-based storage with 0600 permissions
- Default location: `~/.config/acp/` or `$XDG_CONFIG_HOME/acp/`

## Docker Deployment

### Using docker-compose (Recommended)

```bash
# Start services
docker compose up -d

# View logs
docker compose logs -f acp-server

# Stop services
docker compose down
```

### Using Docker directly

```bash
# Build image
docker build -t acp:latest .

# Run server
docker run -d \
  --name acp-server \
  -p 9443:9443 \
  -p 9080:9080 \
  -v acp-data:/var/lib/acp \
  acp:latest
```

### Persisting Data

Data is stored in the Docker volume `acp-data`:

```bash
# Backup data
docker run --rm -v acp-data:/data -v $(pwd):/backup ubuntu tar czf /backup/acp-backup.tar.gz /data

# Restore data
docker run --rm -v acp-data:/data -v $(pwd):/backup ubuntu tar xzf /backup/acp-backup.tar.gz -C /
```

## Requirements

### Build from Source

- **Rust:** 1.75 or later (install from https://rustup.rs/)
- **Git:** For cloning repository
- **Build tools:**
  - macOS: Xcode Command Line Tools (`xcode-select --install`)
  - Linux: gcc, pkg-config, libssl-dev

### Docker

- **Docker:** 20.10 or later
- **Docker Compose:** 2.0 or later (or docker-compose v1.29+)

## Verification

After installation, verify ACP is working:

```bash
# Check versions
acp --version
acp-server --version

# Check help
acp --help
acp-server --help
```

## Next Steps

1. **Start the server:**
   ```bash
   acp-server
   ```

2. **Initialize ACP** (in another terminal):
   ```bash
   acp init
   ```

3. **Create a token:**
   ```bash
   acp token create mytoken
   ```

4. **Configure your agent:**
   ```bash
   export HTTPS_PROXY=http://localhost:9443
   export ACP_TOKEN=<token-from-step-3>
   ```

See the [README](README.md) for full usage documentation.

## Troubleshooting

### "Permission denied" when installing

- Use `--prefix` to install to a user-writable location:
  ```bash
  ./install.sh --prefix ~/.local
  ```
- Or use sudo for system installation:
  ```bash
  sudo ./install.sh
  ```

### "command not found: acp"

The installation directory is not in your PATH. Add it:

```bash
# For /usr/local/bin
export PATH="/usr/local/bin:$PATH"

# For custom prefix
export PATH="$HOME/.local/bin:$PATH"
```

### Build fails with "linker error"

Install build dependencies:

**macOS:**
```bash
xcode-select --install
```

**Ubuntu/Debian:**
```bash
sudo apt-get install build-essential pkg-config libssl-dev
```

**Fedora/RHEL:**
```bash
sudo dnf install gcc pkg-config openssl-devel
```

### Docker container won't start

Check logs:
```bash
docker compose logs acp-server
```

Common issues:
- Port 9443 or 9080 already in use (change in docker-compose.yml)
- Insufficient memory (increase Docker memory limit)

### "No space left on device" during build

- Clean up Docker: `docker system prune -a`
- Clean up Cargo: `cargo clean`
- Check disk space: `df -h`

## Uninstallation

### Manual Install

```bash
# Remove binaries
sudo rm /usr/local/bin/acp
sudo rm /usr/local/bin/acp-server

# Remove data (careful!)
rm -rf ~/.config/acp
```

### Docker

```bash
# Stop and remove containers
docker compose down -v

# Remove images
docker rmi yourusername/acp:latest
```

## Getting Help

- **Issues:** https://github.com/yourusername/agent-credential-proxy/issues
- **Discussions:** https://github.com/yourusername/agent-credential-proxy/discussions
- **Security:** See SECURITY.md for reporting security issues
