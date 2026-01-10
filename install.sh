#!/usr/bin/env bash
# Agent Credential Proxy (ACP) Installation Script
# Supports macOS and Linux
# Usage: curl -fsSL https://example.com/install.sh | bash
#        or: ./install.sh [--prefix /custom/path] [--build-from-source]

set -e

# Configuration
VERSION="${ACP_VERSION:-latest}"
PREFIX="${PREFIX:-/usr/local}"
INSTALL_DIR="${PREFIX}/bin"
BUILD_FROM_SOURCE="${BUILD_FROM_SOURCE:-false}"
GITHUB_REPO="${GITHUB_REPO:-yourusername/agent-credential-proxy}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Detect OS and architecture
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$OS" in
        darwin)
            OS="macos"
            ;;
        linux)
            OS="linux"
            ;;
        *)
            log_error "Unsupported operating system: $OS"
            ;;
    esac

    case "$ARCH" in
        x86_64|amd64)
            ARCH="x86_64"
            ;;
        aarch64|arm64)
            ARCH="aarch64"
            ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            ;;
    esac

    PLATFORM="${OS}-${ARCH}"
    log_info "Detected platform: $PLATFORM"
}

# Check if required commands are available
check_requirements() {
    if [ "$BUILD_FROM_SOURCE" = "true" ]; then
        if ! command -v cargo &> /dev/null; then
            log_error "Rust/Cargo is required for building from source. Install from https://rustup.rs/"
        fi
        log_info "Rust/Cargo found: $(cargo --version)"
    else
        if ! command -v curl &> /dev/null; then
            log_error "curl is required for downloading binaries"
        fi
    fi
}

# Build from source
build_from_source() {
    log_info "Building ACP from source..."

    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"

    log_info "Cloning repository..."
    git clone "https://github.com/${GITHUB_REPO}.git" acp
    cd acp

    if [ "$VERSION" != "latest" ]; then
        log_info "Checking out version $VERSION..."
        git checkout "$VERSION"
    fi

    log_info "Building release binaries..."
    cargo build --release

    log_info "Installing binaries to $INSTALL_DIR..."
    mkdir -p "$INSTALL_DIR"
    cp target/release/acp "$INSTALL_DIR/acp"
    cp target/release/acp-server "$INSTALL_DIR/acp-server"

    cd /
    rm -rf "$TEMP_DIR"

    log_info "Build complete!"
}

# Download pre-built binary
download_binary() {
    log_info "Downloading pre-built binaries for $PLATFORM..."

    if [ "$VERSION" = "latest" ]; then
        DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/acp-${PLATFORM}.tar.gz"
    else
        DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/acp-${PLATFORM}.tar.gz"
    fi

    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"

    log_info "Downloading from $DOWNLOAD_URL..."
    if ! curl -fsSL "$DOWNLOAD_URL" -o acp.tar.gz; then
        log_error "Failed to download binary. Try --build-from-source instead."
    fi

    log_info "Extracting archive..."
    tar -xzf acp.tar.gz

    log_info "Installing binaries to $INSTALL_DIR..."
    mkdir -p "$INSTALL_DIR"
    cp acp "$INSTALL_DIR/acp"
    cp acp-server "$INSTALL_DIR/acp-server"

    cd /
    rm -rf "$TEMP_DIR"

    log_info "Download complete!"
}

# Set executable permissions
set_permissions() {
    chmod +x "$INSTALL_DIR/acp"
    chmod +x "$INSTALL_DIR/acp-server"
    log_info "Set executable permissions"
}

# Verify installation
verify_installation() {
    if [ ! -x "$INSTALL_DIR/acp" ]; then
        log_error "Installation verification failed: acp binary not found or not executable"
    fi

    if [ ! -x "$INSTALL_DIR/acp-server" ]; then
        log_error "Installation verification failed: acp-server binary not found or not executable"
    fi

    log_info "Verifying acp binary..."
    "$INSTALL_DIR/acp" --version || log_error "acp binary verification failed"

    log_info "Verifying acp-server binary..."
    "$INSTALL_DIR/acp-server" --version || log_error "acp-server binary verification failed"
}

# Print post-installation instructions
print_instructions() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}ACP installed successfully!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "Binaries installed to:"
    echo "  - $INSTALL_DIR/acp"
    echo "  - $INSTALL_DIR/acp-server"
    echo ""

    # Check if install dir is in PATH
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        log_warn "$INSTALL_DIR is not in your PATH"
        echo "Add to PATH by adding this to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
        echo ""
        echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
        echo ""
    fi

    echo "Next steps:"
    echo "  1. Start the server: acp-server"
    echo "  2. Initialize ACP: acp init"
    echo "  3. Create a token: acp token create mytoken"
    echo "  4. Install a plugin: acp plugin install <plugin-url>"
    echo ""
    echo "For more information, visit: https://github.com/${GITHUB_REPO}"
    echo ""
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --prefix)
                PREFIX="$2"
                INSTALL_DIR="${PREFIX}/bin"
                shift 2
                ;;
            --build-from-source)
                BUILD_FROM_SOURCE=true
                shift
                ;;
            --version)
                VERSION="$2"
                shift 2
                ;;
            --help)
                echo "ACP Installation Script"
                echo ""
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --prefix PATH           Installation prefix (default: /usr/local)"
                echo "  --build-from-source     Build from source instead of downloading binary"
                echo "  --version VERSION       Install specific version (default: latest)"
                echo "  --help                  Show this help message"
                echo ""
                echo "Environment variables:"
                echo "  ACP_VERSION            Version to install (default: latest)"
                echo "  PREFIX                 Installation prefix (default: /usr/local)"
                echo "  GITHUB_REPO            GitHub repository (default: yourusername/agent-credential-proxy)"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1 (use --help for usage)"
                ;;
        esac
    done
}

# Main installation flow
main() {
    log_info "Starting ACP installation..."

    parse_args "$@"
    detect_platform
    check_requirements

    # Check for sudo if installing to system directory
    if [[ "$INSTALL_DIR" == /usr/* ]] && [ "$EUID" -ne 0 ]; then
        log_warn "Installing to system directory may require sudo"
        log_info "You may need to run: sudo $0 $@"
    fi

    if [ "$BUILD_FROM_SOURCE" = "true" ]; then
        build_from_source
    else
        # Try to download binary, fall back to source build if it fails
        if ! download_binary 2>/dev/null; then
            log_warn "Binary download failed, falling back to source build..."
            BUILD_FROM_SOURCE=true
            check_requirements
            build_from_source
        fi
    fi

    set_permissions
    verify_installation
    print_instructions

    log_info "Installation complete!"
}

# Run main function
main "$@"
