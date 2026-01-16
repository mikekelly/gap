# Core Types Reference

This document provides a comprehensive reference for the core types in GAP (`gap-lib` crate).

## HTTP & Request Types

### GAPRequest
HTTP request with method, url, headers, body.

Used throughout the proxy pipeline to represent incoming HTTP requests that need credential injection.

### GAPCredentials
String key-value map for plugin credentials.

Represents the credentials that plugins need to transform requests (e.g., `{"api_key": "sk-xxx", "secret": "yyy"}`).

## Plugin System

### GAPPlugin
Plugin definition with host matching.

Supports wildcards like `*.s3.amazonaws.com` for matching multiple hosts. See [Patterns](../AGENT_ORIENTATION.md#patterns) for wildcard matching rules.

### PluginRuntime
Sandboxed Boa JS runtime with GAP.crypto, GAP.util, GAP.log, TextEncoder/TextDecoder, URL/URLSearchParams.

Provides a secure JavaScript execution environment for running plugin transform functions. Each runtime instance can load and execute plugins while maintaining isolation from the host system.

**Important:** PluginRuntime is not `Send` due to internal `Rc` types. See [Gotchas](../AGENT_ORIENTATION.md#gotchas) for handling in async contexts.

## Authentication & Authorization

### AgentToken
Bearer token for agent authentication.

The `token` field is public for direct access (e.g., `agent_token.token`). See [Gotchas](../AGENT_ORIENTATION.md#gotchas) for serialization behavior.

## Configuration

### Config
Runtime configuration for the GAP server and CLI.

## Storage

### SecretStore
Async trait for secure storage.

Provides a platform-agnostic interface for storing credentials, tokens, and plugin data securely.

**Implementations:**
- `FileStore` - File-based storage with 0600 permissions (Linux: runs under dedicated service user for isolation)
- `KeychainStore` - macOS Keychain integration (conditional compilation)

**Factory function:** `create_store()` returns the platform-appropriate storage implementation.

### FileStore
File-based storage with 0600 permissions.

On Linux, runs under dedicated service user for isolation. Uses base64url encoding for filenames to safely handle special characters like colons and slashes.

### KeychainStore
macOS Keychain integration (conditional compilation).

**Limitation:** The `list()` method returns an empty vector due to security-framework API limitations. FileStore provides full `list()` functionality.

## Registry System

### Registry
Centralized metadata storage for tokens, plugins, and credentials.

Stored at key `"_registry"` in the SecretStore. Solves listing issues on platforms like macOS Keychain where enumeration is not supported. The registry tracks what exists (metadata) while actual values remain at individual keys.

### RegistryData
JSON structure containing TokenEntry, PluginEntry, and CredentialEntry lists.

`Registry.load()` returns empty RegistryData if not found (not an error).

### Registry Metadata Types
- `TokenEntry` - Token metadata (name, creation time, prefix)
- `PluginEntry` - Plugin metadata (name, patterns, credential schema)
- `CredentialEntry` - Credential metadata (plugin name, field names)

## TLS Infrastructure

### CertificateAuthority
TLS CA for dynamic certificate generation.

Generates self-signed CA certificates valid for 10 years. Used by the proxy server to create host-specific certificates on-demand for MITM TLS interception.

**Key methods:**
- `CertificateAuthority::generate()` - Creates self-signed CA
- `ca.sign_for_hostname(hostname, validity_opt)` - Generates signed certificates (default 24h validity)

**Output format:** Returns `(Vec<u8>, Vec<u8>)` for certificate and private key in DER format (not PEM).

**Certificate caching:** In-memory cache with expiry based on validity period.

## Proxy Server

### ProxyServer
MITM HTTPS proxy with agent authentication and bidirectional streaming.

Implements HTTP CONNECT tunnel with dual TLS (agent-side and upstream). Authenticates agents via `Proxy-Authorization` header (returns 407 if invalid).

**Transform pipeline:**
1. Parse HTTP request
2. Match host against plugin patterns
3. Load credentials from storage
4. Execute plugin transform
5. Serialize and forward to upstream

**Storage pattern:** Shares `Arc<dyn SecretStore>` with Management API to ensure consistent credential access.

## Error Handling

### GapError
Unified error type with context helpers.

Includes Network and Protocol variants for handling connection and HTTP-related errors.

**Best practice:** Use `GapError::storage("msg")` rather than `GapError::Storage("msg".to_string())` for better ergonomics.

## Related Documentation

- [Patterns](../AGENT_ORIENTATION.md#patterns) - Wildcard matching, builder pattern, error context
- [TLS Infrastructure](../AGENT_ORIENTATION.md#tls-infrastructure-rcgen-013) - Detailed TLS implementation notes
- [Proxy Infrastructure](../AGENT_ORIENTATION.md#proxy-infrastructure-phase-4) - Proxy server implementation details
- [Gotchas](../AGENT_ORIENTATION.md#gotchas) - Important implementation caveats
