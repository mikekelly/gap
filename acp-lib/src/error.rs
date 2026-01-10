//! Error types for the Agent Credential Proxy
//!
//! Provides a unified error type that covers all failure modes across
//! the proxy, storage, plugin runtime, and management API.

use thiserror::Error;

/// Result type alias using AcpError
pub type Result<T> = std::result::Result<T, AcpError>;

/// Comprehensive error type for all ACP operations
#[derive(Error, Debug)]
pub enum AcpError {
    /// IO errors (file operations, network)
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization/deserialization errors
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Storage backend errors
    #[error("Storage error: {0}")]
    Storage(String),

    /// TLS/Certificate errors
    #[error("TLS error: {0}")]
    Tls(String),

    /// Proxy operation errors
    #[error("Proxy error: {0}")]
    Proxy(String),

    /// Network errors (connection, timeout)
    #[error("Network error: {0}")]
    Network(String),

    /// Protocol errors (HTTP, TLS handshake)
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Plugin errors (loading, execution, sandbox violations)
    #[error("Plugin error: {0}")]
    Plugin(String),

    /// Authentication/authorization errors
    #[error("Authentication error: {0}")]
    Auth(String),

    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(String),

    /// Not found errors (plugin, credential, token)
    #[error("Not found: {0}")]
    NotFound(String),

    /// Invalid input/request
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Generic errors with context
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

impl AcpError {
    /// Create a storage error with context
    pub fn storage(msg: impl Into<String>) -> Self {
        Self::Storage(msg.into())
    }

    /// Create a TLS error with context
    pub fn tls(msg: impl Into<String>) -> Self {
        Self::Tls(msg.into())
    }

    /// Create a proxy error with context
    pub fn proxy(msg: impl Into<String>) -> Self {
        Self::Proxy(msg.into())
    }

    /// Create a network error with context
    pub fn network(msg: impl Into<String>) -> Self {
        Self::Network(msg.into())
    }

    /// Create a protocol error with context
    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::Protocol(msg.into())
    }

    /// Create a plugin error with context
    pub fn plugin(msg: impl Into<String>) -> Self {
        Self::Plugin(msg.into())
    }

    /// Create an auth error with context
    pub fn auth(msg: impl Into<String>) -> Self {
        Self::Auth(msg.into())
    }

    /// Create a config error with context
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    /// Create a not found error with context
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }

    /// Create an invalid input error with context
    pub fn invalid_input(msg: impl Into<String>) -> Self {
        Self::InvalidInput(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = AcpError::storage("keychain unavailable");
        assert_eq!(err.to_string(), "Storage error: keychain unavailable");

        let err = AcpError::plugin("timeout");
        assert_eq!(err.to_string(), "Plugin error: timeout");

        let err = AcpError::auth("invalid token");
        assert_eq!(err.to_string(), "Authentication error: invalid token");
    }

    #[test]
    fn test_error_conversion_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let acp_err: AcpError = io_err.into();
        assert!(matches!(acp_err, AcpError::Io(_)));
    }

    #[test]
    fn test_result_type_usage() {
        fn returns_result() -> Result<String> {
            Ok("success".to_string())
        }

        assert!(returns_result().is_ok());
    }
}
