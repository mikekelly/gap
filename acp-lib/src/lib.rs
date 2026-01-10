/// Agent Credential Proxy - Shared Library
///
/// This library contains core types, error handling, and shared logic
/// used by both the `acp` CLI and `acp-server` daemon.
pub mod error;
pub mod plugin_runtime;
pub mod proxy;
pub mod storage;
pub mod tls;
pub mod types;

pub use error::{AcpError, Result};
pub use plugin_runtime::PluginRuntime;
pub use proxy::ProxyServer;
pub use storage::{create_store, FileStore, SecretStore};
#[cfg(target_os = "macos")]
pub use storage::KeychainStore;
pub use tls::CertificateAuthority;
pub use types::{ACPCredentials, ACPPlugin, ACPRequest, AgentToken, Config};
