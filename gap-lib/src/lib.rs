/// GAP - Shared Library
///
/// This library contains core types, error handling, and shared logic
/// used by both the `gap` CLI and `gap-server` daemon.
pub mod error;
pub mod http_utils;
#[cfg(target_os = "macos")]
mod keychain_impl;
pub mod paths;
pub mod plugin_matcher;
pub mod plugin_runtime;
pub mod database;
pub mod proxy;
pub mod proxy_transforms;
pub mod registry;
pub mod storage;
pub mod tls;
pub mod types;

pub use error::{GapError, Result};
// parse_http_request and serialize_http_request are now test-only utilities.
// They remain pub in http_utils for integration test access but are no longer
// re-exported from the crate root since no production code depends on them.
pub use paths::ca_cert_path;
pub use plugin_matcher::find_matching_plugin;
pub use plugin_runtime::PluginRuntime;
pub use proxy::ProxyServer;
pub use registry::{CredentialEntry, PluginEntry, Registry, RegistryData, TokenEntry};
pub use storage::{create_store, FileStore, SecretStore};
#[cfg(target_os = "macos")]
pub use storage::KeychainStore;
pub use tls::CertificateAuthority;
pub use types::{GAPCredentials, GAPPlugin, GAPRequest, AgentToken, Config, ActivityEntry};
