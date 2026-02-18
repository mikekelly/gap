/// GAP - Shared Library
///
/// This library contains core types, error handling, and shared logic
/// used by both the `gap` CLI and `gap-server` daemon.
pub mod error;
pub mod http_utils;
pub mod key_provider;
#[cfg(target_os = "macos")]
mod keychain_impl;
pub mod paths;
pub mod plugin_matcher;
pub mod plugin_runtime;
pub mod database;
pub mod proxy;
pub mod proxy_transforms;
pub mod tls;
pub mod types;

pub use error::{GapError, Result};
// parse_http_request and serialize_http_request are now test-only utilities.
// They remain pub in http_utils for integration test access but are no longer
// re-exported from the crate root since no production code depends on them.
pub use key_provider::{KeyProvider, EnvKeyProvider};
#[cfg(target_os = "macos")]
pub use key_provider::KeychainKeyProvider;
pub use paths::ca_cert_path;
pub use plugin_matcher::find_matching_plugin;
pub use plugin_runtime::PluginRuntime;
pub use proxy::ProxyServer;
pub use database::GapDatabase;
pub use tls::{CertificateAuthority, DynamicCertResolver};
pub use types::{
    GAPCredentials, GAPPlugin, GAPRequest, AgentToken, Config, ActivityEntry,
    ActivityFilter, CredentialEntry, PluginEntry, TokenEntry, TokenMetadata,
    ManagementLogEntry, ManagementLogFilter,
};
