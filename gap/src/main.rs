//! GAP CLI - Gated Agent Proxy command-line interface
//!
//! This binary provides the CLI for managing the GAP server,
//! including initialization, plugin management, credential storage,
//! and agent token management.

use clap::{Parser, Subcommand};
use std::process;

mod auth;
mod client;
mod commands;

#[derive(Parser)]
#[command(name = "gap")]
#[command(author, version, about = "GAP CLI", long_about = None)]
struct Cli {
    /// Server URL (default: https://localhost:9080, can be set via SERVER env var)
    #[arg(long, default_value = "https://localhost:9080")]
    server: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize GAP server with password and CA certificate
    Init {
        /// Path to export CA certificate (default: ~/.gap/ca.pem)
        #[arg(long)]
        ca_path: Option<String>,

        /// Management certificate Subject Alternative Names for HTTPS access
        ///
        /// Comma-separated list of SANs to include in the management API certificate.
        /// Each SAN should be prefixed with "DNS:" or "IP:".
        ///
        /// Examples:
        ///   --management-sans "DNS:localhost,IP:127.0.0.1"
        ///   --management-sans "DNS:acp.local,DNS:localhost,IP:192.168.1.100"
        #[arg(long, value_name = "SANS")]
        management_sans: Option<String>,
    },

    /// Show server status (version, uptime, ports)
    Status,

    /// List installed plugins
    Plugins,

    /// Install a plugin
    Install {
        /// Plugin name or URL
        name: String,
    },

    /// Uninstall a plugin
    Uninstall {
        /// Plugin name
        name: String,
    },

    /// Update a plugin to the latest version
    Update {
        /// Plugin name
        name: String,
    },

    /// Set a credential for a plugin
    Set {
        /// Credential key in format <plugin>:<key>
        key: String,
    },

    /// Manage agent tokens
    #[command(subcommand)]
    Token(TokenCommands),

    /// View activity logs
    Activity {
        /// Follow activity stream
        #[arg(long)]
        follow: bool,
    },

    /// Rotate management certificate with new SANs
    NewManagementCert {
        /// Comma-separated list of Subject Alternative Names
        ///
        /// Each SAN should be prefixed with "DNS:" or "IP:".
        ///
        /// Examples:
        ///   --sans "DNS:localhost,IP:127.0.0.1"
        ///   --sans "DNS:acp.local,DNS:localhost,IP:192.168.1.100"
        #[arg(long, value_name = "SANS")]
        sans: String,
    },
}

#[derive(Subcommand)]
enum TokenCommands {
    /// List all tokens
    List,

    /// Create a new token
    Create {
        /// Token name
        name: String,
    },

    /// Revoke a token
    Revoke {
        /// Token ID
        id: String,
    },
}

pub fn get_default_ca_path() -> std::path::PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .expect("Cannot determine home directory");
    std::path::PathBuf::from(home).join(".config").join("gap").join("ca.crt")
}

pub fn create_api_client(server_url: &str) -> anyhow::Result<client::ApiClient> {
    // If using HTTPS, try to load the CA cert
    if server_url.starts_with("https://") {
        let ca_path = get_default_ca_path();

        // For init command, the CA doesn't exist yet, so we'll handle that specially
        // in the init command itself. For all other commands, we require the CA cert.
        if ca_path.exists() {
            let ca_pem = std::fs::read(&ca_path)
                .map_err(|e| anyhow::anyhow!("Failed to read CA certificate from {}: {}", ca_path.display(), e))?;

            client::ApiClient::with_ca_cert(server_url, &ca_pem)
                .map_err(|e| anyhow::anyhow!("Failed to create HTTPS client: {}. Ensure the CA certificate at {} is valid.", e, ca_path.display()))
        } else {
            // CA cert doesn't exist - likely need to run `gap init` first
            Err(anyhow::anyhow!(
                "CA certificate not found at {}. Please run `gap init` first to initialize the server and download the CA certificate.",
                ca_path.display()
            ))
        }
    } else {
        // HTTP - use default client (for backwards compatibility during transition)
        Ok(client::ApiClient::new(server_url))
    }
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Init { ca_path, management_sans } => commands::init::run(&cli.server, ca_path.as_deref(), management_sans.as_deref()).await,
        Commands::Status => commands::status::run(&cli.server).await,
        Commands::Plugins => commands::plugins::list(&cli.server).await,
        Commands::Install { name } => commands::plugins::install(&cli.server, &name).await,
        Commands::Uninstall { name } => commands::plugins::uninstall(&cli.server, &name).await,
        Commands::Update { name } => commands::plugins::update(&cli.server, &name).await,
        Commands::Set { key } => commands::credentials::set(&cli.server, &key).await,
        Commands::Token(token_cmd) => match token_cmd {
            TokenCommands::List => commands::tokens::list(&cli.server).await,
            TokenCommands::Create { name } => commands::tokens::create(&cli.server, &name).await,
            TokenCommands::Revoke { id } => commands::tokens::revoke(&cli.server, &id).await,
        },
        Commands::Activity { follow } => commands::activity::run(&cli.server, follow).await,
        Commands::NewManagementCert { sans } => commands::new_management_cert::run(&cli.server, &sans).await,
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_init_parses() {
        let _cli = Cli::parse_from(["gap", "init"]);
    }

    #[test]
    fn test_cli_init_with_ca_path() {
        let cli = Cli::parse_from(["gap", "init", "--ca-path", "/tmp/ca.pem"]);
        match cli.command {
            Commands::Init { ca_path, management_sans: _ } => {
                assert_eq!(ca_path.as_deref(), Some("/tmp/ca.pem"));
            }
            _ => panic!("Expected Init command"),
        }
    }

    #[test]
    fn test_cli_status_parses() {
        let _cli = Cli::parse_from(["gap", "status"]);
    }

    #[test]
    fn test_cli_plugins_parses() {
        let _cli = Cli::parse_from(["gap", "plugins"]);
    }

    #[test]
    fn test_cli_install_parses() {
        let cli = Cli::parse_from(["gap", "install", "exa"]);
        match cli.command {
            Commands::Install { name } => {
                assert_eq!(name, "exa");
            }
            _ => panic!("Expected Install command"),
        }
    }

    #[test]
    fn test_cli_uninstall_parses() {
        let cli = Cli::parse_from(["gap", "uninstall", "exa"]);
        match cli.command {
            Commands::Uninstall { name } => {
                assert_eq!(name, "exa");
            }
            _ => panic!("Expected Uninstall command"),
        }
    }

    #[test]
    fn test_cli_set_parses() {
        let cli = Cli::parse_from(["gap", "set", "exa:api_key"]);
        match cli.command {
            Commands::Set { key } => {
                assert_eq!(key, "exa:api_key");
            }
            _ => panic!("Expected Set command"),
        }
    }

    #[test]
    fn test_cli_token_list_parses() {
        let _cli = Cli::parse_from(["gap", "token", "list"]);
    }

    #[test]
    fn test_cli_token_create_parses() {
        let cli = Cli::parse_from(["gap", "token", "create", "test-token"]);
        match cli.command {
            Commands::Token(TokenCommands::Create { name }) => {
                assert_eq!(name, "test-token");
            }
            _ => panic!("Expected Token Create command"),
        }
    }

    #[test]
    fn test_cli_token_revoke_parses() {
        let cli = Cli::parse_from(["gap", "token", "revoke", "abc123"]);
        match cli.command {
            Commands::Token(TokenCommands::Revoke { id }) => {
                assert_eq!(id, "abc123");
            }
            _ => panic!("Expected Token Revoke command"),
        }
    }

    #[test]
    fn test_cli_activity_parses() {
        let _cli = Cli::parse_from(["gap", "activity"]);
    }

    #[test]
    fn test_cli_activity_follow_parses() {
        let cli = Cli::parse_from(["gap", "activity", "--follow"]);
        match cli.command {
            Commands::Activity { follow } => {
                assert!(follow);
            }
            _ => panic!("Expected Activity command"),
        }
    }

    #[test]
    fn test_cli_server_default() {
        let cli = Cli::parse_from(["gap", "status"]);
        assert_eq!(cli.server, "https://localhost:9080");
    }

    #[test]
    fn test_cli_server_override() {
        let cli = Cli::parse_from(["gap", "--server", "http://custom:8080", "status"]);
        assert_eq!(cli.server, "http://custom:8080");
    }

    #[test]
    fn test_cli_init_with_management_sans() {
        let cli = Cli::parse_from([
            "gap",
            "init",
            "--management-sans",
            "DNS:localhost,IP:127.0.0.1",
        ]);
        match cli.command {
            Commands::Init {
                ca_path: _,
                management_sans,
            } => {
                assert_eq!(
                    management_sans.as_deref(),
                    Some("DNS:localhost,IP:127.0.0.1")
                );
            }
            _ => panic!("Expected Init command"),
        }
    }

    #[test]
    fn test_cli_new_management_cert_parses() {
        let cli = Cli::parse_from([
            "gap",
            "new-management-cert",
            "--sans",
            "DNS:localhost,IP:127.0.0.1",
        ]);
        match cli.command {
            Commands::NewManagementCert { sans } => {
                assert_eq!(sans, "DNS:localhost,IP:127.0.0.1");
            }
            _ => panic!("Expected NewManagementCert command"),
        }
    }

    #[test]
    fn test_cli_new_management_cert_multiple_sans() {
        let cli = Cli::parse_from([
            "gap",
            "new-management-cert",
            "--sans",
            "DNS:localhost,DNS:example.com,IP:127.0.0.1,IP:192.168.1.1",
        ]);
        match cli.command {
            Commands::NewManagementCert { sans } => {
                assert_eq!(sans, "DNS:localhost,DNS:example.com,IP:127.0.0.1,IP:192.168.1.1");
            }
            _ => panic!("Expected NewManagementCert command"),
        }
    }
}
