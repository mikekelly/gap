//! ACP CLI - Agent Credential Proxy command-line interface
//!
//! This binary provides the CLI for managing the ACP server,
//! including initialization, plugin management, credential storage,
//! and agent token management.

use clap::{Parser, Subcommand};
use std::process;

mod auth;
mod client;
mod commands;

#[derive(Parser)]
#[command(name = "acp")]
#[command(author, version, about = "Agent Credential Proxy CLI", long_about = None)]
struct Cli {
    /// Server URL (default: http://localhost:9080, can be set via SERVER env var)
    #[arg(long, default_value = "http://localhost:9080")]
    server: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize ACP server with password and CA certificate
    Init {
        /// Path to export CA certificate (default: ~/.acp/ca.pem)
        #[arg(long)]
        ca_path: Option<String>,
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

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Init { ca_path } => commands::init::run(&cli.server, ca_path.as_deref()).await,
        Commands::Status => commands::status::run(&cli.server).await,
        Commands::Plugins => commands::plugins::list(&cli.server).await,
        Commands::Install { name } => commands::plugins::install(&cli.server, &name).await,
        Commands::Uninstall { name } => commands::plugins::uninstall(&cli.server, &name).await,
        Commands::Set { key } => commands::credentials::set(&cli.server, &key).await,
        Commands::Token(token_cmd) => match token_cmd {
            TokenCommands::List => commands::tokens::list(&cli.server).await,
            TokenCommands::Create { name } => commands::tokens::create(&cli.server, &name).await,
            TokenCommands::Revoke { id } => commands::tokens::revoke(&cli.server, &id).await,
        },
        Commands::Activity { follow } => commands::activity::run(&cli.server, follow).await,
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
        let _cli = Cli::parse_from(["acp", "init"]);
    }

    #[test]
    fn test_cli_init_with_ca_path() {
        let cli = Cli::parse_from(["acp", "init", "--ca-path", "/tmp/ca.pem"]);
        match cli.command {
            Commands::Init { ca_path } => {
                assert_eq!(ca_path.as_deref(), Some("/tmp/ca.pem"));
            }
            _ => panic!("Expected Init command"),
        }
    }

    #[test]
    fn test_cli_status_parses() {
        let _cli = Cli::parse_from(["acp", "status"]);
    }

    #[test]
    fn test_cli_plugins_parses() {
        let _cli = Cli::parse_from(["acp", "plugins"]);
    }

    #[test]
    fn test_cli_install_parses() {
        let cli = Cli::parse_from(["acp", "install", "exa"]);
        match cli.command {
            Commands::Install { name } => {
                assert_eq!(name, "exa");
            }
            _ => panic!("Expected Install command"),
        }
    }

    #[test]
    fn test_cli_uninstall_parses() {
        let cli = Cli::parse_from(["acp", "uninstall", "exa"]);
        match cli.command {
            Commands::Uninstall { name } => {
                assert_eq!(name, "exa");
            }
            _ => panic!("Expected Uninstall command"),
        }
    }

    #[test]
    fn test_cli_set_parses() {
        let cli = Cli::parse_from(["acp", "set", "exa:api_key"]);
        match cli.command {
            Commands::Set { key } => {
                assert_eq!(key, "exa:api_key");
            }
            _ => panic!("Expected Set command"),
        }
    }

    #[test]
    fn test_cli_token_list_parses() {
        let _cli = Cli::parse_from(["acp", "token", "list"]);
    }

    #[test]
    fn test_cli_token_create_parses() {
        let cli = Cli::parse_from(["acp", "token", "create", "test-token"]);
        match cli.command {
            Commands::Token(TokenCommands::Create { name }) => {
                assert_eq!(name, "test-token");
            }
            _ => panic!("Expected Token Create command"),
        }
    }

    #[test]
    fn test_cli_token_revoke_parses() {
        let cli = Cli::parse_from(["acp", "token", "revoke", "abc123"]);
        match cli.command {
            Commands::Token(TokenCommands::Revoke { id }) => {
                assert_eq!(id, "abc123");
            }
            _ => panic!("Expected Token Revoke command"),
        }
    }

    #[test]
    fn test_cli_activity_parses() {
        let _cli = Cli::parse_from(["acp", "activity"]);
    }

    #[test]
    fn test_cli_activity_follow_parses() {
        let cli = Cli::parse_from(["acp", "activity", "--follow"]);
        match cli.command {
            Commands::Activity { follow } => {
                assert!(follow);
            }
            _ => panic!("Expected Activity command"),
        }
    }

    #[test]
    fn test_cli_server_default() {
        let cli = Cli::parse_from(["acp", "status"]);
        assert_eq!(cli.server, "http://localhost:9080");
    }

    #[test]
    fn test_cli_server_override() {
        let cli = Cli::parse_from(["acp", "--server", "http://custom:8080", "status"]);
        assert_eq!(cli.server, "http://custom:8080");
    }
}
