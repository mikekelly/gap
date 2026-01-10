//! Init command implementation

use crate::auth::{hash_password, read_password_with_confirmation};
use crate::client::ApiClient;
use anyhow::Result;
use serde_json::json;

pub async fn run(server_url: &str, ca_path: Option<&str>) -> Result<()> {
    println!("Initializing ACP server...");
    println!();

    // Get password from user
    let password = read_password_with_confirmation("Enter password for ACP: ")?;
    let password_hash = hash_password(&password);

    // Call init endpoint
    let client = ApiClient::new(server_url);

    let body = if let Some(path) = ca_path {
        json!({
            "ca_path": path
        })
    } else {
        json!({})
    };

    let response: crate::client::InitResponse = client.post_auth("/init", &password_hash, body).await?;

    println!();
    println!("ACP initialized successfully!");
    println!("CA certificate saved to: {}", response.ca_path);
    println!();
    println!("Next steps:");
    println!("  1. Trust the CA certificate in your system");
    println!("  2. Install plugins: acp install <plugin>");
    println!("  3. Configure credentials: acp set <plugin>:<key>");
    println!("  4. Create agent tokens: acp token create <name>");

    Ok(())
}
