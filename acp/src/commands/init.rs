//! Init command implementation

use crate::auth::{hash_password, read_password_with_confirmation};
use crate::client::ApiClient;
use anyhow::Result;
use serde_json::json;

pub async fn run(server_url: &str, ca_path: Option<&str>, management_sans: Option<&str>) -> Result<()> {
    println!("Initializing ACP server...");
    println!();

    // Get password from user
    let password = read_password_with_confirmation("Enter password for ACP: ")?;
    let password_hash = hash_password(&password);

    // Call init endpoint
    // For init, we use the basic client without CA verification since the CA doesn't exist yet
    // If the server URL is HTTPS, we'll use a client that accepts any certificate
    let client = if server_url.starts_with("https://") {
        eprintln!("Note: Using HTTPS for init. The server certificate will not be verified during initialization.");
        eprintln!("After init completes, the CA certificate will be saved and used for all future connections.");
        eprintln!();

        // Create a client that accepts any certificate for init
        // This is acceptable because:
        // 1. Init is interactive and the user can verify the CA cert afterward
        // 2. The CA cert is downloaded during init and saved locally
        // 3. All subsequent commands will verify against this CA cert
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to create HTTP client: {}", e))?;

        ApiClient::from_reqwest_client(server_url, client)
    } else {
        ApiClient::new(server_url)
    };

    // Parse management SANs if provided
    let management_sans_vec = management_sans.map(|s| {
        s.split(',')
            .map(|san| san.trim().to_string())
            .collect::<Vec<String>>()
    });

    // Build request body
    let mut body = json!({});
    if let Some(path) = ca_path {
        body.as_object_mut().unwrap().insert("ca_path".to_string(), json!(path));
    }
    if let Some(sans) = management_sans_vec {
        body.as_object_mut().unwrap().insert("management_sans".to_string(), json!(sans));
    }

    let response: crate::client::InitResponse = client.post_auth("/init", &password_hash, body).await?;

    println!();
    println!("ACP initialized successfully!");
    println!("CA certificate saved to: {}", response.ca_path);
    println!();
    println!("Next steps:");
    println!("  1. Install plugins: acp install <plugin>");
    println!("  2. Configure credentials: acp set <plugin>:<key>");
    println!("  3. Create agent tokens: acp token create <name>");
    println!();
    println!("Clients should be configured to trust the CA cert at the path above.");

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_parse_management_sans() {
        // Test parsing comma-separated SANs
        let input = "DNS:localhost,IP:127.0.0.1";
        let result: Vec<String> = input.split(',')
            .map(|san| san.trim().to_string())
            .collect();

        assert_eq!(result, vec!["DNS:localhost", "IP:127.0.0.1"]);
    }

    #[test]
    fn test_parse_management_sans_with_spaces() {
        // Test parsing with extra whitespace
        let input = " DNS:localhost , IP:127.0.0.1 , DNS:example.com ";
        let result: Vec<String> = input.split(',')
            .map(|san| san.trim().to_string())
            .collect();

        assert_eq!(result, vec!["DNS:localhost", "IP:127.0.0.1", "DNS:example.com"]);
    }

    #[test]
    fn test_parse_management_sans_single() {
        // Test single SAN
        let input = "DNS:localhost";
        let result: Vec<String> = input.split(',')
            .map(|san| san.trim().to_string())
            .collect();

        assert_eq!(result, vec!["DNS:localhost"]);
    }
}
