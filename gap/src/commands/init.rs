//! Init command implementation

use crate::auth::{hash_password, read_password_with_confirmation};
use crate::client::ApiClient;
use anyhow::Result;
use serde_json::json;

pub async fn run(server_url: &str, ca_path: Option<&str>, management_sans: Option<&str>) -> Result<()> {
    println!("Initializing GAP server...");
    println!();

    // Get password from user
    let password = read_password_with_confirmation("Enter password for GAP: ")?;
    let password_hash = hash_password(&password);

    // Call init endpoint
    // Load CA cert from well-known filesystem location (written by gap-server at boot)
    let client = if server_url.starts_with("https://") {
        let ca_cert_path = gap_lib::ca_cert_path();
        let ca_cert = std::fs::read(&ca_cert_path)
            .map_err(|e| anyhow::anyhow!(
                "Cannot read CA cert at {}. Is gap-server running?\nError: {}",
                ca_cert_path.display(), e
            ))?;

        ApiClient::with_ca_cert(server_url, &ca_cert)?
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
    println!("GAP initialized successfully!");
    println!("CA certificate saved to: {}", response.ca_path);
    println!();
    println!("Next steps:");
    println!("  1. Install plugins: gap install <plugin>");
    println!("  2. Configure credentials: gap set <plugin>:<key>");
    println!("  3. Create agent tokens: gap token create <name>");
    println!();
    println!("Clients should be configured to trust the CA cert at the path above.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_api_client_with_ca_cert() {
        // This test verifies that we can create an ApiClient with a CA cert from bytes
        // which is what the init command will do when reading from the filesystem

        // Generate a test CA certificate
        let ca = gap_lib::tls::CertificateAuthority::generate().unwrap();
        let ca_pem = ca.ca_cert_pem();

        // Verify we can create an ApiClient with this CA cert
        let result = ApiClient::with_ca_cert("https://localhost:9080", ca_pem.as_bytes());
        assert!(result.is_ok(), "Should be able to create ApiClient with CA cert from bytes");
    }
}
