//! Credential management commands

use crate::auth::{hash_password, read_password, read_secret};
use crate::client::ApiClient;
use anyhow::Result;
use serde_json::json;

pub async fn set(server_url: &str, key: &str) -> Result<()> {
    // Parse key as plugin:credential_key
    let parts: Vec<&str> = key.split(':').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid key format. Expected <plugin>:<key>, got '{}'", key);
    }

    let plugin = parts[0];
    let credential_key = parts[1];

    // Get password for authentication
    let password = read_password("Password: ")?;
    let password_hash = hash_password(&password);

    // Get credential value (hidden input)
    let credential_value = read_secret(&format!("Value for {}:{}: ", plugin, credential_key))?;

    let client = ApiClient::new(server_url);

    // URL-encode plugin name since it may contain slashes (e.g., "mikekelly/exa-acp")
    let encoded_plugin = urlencoding::encode(plugin);
    let path = format!("/credentials/{}/{}", encoded_plugin, credential_key);
    let body = json!({
        "value": credential_value
    });

    let response: crate::client::SetCredentialResponse =
        client.post_auth(&path, &password_hash, body).await?;

    if response.set {
        println!("Credential '{}:{}' set successfully.", response.plugin, response.key);
    } else {
        println!("Failed to set credential '{}:{}'.", response.plugin, response.key);
    }

    Ok(())
}
