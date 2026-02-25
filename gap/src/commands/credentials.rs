//! Credential management commands

use crate::auth::{hash_password, read_password, read_secret};
use anyhow::Result;
use serde_json::json;

pub async fn set(server_url: &str, key: &str) -> Result<()> {
    // Parse key as plugin_id:credential_key
    let parts: Vec<&str> = key.split(':').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid key format. Expected <plugin_id>:<key>, got '{}'", key);
    }

    let plugin_id = parts[0];
    let credential_key = parts[1];

    // Get password for authentication
    let password = read_password("Password: ")?;
    let password_hash = hash_password(&password);

    // Get credential value (hidden input)
    let credential_value = read_secret(&format!("Value for {}:{}: ", plugin_id, credential_key))?;

    let client = crate::create_api_client(server_url)?;

    // UUIDs don't contain slashes, no URL encoding needed
    let path = format!("/credentials/{}/{}", plugin_id, credential_key);
    let body = json!({
        "value": credential_value
    });

    let response: crate::client::SetCredentialResponse =
        client.post_auth(&path, &password_hash, body).await?;

    if response.set {
        println!("Credential '{}:{}' set successfully.", response.plugin_id, response.key);
    } else {
        println!("Failed to set credential '{}:{}'.", response.plugin_id, response.key);
    }

    Ok(())
}
