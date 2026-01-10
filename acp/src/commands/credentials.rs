//! Credential management commands

use crate::auth::{hash_password, read_password};
use crate::client::ApiClient;
use anyhow::{Context, Result};
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
    let credential_value = rpassword::prompt_password(format!("Value for {}:{}: ", plugin, credential_key))
        .context("Failed to read credential value")?;

    let client = ApiClient::new(server_url);

    let path = format!("/credentials/{}/{}", plugin, credential_key);
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
