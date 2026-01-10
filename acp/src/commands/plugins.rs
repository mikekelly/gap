//! Plugin management commands

use crate::auth::{hash_password, read_password};
use crate::client::ApiClient;
use anyhow::Result;
use serde_json::json;

pub async fn list(server_url: &str) -> Result<()> {
    let password = read_password("Password: ")?;
    let password_hash = hash_password(&password);

    let client = ApiClient::new(server_url);
    let response: crate::client::PluginsResponse =
        client.post_auth("/plugins", &password_hash, json!({})).await?;

    if response.plugins.is_empty() {
        println!("No plugins installed.");
    } else {
        println!("Installed Plugins:");
        println!();
        for plugin in response.plugins {
            println!("  {}", plugin.name);
            println!("    Matches: {}", plugin.match_patterns.join(", "));
            println!("    Credentials: {}", plugin.credential_schema.join(", "));
            println!();
        }
    }

    Ok(())
}

pub async fn install(server_url: &str, name: &str) -> Result<()> {
    let password = read_password("Password: ")?;
    let password_hash = hash_password(&password);

    let client = ApiClient::new(server_url);

    let body = json!({
        "name": name
    });

    let response: crate::client::InstallResponse =
        client.post_auth("/plugins/install", &password_hash, body).await?;

    if response.installed {
        println!("Plugin '{}' installed successfully.", response.name);
    } else {
        println!("Failed to install plugin '{}'.", response.name);
    }

    Ok(())
}

pub async fn uninstall(server_url: &str, name: &str) -> Result<()> {
    let password = read_password("Password: ")?;
    let password_hash = hash_password(&password);

    let client = ApiClient::new(server_url);

    let path = format!("/plugins/{}", name);
    let response: crate::client::UninstallResponse =
        client.delete_auth(&path, &password_hash).await?;

    if response.uninstalled {
        println!("Plugin '{}' uninstalled successfully.", response.name);
    } else {
        println!("Failed to uninstall plugin '{}'.", response.name);
    }

    Ok(())
}
