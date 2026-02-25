//! Plugin management commands

use crate::auth::{hash_password, read_password};
use anyhow::Result;
use serde_json::json;

pub async fn list(server_url: &str) -> Result<()> {
    let password = read_password("Password: ")?;
    let password_hash = hash_password(&password);

    let client = crate::create_api_client(server_url)?;
    let response: crate::client::PluginsResponse =
        client.post_auth("/plugins", &password_hash, json!({})).await?;

    if response.plugins.is_empty() {
        println!("No plugins installed.");
    } else {
        println!("Installed Plugins:");
        println!();
        for plugin in response.plugins {
            println!("  {}", plugin.id);
            println!("    Matches: {}", plugin.match_patterns.join(", "));
            println!("    Credentials: {}", plugin.credential_schema.join(", "));
            println!();
        }
    }

    Ok(())
}

pub async fn install(server_url: &str, source: &str) -> Result<()> {
    let password = read_password("Password: ")?;
    let password_hash = hash_password(&password);

    let client = crate::create_api_client(server_url)?;

    let body = json!({
        "source": source
    });

    let response: crate::client::InstallResponse =
        client.post_auth("/plugins/install", &password_hash, body).await?;

    if response.installed {
        if let Some(sha) = response.commit_sha {
            println!("Plugin '{}' ({}) installed successfully. (commit: {})", response.id, response.source, sha);
        } else {
            println!("Plugin '{}' ({}) installed successfully.", response.id, response.source);
        }
    } else {
        println!("Failed to install plugin '{}'.", response.id);
    }

    Ok(())
}

pub async fn uninstall(server_url: &str, id: &str) -> Result<()> {
    let password = read_password("Password: ")?;
    let password_hash = hash_password(&password);

    let client = crate::create_api_client(server_url)?;

    // UUIDs don't contain slashes, no URL encoding needed
    let path = format!("/plugins/{}", id);
    let response: crate::client::UninstallResponse =
        client.delete_auth(&path, &password_hash).await?;

    if response.uninstalled {
        println!("Plugin '{}' uninstalled successfully.", response.id);
    } else {
        println!("Failed to uninstall plugin '{}'.", response.id);
    }

    Ok(())
}

pub async fn update(server_url: &str, id: &str) -> Result<()> {
    let password = read_password("Password: ")?;
    let password_hash = hash_password(&password);

    let client = crate::create_api_client(server_url)?;

    // UUIDs don't contain slashes, no URL encoding needed
    let path = format!("/plugins/{}/update", id);
    let response: crate::client::UpdateResponse =
        client.post_auth(&path, &password_hash, json!({})).await?;

    if response.updated {
        if let Some(sha) = response.commit_sha {
            println!("Plugin '{}' updated successfully. (commit: {})", response.id, sha);
        } else {
            println!("Plugin '{}' updated successfully.", response.id);
        }
    } else {
        println!("Failed to update plugin '{}'.", response.id);
    }

    Ok(())
}
