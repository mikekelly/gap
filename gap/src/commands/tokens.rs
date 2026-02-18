//! Token management commands

use crate::auth::{hash_password, read_password};
use anyhow::Result;
use serde_json::json;

pub async fn list(server_url: &str) -> Result<()> {
    let password = read_password("Password: ")?;
    let password_hash = hash_password(&password);

    let client = crate::create_api_client(server_url)?;
    let response: crate::client::TokensResponse =
        client.get_auth("/tokens", &password_hash, &[]).await?;

    if response.tokens.is_empty() {
        println!("No tokens found.");
    } else {
        println!("Agent Tokens:");
        println!();
        for token in response.tokens {
            println!("  ID: {}", token.id);
            println!("  Name: {}", token.name);
            println!("  Prefix: {}", token.prefix);
            println!("  Created: {}", token.created_at);
            println!();
        }
    }

    Ok(())
}

pub async fn create(server_url: &str, name: &str) -> Result<()> {
    let password = read_password("Password: ")?;
    let password_hash = hash_password(&password);

    let client = crate::create_api_client(server_url)?;

    let body = json!({
        "name": name
    });

    let response: crate::client::CreateTokenResponse =
        client.post_auth("/tokens/create", &password_hash, body).await?;

    println!("Token created successfully!");
    println!();
    println!("  ID: {}", response.id);
    println!("  Name: {}", response.name);
    println!("  Token: {}", response.token);
    println!();
    println!("WARNING: Save this token securely. It will not be shown again.");

    Ok(())
}

pub async fn revoke(server_url: &str, id: &str) -> Result<()> {
    let password = read_password("Password: ")?;
    let password_hash = hash_password(&password);

    let client = crate::create_api_client(server_url)?;

    let path = format!("/tokens/{}", id);
    let response: crate::client::RevokeTokenResponse =
        client.delete_auth(&path, &password_hash).await?;

    if response.revoked {
        println!("Token '{}' revoked successfully.", response.id);
    } else {
        println!("Failed to revoke token '{}'.", response.id);
    }

    Ok(())
}
