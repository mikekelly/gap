//! Token management commands

use crate::auth::{hash_password, read_password};
use anyhow::Result;
use serde_json::json;

pub async fn list(server_url: &str, include_revoked: bool) -> Result<()> {
    let password = read_password("Password: ")?;
    let password_hash = hash_password(&password);

    let client = crate::create_api_client(server_url)?;

    let query_params = if include_revoked {
        vec![("include_revoked", "true")]
    } else {
        vec![]
    };

    let response: crate::client::TokensResponse =
        client.get_auth("/tokens", &password_hash, &query_params).await?;

    if response.tokens.is_empty() {
        println!("No tokens found.");
    } else {
        println!("Agent Tokens:");
        println!();
        for token in response.tokens {
            println!("  Prefix: {}", token.prefix);
            println!("  Created: {}", token.created_at);
            if let Some(ref permitted) = token.permitted {
                if permitted.is_empty() {
                    println!("  Scopes: (deny all)");
                } else {
                    println!("  Scopes: {}", serde_json::to_string(permitted).unwrap_or_default());
                }
            } else {
                println!("  Scopes: (unrestricted)");
            }
            if let Some(ref revoked_at) = token.revoked_at {
                println!("  Revoked: {}", revoked_at);
            }
            println!();
        }
    }

    Ok(())
}

pub async fn create(server_url: &str, scopes_json: Option<String>, scopes_file: Option<String>) -> Result<()> {
    let password = read_password("Password: ")?;
    let password_hash = hash_password(&password);

    let client = crate::create_api_client(server_url)?;

    // Build the request body from scopes
    let body = if let Some(file_path) = scopes_file {
        let content = std::fs::read_to_string(&file_path)
            .map_err(|e| anyhow::anyhow!("Failed to read scopes file '{}': {}", file_path, e))?;
        let permitted: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Invalid JSON in scopes file: {}", e))?;
        json!({ "permitted": permitted })
    } else if let Some(scopes_str) = scopes_json {
        let permitted: serde_json::Value = serde_json::from_str(&scopes_str)
            .map_err(|e| anyhow::anyhow!("Invalid JSON scopes: {}", e))?;
        json!({ "permitted": permitted })
    } else {
        // No scopes = unrestricted token
        json!({})
    };

    let response: crate::client::CreateTokenResponse =
        client.post_auth("/tokens", &password_hash, body).await?;

    println!("Token created successfully!");
    println!();
    println!("  Prefix: {}", response.prefix);
    println!("  Token:  {}", response.token);
    if let Some(ref permitted) = response.permitted {
        if !permitted.is_empty() {
            println!("  Scopes: {}", serde_json::to_string(permitted).unwrap_or_default());
        }
    }
    println!();
    println!("WARNING: Save this token securely. It will not be shown again.");

    Ok(())
}

pub async fn revoke(server_url: &str, prefix: &str) -> Result<()> {
    let password = read_password("Password: ")?;
    let password_hash = hash_password(&password);

    let client = crate::create_api_client(server_url)?;

    let path = format!("/tokens/{}", prefix);
    let response: crate::client::RevokeTokenResponse =
        client.delete_auth(&path, &password_hash).await?;

    if response.revoked {
        println!("Token '{}' revoked successfully.", response.prefix);
    } else {
        println!("Failed to revoke token '{}'.", response.prefix);
    }

    Ok(())
}
