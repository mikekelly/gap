//! Activity log commands

use crate::auth::{hash_password, read_password};
use crate::client::ApiClient;
use anyhow::Result;
use serde_json::json;

pub async fn run(server_url: &str, follow: bool) -> Result<()> {
    let password = read_password("Password: ")?;
    let password_hash = hash_password(&password);

    let client = ApiClient::new(server_url);

    if follow {
        // TODO: Implement SSE streaming for --follow
        anyhow::bail!("Activity streaming not yet implemented");
    } else {
        let response: crate::client::ActivityResponse =
            client.post_auth("/activity", &password_hash, json!({})).await?;

        if response.entries.is_empty() {
            println!("No activity recorded.");
        } else {
            println!("Recent Activity:");
            println!();
            for entry in response.entries {
                println!(
                    "[{}] {} {} {} -> {}",
                    entry.timestamp, entry.agent, entry.method, entry.url, entry.status
                );
            }
        }
    }

    Ok(())
}
