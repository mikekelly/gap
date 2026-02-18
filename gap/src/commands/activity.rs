//! Activity log commands

use crate::auth::{hash_password, read_password};
use anyhow::Result;

pub async fn run(server_url: &str, follow: bool) -> Result<()> {
    let password = read_password("Password: ")?;
    let password_hash = hash_password(&password);

    let client = crate::create_api_client(server_url)?;

    if follow {
        // TODO: Implement SSE streaming for --follow
        anyhow::bail!("Activity streaming not yet implemented");
    } else {
        let response: crate::client::ActivityResponse =
            client.get_auth("/activity", &password_hash, &[]).await?;

        if response.entries.is_empty() {
            println!("No activity recorded.");
        } else {
            println!("Recent Activity:");
            println!();
            for entry in response.entries {
                let agent = entry.agent_id.as_deref().unwrap_or("-");
                println!(
                    "[{}] {} {} {} -> {}",
                    entry.timestamp, agent, entry.method, entry.url, entry.status
                );
            }
        }
    }

    Ok(())
}
