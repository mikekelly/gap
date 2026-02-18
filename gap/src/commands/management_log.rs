//! Management audit log commands

use crate::auth::{hash_password, read_password};
use anyhow::Result;
use serde_json::json;

pub async fn run(
    server_url: &str,
    follow: bool,
    operation: Option<String>,
    resource_type: Option<String>,
    resource_id: Option<String>,
    limit: Option<u32>,
) -> Result<()> {
    let password = read_password("Password: ")?;
    let password_hash = hash_password(&password);
    let client = crate::create_api_client(server_url)?;

    if follow {
        anyhow::bail!("Management log streaming not yet implemented");
    } else {
        let mut query_params = json!({});
        if let Some(ref op) = operation {
            query_params["operation"] = json!(op);
        }
        if let Some(ref rt) = resource_type {
            query_params["resource_type"] = json!(rt);
        }
        if let Some(ref rid) = resource_id {
            query_params["resource_id"] = json!(rid);
        }
        if let Some(l) = limit {
            query_params["limit"] = json!(l);
        }

        let response: crate::client::ManagementLogResponse =
            client.post_auth("/management-log", &password_hash, query_params).await?;

        if response.entries.is_empty() {
            println!("No management log entries.");
        } else {
            println!("Management Log:");
            println!();
            for entry in response.entries {
                let resource = entry.resource_id.as_deref().unwrap_or("-");
                let status = if entry.success { "OK" } else { "FAIL" };
                let error = entry.error_message.as_deref().unwrap_or("");
                let error_suffix = if error.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", error)
                };
                println!(
                    "[{}] {} {}/{} [{}]{}",
                    entry.timestamp, entry.operation, entry.resource_type, resource, status, error_suffix
                );
            }
        }
    }
    Ok(())
}
