//! Status command implementation

use crate::client::ApiClient;
use anyhow::Result;

pub async fn run(server_url: &str) -> Result<()> {
    let client = ApiClient::new(server_url);
    let status: crate::client::StatusResponse = client.get("/status").await?;

    println!("ACP Server Status");
    println!("  Version: {}", status.version);
    println!("  Uptime: {} seconds", status.uptime_seconds);
    println!("  Proxy Port: {}", status.proxy_port);
    println!("  API Port: {}", status.api_port);

    Ok(())
}
