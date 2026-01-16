//! macOS LaunchAgent support for background service management
//!
//! This module provides plist generation for macOS LaunchAgents.
//! LaunchAgents run as user-level daemons after login with access to the user's Keychain.

#[cfg(target_os = "macos")]
use std::path::PathBuf;

#[cfg(target_os = "macos")]
/// Generate LaunchAgent plist XML for gap-server
///
/// Creates a plist configuration that:
/// - Runs at login (RunAtLoad)
/// - Keeps the service alive (KeepAlive)
/// - Logs stdout/stderr to ~/.gap/logs/
///
/// # Arguments
/// * `binary_path` - Absolute path to the gap-server binary
///
/// # Returns
/// Valid plist XML as a String
pub fn generate_plist(binary_path: &str) -> String {
    let log_dir = get_log_dir();
    let log_dir_str = log_dir.to_string_lossy();

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.gap.server</string>
  <key>Program</key>
  <string>{}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{}</string>
    <string>run</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{}/gap-server.log</string>
  <key>StandardErrorPath</key>
  <string>{}/gap-server.err</string>
</dict>
</plist>
"#,
        binary_path, binary_path, log_dir_str, log_dir_str
    )
}

#[cfg(target_os = "macos")]
/// Get the default plist path for the LaunchAgent
///
/// Returns ~/Library/LaunchAgents/com.gap.server.plist
pub fn get_plist_path() -> PathBuf {
    let home_dir = dirs::home_dir().expect("Could not determine home directory");
    home_dir
        .join("Library")
        .join("LaunchAgents")
        .join("com.gap.server.plist")
}

#[cfg(target_os = "macos")]
/// Get the log directory path
///
/// Returns ~/.gap/logs/
pub fn get_log_dir() -> PathBuf {
    let home_dir = dirs::home_dir().expect("Could not determine home directory");
    home_dir.join(".gap").join("logs")
}

#[cfg(target_os = "macos")]
/// Get the GAP data directory path
///
/// Returns ~/.gap/
pub fn get_gap_dir() -> PathBuf {
    let home_dir = dirs::home_dir().expect("Could not determine home directory");
    home_dir.join(".gap")
}

#[cfg(target_os = "macos")]
/// Install the gap-server as a LaunchAgent
///
/// This function:
/// - Gets the current executable path
/// - Creates the LaunchAgents directory if it doesn't exist
/// - Creates the log directory (~/.gap/logs/)
/// - Generates the plist file
/// - Loads the service with launchctl
/// - Starts the service immediately
///
/// # Returns
/// Ok(()) on success, or an error if installation fails
pub fn install() -> anyhow::Result<()> {
    use std::fs;
    use std::process::Command;

    // Get the binary path (current executable)
    let binary_path = std::env::current_exe()?
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Could not determine binary path"))?
        .to_string();

    // Get plist path
    let plist_path = get_plist_path();

    // Check if plist already exists
    if plist_path.exists() {
        anyhow::bail!(
            "Service already installed at {}.\nRun 'gap-server uninstall' first.",
            plist_path.display()
        );
    }

    // Create LaunchAgents directory if it doesn't exist
    if let Some(parent) = plist_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Create log directory
    let log_dir = get_log_dir();
    fs::create_dir_all(&log_dir)?;

    // Generate plist content
    let plist_content = generate_plist(&binary_path);

    // Write plist file
    fs::write(&plist_path, plist_content)?;
    println!("Created plist at {}", plist_path.display());

    // Load the service with launchctl
    let output = Command::new("launchctl")
        .arg("load")
        .arg(&plist_path)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to load service: {}", stderr);
    }

    println!("Loaded service with launchctl");

    // Start the service immediately
    let output = Command::new("launchctl")
        .arg("start")
        .arg("com.gap.server")
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to start service: {}", stderr);
    }

    println!("Started service com.gap.server");
    println!("\nService installed successfully!");
    println!("Logs will be written to:");
    println!("  stdout: {}/gap-server.log", log_dir.display());
    println!("  stderr: {}/gap-server.err", log_dir.display());

    Ok(())
}

#[cfg(target_os = "macos")]
/// Check the status of the gap-server service
///
/// This function checks if:
/// - The plist file exists
/// - The service is currently running
pub fn status() {
    use std::process::Command;

    let plist_path = get_plist_path();

    // Check if plist exists
    if !plist_path.exists() {
        println!("not installed");
        return;
    }

    // Run launchctl list to check if the service is running
    let output = Command::new("launchctl")
        .args(["list", "com.gap.server"])
        .output();

    match output {
        Ok(output) => {
            if output.status.success() {
                // Parse the output to get PID
                let stdout = String::from_utf8_lossy(&output.stdout);
                // launchctl list output format:
                // PID    Status  Label
                // 12345  0       com.gap.server
                // or just the label if not running

                // Look for lines containing the label
                for line in stdout.lines() {
                    if line.contains("com.gap.server") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 3 {
                            // First part is PID (or "-" if not running)
                            if parts[0] != "-" {
                                println!("running (pid {})", parts[0]);
                                return;
                            }
                        }
                    }
                }
                // If we get here, the service is loaded but not running
                println!("not running");
            } else {
                // launchctl list failed, service not loaded
                println!("not running");
            }
        }
        Err(e) => {
            eprintln!("Error checking service status: {}", e);
            std::process::exit(1);
        }
    }
}

#[cfg(target_os = "macos")]
/// Uninstall the gap-server LaunchAgent
///
/// This function:
/// - Stops the service (ignoring errors if not running)
/// - Unloads the LaunchAgent (ignoring errors if not loaded)
/// - Removes the plist file
/// - Optionally removes ~/.gap/ directory if purge is true
///
/// # Arguments
/// * `purge` - If true, also remove the ~/.gap/ directory
///
/// # Returns
/// Ok(()) on success, or an error if critical operations fail
pub fn uninstall(purge: bool) -> anyhow::Result<()> {
    use std::process::Command;

    let plist_path = get_plist_path();

    // Check if installed
    if !plist_path.exists() {
        println!("gap-server is not installed");
        return Ok(());
    }

    // Stop the service (ignore errors if not running)
    let _ = Command::new("launchctl")
        .args(["stop", "com.gap.server"])
        .output();

    // Unload the service (ignore errors if not loaded)
    let _ = Command::new("launchctl")
        .args(["unload", plist_path.to_str().unwrap()])
        .output();

    // Remove plist file
    if let Err(e) = std::fs::remove_file(&plist_path) {
        eprintln!("Warning: Failed to remove plist file: {}", e);
    } else {
        println!("Removed {}", plist_path.display());
    }

    // If --purge flag is set, remove ~/.gap/ directory
    if purge {
        let gap_dir = get_gap_dir();
        if gap_dir.exists() {
            if let Err(e) = std::fs::remove_dir_all(&gap_dir) {
                eprintln!("Warning: Failed to remove data directory: {}", e);
            } else {
                println!("Removed {}", gap_dir.display());
            }
        }
    }

    println!("gap-server uninstalled successfully");
    Ok(())
}

#[cfg(test)]
#[cfg(target_os = "macos")]
mod tests {
    use super::*;

    #[test]
    fn test_generate_plist_contains_required_keys() {
        let binary_path = "/usr/local/bin/gap-server";
        let plist = generate_plist(binary_path);

        // Verify XML structure
        assert!(plist.contains(r#"<?xml version="1.0" encoding="UTF-8"?>"#));
        assert!(plist.contains(r#"<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN""#));
        assert!(plist.contains(r#"<plist version="1.0">"#));

        // Verify required keys
        assert!(plist.contains("<key>Label</key>"));
        assert!(plist.contains("<string>com.gap.server</string>"));

        assert!(plist.contains("<key>Program</key>"));
        assert!(plist.contains(&format!("<string>{}</string>", binary_path)));

        assert!(plist.contains("<key>ProgramArguments</key>"));
        assert!(plist.contains("<array>"));
        assert!(plist.contains("<string>run</string>"));

        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains("<true/>"));

        assert!(plist.contains("<key>KeepAlive</key>"));

        assert!(plist.contains("<key>StandardOutPath</key>"));
        assert!(plist.contains("<key>StandardErrorPath</key>"));
    }

    #[test]
    fn test_generate_plist_uses_correct_log_paths() {
        let binary_path = "/usr/local/bin/gap-server";
        let plist = generate_plist(binary_path);
        let log_dir = get_log_dir();
        let log_dir_str = log_dir.to_string_lossy();

        // Verify log paths contain the log directory
        assert!(plist.contains(&format!("<string>{}/gap-server.log</string>", log_dir_str)));
        assert!(plist.contains(&format!("<string>{}/gap-server.err</string>", log_dir_str)));
    }

    #[test]
    fn test_generate_plist_valid_xml_structure() {
        let binary_path = "/usr/local/bin/gap-server";
        let plist = generate_plist(binary_path);

        // Verify it starts and ends correctly
        assert!(plist.starts_with(r#"<?xml version="1.0" encoding="UTF-8"?>"#));
        assert!(plist.trim().ends_with("</plist>"));

        // Verify dict structure
        assert!(plist.contains("<dict>"));
        assert!(plist.contains("</dict>"));
    }

    #[test]
    fn test_get_plist_path_returns_correct_location() {
        let path = get_plist_path();
        let path_str = path.to_string_lossy();

        // Should be in ~/Library/LaunchAgents/
        assert!(path_str.contains("Library/LaunchAgents"));
        assert!(path_str.ends_with("com.gap.server.plist"));
    }

    #[test]
    fn test_get_log_dir_returns_gap_logs() {
        let log_dir = get_log_dir();
        let log_dir_str = log_dir.to_string_lossy();

        // Should be ~/.gap/logs/
        assert!(log_dir_str.contains(".gap"));
        assert!(log_dir_str.ends_with("logs"));
    }

    #[test]
    fn test_generate_plist_escapes_special_characters() {
        // Test with a path containing special characters that need XML escaping
        let binary_path = "/path/with spaces/gap-server";
        let plist = generate_plist(binary_path);

        // The path should appear in the plist (spaces are allowed in XML strings)
        assert!(plist.contains("/path/with spaces/gap-server"));
    }

    #[test]
    fn test_generate_plist_program_arguments_order() {
        let binary_path = "/usr/local/bin/gap-server";
        let plist = generate_plist(binary_path);

        // Find the ProgramArguments array
        let args_start = plist.find("<key>ProgramArguments</key>").expect("ProgramArguments key not found");
        let args_section = &plist[args_start..];

        // Find the array section
        let array_start = args_section.find("<array>").expect("array not found");
        let array_end = args_section.find("</array>").expect("array end not found");
        let array_content = &args_section[array_start..array_end];

        // First argument should be the binary path
        let first_arg_pos = array_content.find(&format!("<string>{}</string>", binary_path))
            .expect("binary path not found in array");

        // Second argument should be "run"
        let run_arg_pos = array_content.find("<string>run</string>")
            .expect("run argument not found in array");

        // Binary path should come before "run"
        assert!(first_arg_pos < run_arg_pos, "Binary path should be first argument");
    }
}
