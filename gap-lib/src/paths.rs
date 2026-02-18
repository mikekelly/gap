//! Platform-specific path utilities for GAP
//!
//! This module provides functions to get well-known paths for GAP resources
//! like the CA certificate, ensuring consistent paths across platforms.

use std::path::PathBuf;

/// Returns the platform-specific path for the CA certificate.
///
/// On macOS: ~/Library/Application Support/gap/ca.crt
/// On Linux: /var/lib/gap/ca.crt
///
/// # Examples
///
/// ```
/// use gap_lib::ca_cert_path;
/// let path = ca_cert_path();
/// assert!(path.to_string_lossy().contains("ca.crt"));
/// ```
pub fn ca_cert_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        // ~/Library/Application Support/gap/ca.crt
        dirs::data_dir()
            .expect("Failed to determine data directory")
            .join("gap")
            .join("ca.crt")
    }
    #[cfg(not(target_os = "macos"))]
    {
        // /var/lib/gap/ca.crt
        PathBuf::from("/var/lib/gap/ca.crt")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "macos")]
    fn test_ca_cert_path_macos() {
        let path = ca_cert_path();

        // On macOS, should be ~/Library/Application Support/gap/ca.crt
        let path_str = path.to_string_lossy();
        assert!(path_str.contains("Library/Application Support/gap/ca.crt"),
                "Expected path to contain 'Library/Application Support/gap/ca.crt', got: {}", path_str);

        // Verify it's an absolute path
        assert!(path.is_absolute(), "CA cert path should be absolute");

        // Verify the filename is correct
        assert_eq!(path.file_name().unwrap().to_str().unwrap(), "ca.crt");

        // Verify the parent directory is "gap"
        assert_eq!(path.parent().unwrap().file_name().unwrap().to_str().unwrap(), "gap");
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn test_ca_cert_path_linux() {
        let path = ca_cert_path();

        // On Linux, should be /var/lib/gap/ca.crt
        assert_eq!(path, PathBuf::from("/var/lib/gap/ca.crt"));

        // Verify it's an absolute path
        assert!(path.is_absolute(), "CA cert path should be absolute");

        // Verify the filename is correct
        assert_eq!(path.file_name().unwrap().to_str().unwrap(), "ca.crt");

        // Verify the parent directory is "gap"
        assert_eq!(path.parent().unwrap().file_name().unwrap().to_str().unwrap(), "gap");
    }
}
