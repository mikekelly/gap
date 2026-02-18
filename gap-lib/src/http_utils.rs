//! HTTP utilities for parsing and serializing HTTP requests
//!
//! Provides functions to convert between raw HTTP bytes and GAPRequest structs.

use crate::error::{GapError, Result};
use crate::types::GAPRequest;
use std::collections::HashMap;

/// Parse raw HTTP request bytes into an GAPRequest
///
/// Extracts method, path, headers, and body from HTTP/1.1 format.
/// Constructs full URL from Host header and request path.
///
/// # Arguments
/// * `bytes` - Raw HTTP request bytes
///
/// # Returns
/// Parsed GAPRequest struct
pub fn parse_http_request(bytes: &[u8]) -> Result<GAPRequest> {
    let request_str = std::str::from_utf8(bytes)
        .map_err(|e| GapError::protocol(format!("Invalid UTF-8 in HTTP request: {}", e)))?;

    // Split into lines
    let mut lines = request_str.lines();

    // Parse request line: "METHOD /path HTTP/1.1"
    let request_line = lines
        .next()
        .ok_or_else(|| GapError::protocol("Empty HTTP request"))?;

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(GapError::protocol(format!(
            "Invalid HTTP request line: {}",
            request_line
        )));
    }

    let method = parts[0].to_string();
    let path = parts[1].to_string();

    // Parse headers
    let mut headers = HashMap::new();
    let mut body_start = 0;

    for (i, line) in lines.enumerate() {
        if line.is_empty() {
            // End of headers, rest is body
            // Calculate byte offset for body
            let header_text: String = request_str.lines().take(i + 2).collect::<Vec<_>>().join("\r\n");
            body_start = header_text.len() + 2; // +2 for final \r\n
            break;
        }

        // Parse header: "Key: Value"
        if let Some(colon_pos) = line.find(':') {
            let key = line[..colon_pos].trim().to_string();
            let value = line[colon_pos + 1..].trim().to_string();
            headers.insert(key, value);
        }
    }

    // Extract host from headers
    let host = headers
        .get("Host")
        .ok_or_else(|| GapError::protocol("Missing Host header"))?
        .clone();

    // Construct full URL (assume HTTPS since we're a MITM proxy)
    let url = if path.starts_with("http://") || path.starts_with("https://") {
        path
    } else {
        format!("https://{}{}", host, path)
    };

    // Extract body (if any)
    let body = if body_start > 0 && body_start < bytes.len() {
        bytes[body_start..].to_vec()
    } else {
        Vec::new()
    };

    Ok(GAPRequest {
        method,
        url,
        headers,
        body,
    })
}

/// Serialize GAPRequest back to raw HTTP bytes
///
/// Converts GAPRequest into HTTP/1.1 format suitable for forwarding.
///
/// # Arguments
/// * `request` - GAPRequest to serialize
///
/// # Returns
/// Raw HTTP bytes
pub fn serialize_http_request(request: &GAPRequest) -> Result<Vec<u8>> {
    let mut result = Vec::new();

    // Extract path from URL
    let path = extract_path_from_url(&request.url)?;

    // Write request line: "METHOD /path HTTP/1.1\r\n"
    result.extend_from_slice(format!("{} {} HTTP/1.1\r\n", request.method, path).as_bytes());

    // Write headers
    for (key, value) in &request.headers {
        result.extend_from_slice(format!("{}: {}\r\n", key, value).as_bytes());
    }

    // Add Content-Length header if body is present and not already set
    if !request.body.is_empty() && !request.headers.contains_key("Content-Length") {
        result.extend_from_slice(format!("Content-Length: {}\r\n", request.body.len()).as_bytes());
    }

    // End of headers
    result.extend_from_slice(b"\r\n");

    // Write body
    result.extend_from_slice(&request.body);

    Ok(result)
}

/// Extract path and query from full URL
///
/// Converts "https://example.com/path?query" to "/path?query"
pub(crate) fn extract_path_from_url(url: &str) -> Result<String> {
    // Simple URL parsing - find the third slash
    if url.starts_with("http://") || url.starts_with("https://") {
        let without_scheme = if let Some(stripped) = url.strip_prefix("https://") {
            stripped
        } else {
            url.strip_prefix("http://").unwrap_or(url)
        };

        // Find the first slash after the host
        if let Some(slash_pos) = without_scheme.find('/') {
            Ok(without_scheme[slash_pos..].to_string())
        } else {
            Ok("/".to_string())
        }
    } else {
        // Already a path
        Ok(url.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_path_from_url() {
        assert_eq!(extract_path_from_url("https://example.com/path").unwrap(), "/path");
        assert_eq!(extract_path_from_url("https://example.com/path?query=1").unwrap(), "/path?query=1");
        assert_eq!(extract_path_from_url("https://example.com").unwrap(), "/");
        assert_eq!(extract_path_from_url("/path").unwrap(), "/path");
    }

    #[test]
    fn test_parse_simple_request() {
        let raw = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let req = parse_http_request(raw).unwrap();

        assert_eq!(req.method, "GET");
        assert_eq!(req.url, "https://example.com/test");
        assert_eq!(req.headers.get("Host"), Some(&"example.com".to_string()));
        assert_eq!(req.body, b"");
    }

    #[test]
    fn test_parse_request_with_body() {
        let raw = b"POST /data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\ntest";
        let req = parse_http_request(raw).unwrap();

        assert_eq!(req.method, "POST");
        assert_eq!(req.body, b"test");
    }

    #[test]
    fn test_serialize_simple_request() {
        let req = GAPRequest::new("GET", "https://example.com/test")
            .with_header("Host", "example.com");

        let serialized = serialize_http_request(&req).unwrap();
        let serialized_str = String::from_utf8_lossy(&serialized);

        assert!(serialized_str.starts_with("GET /test HTTP/1.1\r\n"));
        assert!(serialized_str.contains("Host: example.com\r\n"));
    }

    #[test]
    fn test_serialize_request_with_body() {
        let req = GAPRequest::new("POST", "https://example.com/data")
            .with_header("Host", "example.com")
            .with_body(b"test".to_vec());

        let serialized = serialize_http_request(&req).unwrap();
        let serialized_str = String::from_utf8_lossy(&serialized);

        assert!(serialized_str.contains("Content-Length: 4\r\n"));
        assert!(serialized_str.ends_with("\r\n\r\ntest"));
    }
}
