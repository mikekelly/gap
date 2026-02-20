//! TLS infrastructure for dynamic certificate generation
//!
//! This module provides:
//! - Certificate Authority (CA) generation and management
//! - Dynamic certificate signing for any hostname
//! - Certificate caching with expiration
//! - PEM serialization/deserialization

use crate::{GapError, Result};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

/// A Certificate Authority that can generate and sign certificates
#[derive(Debug)]
pub struct CertificateAuthority {
    /// The CA certificate PEM (for export)
    ca_cert_pem: String,
    /// The CA key PEM (for export)
    ca_key_pem: String,
    /// Certificate cache
    cache: Arc<RwLock<CertificateCache>>,
}

/// Cached certificate entry with expiration
#[derive(Debug)]
struct CachedCertificate {
    /// Certificate in DER format
    cert: Vec<u8>,
    /// Private key in DER format
    key: Vec<u8>,
    /// Expiration time
    expires_at: SystemTime,
}

/// Certificate cache with expiry
#[derive(Debug)]
struct CertificateCache {
    entries: HashMap<String, CachedCertificate>,
}

impl CertificateCache {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn get(&mut self, hostname: &str) -> Option<(Vec<u8>, Vec<u8>)> {
        // Clean up expired entries
        let now = SystemTime::now();
        self.entries.retain(|_, entry| entry.expires_at > now);

        // Return cached certificate if valid
        self.entries.get(hostname).map(|entry| {
            (entry.cert.clone(), entry.key.clone())
        })
    }

    fn insert(&mut self, hostname: String, cert: Vec<u8>, key: Vec<u8>, validity: Duration) {
        let expires_at = SystemTime::now() + validity;
        self.entries.insert(hostname, CachedCertificate {
            cert,
            key,
            expires_at,
        });
    }

    fn clear(&mut self) {
        self.entries.clear();
    }
}

impl CertificateAuthority {
    /// Generate a new Certificate Authority
    ///
    /// Creates a self-signed CA certificate with a private key.
    /// The CA is valid for 10 years by default.
    pub fn generate() -> Result<Self> {
        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
        use time::{Duration as TimeDuration, OffsetDateTime};

        // Generate CA key pair
        let key_pair = KeyPair::generate()
            .map_err(|e| GapError::tls(format!("Failed to generate CA key pair: {}", e)))?;

        // Set up CA parameters
        let mut params = CertificateParams::default();

        // Set distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "GAP Certificate Authority");
        dn.push(DnType::OrganizationName, "GAP");
        params.distinguished_name = dn;

        // Set validity period (10 years)
        let now = OffsetDateTime::now_utc();
        params.not_before = now - TimeDuration::minutes(5); // Allow 5 minute clock skew
        params.not_after = now + TimeDuration::days(3650); // 10 years

        // Mark as CA
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        // Set key usages for CA
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];

        // Generate self-signed CA certificate
        let cert = params.self_signed(&key_pair)
            .map_err(|e| GapError::tls(format!("Failed to generate CA certificate: {}", e)))?;

        let ca_cert_pem = cert.pem();
        let ca_key_pem = key_pair.serialize_pem();

        Ok(Self {
            ca_cert_pem,
            ca_key_pem,
            cache: Arc::new(RwLock::new(CertificateCache::new())),
        })
    }

    /// Load a Certificate Authority from DER-encoded certificate and key
    pub fn from_der(ca_cert: Vec<u8>, ca_key: Vec<u8>) -> Result<Self> {
        let ca_cert_pem = der_to_pem(&ca_cert, "CERTIFICATE");
        let ca_key_pem = der_to_pem(&ca_key, "PRIVATE KEY");
        Ok(Self {
            ca_cert_pem,
            ca_key_pem,
            cache: Arc::new(RwLock::new(CertificateCache::new())),
        })
    }

    /// Load a Certificate Authority from PEM-encoded certificate and key
    pub fn from_pem(ca_cert_pem: &str, ca_key_pem: &str) -> Result<Self> {
        // Validate that they are valid PEM
        let _ = pem_to_der(ca_cert_pem, "CERTIFICATE")?;
        let _ = pem_to_der(ca_key_pem, "PRIVATE KEY")?;

        Ok(Self {
            ca_cert_pem: ca_cert_pem.to_string(),
            ca_key_pem: ca_key_pem.to_string(),
            cache: Arc::new(RwLock::new(CertificateCache::new())),
        })
    }

    /// Export the CA certificate as PEM
    pub fn ca_cert_pem(&self) -> String {
        self.ca_cert_pem.clone()
    }

    /// Export the CA private key as PEM
    pub fn ca_key_pem(&self) -> String {
        self.ca_key_pem.clone()
    }

    /// Export the CA certificate as DER
    pub fn ca_cert_der(&self) -> Vec<u8> {
        pem_to_der(&self.ca_cert_pem, "CERTIFICATE").expect("Invalid CA cert PEM")
    }

    /// Export the CA private key as DER
    pub fn ca_key_der(&self) -> Vec<u8> {
        pem_to_der(&self.ca_key_pem, "PRIVATE KEY").expect("Invalid CA key PEM")
    }

    /// Generate a certificate for the given hostname
    ///
    /// Returns a tuple of (certificate_der, private_key_der).
    /// The certificate is valid for the specified duration (default 24 hours).
    /// Results are cached to avoid regenerating certificates.
    pub fn sign_for_hostname(&self, hostname: &str, validity: Option<Duration>) -> Result<(Vec<u8>, Vec<u8>)> {
        let validity = validity.unwrap_or(Duration::from_secs(24 * 60 * 60));

        // Check cache first
        {
            let mut cache = self.cache.write()
                .map_err(|_| GapError::tls("Failed to acquire cache write lock"))?;

            if let Some(cached) = cache.get(hostname) {
                return Ok(cached);
            }
        }

        // Generate new certificate
        let (cert, key) = self.generate_cert_for_hostname(hostname, validity)?;

        // Cache the result
        {
            let mut cache = self.cache.write()
                .map_err(|_| GapError::tls("Failed to acquire cache write lock"))?;
            cache.insert(hostname.to_string(), cert.clone(), key.clone(), validity);
        }

        Ok((cert, key))
    }

    /// Generate a server certificate with configurable Subject Alternative Names (SANs)
    ///
    /// Returns a tuple of (certificate_der, private_key_der).
    ///
    /// SANs should be in the format:
    /// - `DNS:hostname` for DNS names (e.g., "DNS:localhost", "DNS:example.com")
    /// - `IP:address` for IP addresses (e.g., "IP:127.0.0.1", "IP:::1")
    ///
    /// The certificate will have key usages appropriate for TLS server authentication.
    pub fn sign_server_cert(&self, sans: &[String]) -> Result<(Vec<u8>, Vec<u8>)> {
        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
        use time::{Duration as TimeDuration, OffsetDateTime};

        // Parse SANs
        let mut parsed_sans = Vec::new();
        for san in sans {
            if let Some(dns_name) = san.strip_prefix("DNS:") {
                parsed_sans.push(SanType::DnsName(dns_name.to_string().try_into()
                    .map_err(|e| GapError::tls(format!("Invalid DNS name '{}': {}", dns_name, e)))?));
            } else if let Some(ip_str) = san.strip_prefix("IP:") {
                let ip_addr = ip_str.parse()
                    .map_err(|e| GapError::tls(format!("Invalid IP address '{}': {}", ip_str, e)))?;
                parsed_sans.push(SanType::IpAddress(ip_addr));
            } else {
                return Err(GapError::tls(format!("Invalid SAN format '{}'. Expected 'DNS:hostname' or 'IP:address'", san)));
            }
        }

        if parsed_sans.is_empty() {
            return Err(GapError::tls("At least one SAN is required"));
        }

        // Reconstruct CA for signing
        let (ca_cert, ca_key_pair) = self.reconstruct_ca_for_signing()?;

        // Generate key pair for the new certificate
        let key_pair = KeyPair::generate()
            .map_err(|e| GapError::tls(format!("Failed to generate key pair: {}", e)))?;

        // Set up certificate parameters with SANs
        let mut params = CertificateParams::default();
        params.subject_alt_names = parsed_sans;

        // Set distinguished name (use first SAN as CN if available)
        let mut dn = DistinguishedName::new();
        if let Some(first_san) = sans.first() {
            let cn = if let Some(dns) = first_san.strip_prefix("DNS:") {
                dns
            } else {
                first_san.strip_prefix("IP:").unwrap_or("GAP Server")
            };
            dn.push(DnType::CommonName, cn);
        }
        params.distinguished_name = dn;

        // Set validity period (default to 90 days for server certs)
        let now = OffsetDateTime::now_utc();
        let validity = TimeDuration::days(90);
        params.not_before = now - TimeDuration::minutes(5); // Allow 5 minute clock skew
        params.not_after = now + validity;

        // Set as end-entity certificate (not a CA)
        params.is_ca = rcgen::IsCa::NoCa;

        // Set key usages for server authentication
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];

        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        ];

        // Sign the certificate with the CA
        let cert = params.signed_by(&key_pair, &ca_cert, &ca_key_pair)
            .map_err(|e| GapError::tls(format!("Failed to sign certificate: {}", e)))?;

        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der().to_vec();

        Ok((cert_der, key_der))
    }

    /// Reconstruct the CA certificate and key pair for signing operations
    ///
    /// This is a workaround for rcgen 0.13 not supporting loading certs from PEM/DER.
    /// We reconstruct the CA from its parameters so it can be used for signing.
    /// The DN is extracted from the stored certificate (not hardcoded) so that
    /// injected CAs with custom DNs produce leaf certs with correct issuer fields.
    fn reconstruct_ca_for_signing(&self) -> Result<(rcgen::Certificate, rcgen::KeyPair)> {
        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
        use x509_parser::oid_registry;

        let ca_key_pair = KeyPair::from_pem(&self.ca_key_pem)
            .map_err(|e| GapError::tls(format!("Failed to parse CA private key: {}", e)))?;

        // Parse the stored cert DER to extract the subject DN
        let ca_cert_der = self.ca_cert_der();
        let (_, parsed) = x509_parser::parse_x509_certificate(&ca_cert_der)
            .map_err(|e| GapError::tls(format!("Failed to parse CA certificate DER: {}", e)))?;

        let mut ca_dn = DistinguishedName::new();
        for rdn in parsed.subject().iter() {
            for attr in rdn.iter() {
                let value = attr.as_str()
                    .map_err(|e| GapError::tls(format!("Failed to read DN attribute: {}", e)))?;
                let oid = attr.attr_type();
                if *oid == oid_registry::OID_X509_COMMON_NAME {
                    ca_dn.push(DnType::CommonName, value);
                } else if *oid == oid_registry::OID_X509_ORGANIZATION_NAME {
                    ca_dn.push(DnType::OrganizationName, value);
                } else if *oid == oid_registry::OID_X509_COUNTRY_NAME {
                    ca_dn.push(DnType::CountryName, value);
                } else if *oid == oid_registry::OID_X509_LOCALITY_NAME {
                    ca_dn.push(DnType::LocalityName, value);
                } else if *oid == oid_registry::OID_X509_STATE_OR_PROVINCE_NAME {
                    ca_dn.push(DnType::StateOrProvinceName, value);
                } else if *oid == oid_registry::OID_X509_ORGANIZATIONAL_UNIT {
                    ca_dn.push(DnType::OrganizationalUnitName, value);
                }
            }
        }

        let mut ca_params = CertificateParams::default();
        ca_params.distinguished_name = ca_dn;
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];

        let ca_cert = ca_params.self_signed(&ca_key_pair)
            .map_err(|e| GapError::tls(format!("Failed to reconstruct CA certificate: {}", e)))?;

        Ok((ca_cert, ca_key_pair))
    }

    /// Generate a certificate for the hostname without caching
    ///
    /// Handles both DNS hostnames and IP addresses. IP addresses are detected
    /// via `IpAddr::from_str` and added as IP SANs (not DNS SANs), which is
    /// required for TLS clients to validate certs for IP-based connections.
    fn generate_cert_for_hostname(&self, hostname: &str, validity: Duration) -> Result<(Vec<u8>, Vec<u8>)> {
        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
        use time::{Duration as TimeDuration, OffsetDateTime};

        // Reconstruct CA for signing
        let (ca_cert, ca_key_pair) = self.reconstruct_ca_for_signing()?;

        // Generate key pair for the new certificate
        let key_pair = KeyPair::generate()
            .map_err(|e| GapError::tls(format!("Failed to generate key pair: {}", e)))?;

        // Set up certificate parameters, handling IP addresses vs DNS names
        let mut params = if let Ok(ip) = hostname.parse::<std::net::IpAddr>() {
            // IP address: use default params and add IP SAN manually
            let mut p = CertificateParams::default();
            p.subject_alt_names = vec![SanType::IpAddress(ip)];
            p
        } else {
            // DNS hostname: use the existing behavior
            CertificateParams::new(vec![hostname.to_string()])
                .map_err(|e| GapError::tls(format!("Failed to create certificate params: {}", e)))?
        };

        // Set distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, hostname);
        params.distinguished_name = dn;

        // Set validity period
        let now = OffsetDateTime::now_utc();
        let validity_duration = TimeDuration::seconds(validity.as_secs() as i64);
        params.not_before = now - TimeDuration::minutes(5); // Allow 5 minute clock skew
        params.not_after = now + validity_duration;

        // Set as end-entity certificate (not a CA)
        params.is_ca = rcgen::IsCa::NoCa;

        // Set key usages for server authentication
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];

        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        ];

        // Sign the certificate with the CA
        let cert = params.signed_by(&key_pair, &ca_cert, &ca_key_pair)
            .map_err(|e| GapError::tls(format!("Failed to sign certificate: {}", e)))?;

        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der().to_vec();

        Ok((cert_der, key_der))
    }

    /// Clear the certificate cache
    pub fn clear_cache(&self) -> Result<()> {
        let mut cache = self.cache.write()
            .map_err(|_| GapError::tls("Failed to acquire cache write lock"))?;
        cache.clear();
        Ok(())
    }
}

/// Resolves TLS certificates dynamically using the CA to generate certs
/// matching the SNI hostname from client hello.
#[derive(Debug)]
pub struct DynamicCertResolver {
    ca: Arc<CertificateAuthority>,
}

impl DynamicCertResolver {
    pub fn new(ca: Arc<CertificateAuthority>) -> Self {
        Self { ca }
    }
}

impl rustls::server::ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        // No-SNI fallback to "localhost" — IP-based connections don't send SNI per RFC 6066
        let sni = client_hello.server_name().unwrap_or("localhost");

        let (cert_der, key_der) = self.ca.sign_for_hostname(sni, None).ok()?;

        let key = rustls::pki_types::PrivateKeyDer::try_from(key_der).ok()?;
        let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key).ok()?;

        // Include CA cert in chain so clients can verify the full chain
        let ca_cert_der = self.ca.ca_cert_der();
        let cert_chain = vec![
            rustls::pki_types::CertificateDer::from(cert_der),
            rustls::pki_types::CertificateDer::from(ca_cert_der),
        ];

        Some(Arc::new(rustls::sign::CertifiedKey::new(cert_chain, signing_key)))
    }
}

/// Validate that a certificate's public key matches the private key.
///
/// Compares the SubjectPublicKeyInfo (SPKI) DER from both the certificate
/// and the private key to verify they correspond.
pub fn validate_cert_key_match(cert_der: &[u8], key_der: &[u8]) -> Result<()> {
    use rcgen::KeyPair;

    // Parse the private key to get its public key (SPKI DER)
    let key_pem = der_to_pem(key_der, "PRIVATE KEY");
    let key_pair = KeyPair::from_pem(&key_pem)
        .map_err(|e| GapError::tls(format!("Invalid private key: {}", e)))?;
    let key_public = key_pair.public_key_der();

    // Parse the certificate to get its public key (SPKI DER)
    let (_, parsed_cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| GapError::tls(format!("Invalid certificate: {}", e)))?;
    let cert_public = parsed_cert.tbs_certificate.subject_pki.raw;

    // Compare SubjectPublicKeyInfo DER bytes — they must be identical
    if key_public.as_slice() != cert_public {
        return Err(GapError::tls(
            "Certificate and private key do not match — the certificate's public key differs from the private key's public key"
        ));
    }

    Ok(())
}

/// Convert PEM to DER format
fn pem_to_der(pem: &str, label: &str) -> Result<Vec<u8>> {
    let start_marker = format!("-----BEGIN {}-----", label);
    let end_marker = format!("-----END {}-----", label);

    let pem = pem.trim();

    if !pem.starts_with(&start_marker) || !pem.ends_with(&end_marker) {
        return Err(GapError::tls(format!("Invalid PEM format: expected {} markers", label)));
    }

    // Extract base64 content between markers
    let content = pem
        .strip_prefix(&start_marker)
        .and_then(|s| s.strip_suffix(&end_marker))
        .ok_or_else(|| GapError::tls("Invalid PEM format"))?
        .trim();

    // Decode base64
    base64_decode(content)
        .map_err(|e| GapError::tls(format!("Failed to decode PEM base64: {}", e)))
}

/// Convert DER to PEM format
pub fn der_to_pem(der: &[u8], label: &str) -> String {
    let encoded = base64_encode(der);
    format!("-----BEGIN {}-----\n{}\n-----END {}-----\n", label, encoded, label)
}

/// Base64 encode with line wrapping at 64 characters
fn base64_encode(data: &[u8]) -> String {
    use std::fmt::Write;

    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    let mut col = 0;

    for chunk in data.chunks(3) {
        let buf = match chunk.len() {
            1 => [chunk[0], 0, 0],
            2 => [chunk[0], chunk[1], 0],
            _ => [chunk[0], chunk[1], chunk[2]],
        };

        let b1 = (buf[0] >> 2) as usize;
        let b2 = (((buf[0] & 0x03) << 4) | (buf[1] >> 4)) as usize;
        let b3 = (((buf[1] & 0x0f) << 2) | (buf[2] >> 6)) as usize;
        let b4 = (buf[2] & 0x3f) as usize;

        write!(result, "{}", ALPHABET[b1] as char).unwrap();
        write!(result, "{}", ALPHABET[b2] as char).unwrap();

        col += 2;

        if chunk.len() > 1 {
            write!(result, "{}", ALPHABET[b3] as char).unwrap();
            col += 1;
        } else {
            write!(result, "=").unwrap();
            col += 1;
        }

        if chunk.len() > 2 {
            write!(result, "{}", ALPHABET[b4] as char).unwrap();
            col += 1;
        } else {
            write!(result, "=").unwrap();
            col += 1;
        }

        if col >= 64 {
            writeln!(result).unwrap();
            col = 0;
        }
    }

    result
}

/// Base64 decode
fn base64_decode(data: &str) -> std::result::Result<Vec<u8>, String> {
    const DECODE: [i8; 256] = {
        let mut table = [-1i8; 256];
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0;
        while i < alphabet.len() {
            table[alphabet[i] as usize] = i as i8;
            i += 1;
        }
        table
    };

    let data = data.chars().filter(|c| !c.is_whitespace()).collect::<String>();
    let data = data.as_bytes();

    if data.len() % 4 != 0 {
        return Err("Invalid base64 length".to_string());
    }

    let mut result = Vec::new();

    for chunk in data.chunks(4) {
        let b1 = DECODE[chunk[0] as usize];
        let b2 = DECODE[chunk[1] as usize];
        let b3 = if chunk[2] == b'=' { -1 } else { DECODE[chunk[2] as usize] };
        let b4 = if chunk[3] == b'=' { -1 } else { DECODE[chunk[3] as usize] };

        if b1 < 0 || b2 < 0 {
            return Err("Invalid base64 character".to_string());
        }

        result.push(((b1 << 2) | (b2 >> 4)) as u8);

        if b3 >= 0 {
            result.push((((b2 & 0x0f) << 4) | (b3 >> 2)) as u8);
        }

        if b4 >= 0 {
            result.push((((b3 & 0x03) << 6) | b4) as u8);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, World!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(data, decoded.as_slice());
    }

    #[test]
    fn test_base64_standard_vectors() {
        // Standard test vectors from RFC 4648
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn test_pem_roundtrip() {
        let original_der = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let pem = der_to_pem(&original_der, "TEST");
        let decoded_der = pem_to_der(&pem, "TEST").unwrap();
        assert_eq!(original_der, decoded_der);
    }

    #[test]
    fn test_pem_format() {
        let der = vec![1, 2, 3];
        let pem = der_to_pem(&der, "CERTIFICATE");
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
    }

    #[test]
    fn test_ca_generation() {
        let ca = CertificateAuthority::generate().unwrap();

        // CA cert and key should be non-empty
        assert!(!ca.ca_cert_der().is_empty());
        assert!(!ca.ca_key_der().is_empty());

        // Should be able to export to PEM
        let ca_cert_pem = ca.ca_cert_pem();
        let ca_key_pem = ca.ca_key_pem();

        assert!(ca_cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(ca_key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn test_ca_from_pem_roundtrip() {
        // Create some dummy DER data
        let ca_cert_der = vec![1, 2, 3, 4, 5];
        let ca_key_der = vec![6, 7, 8, 9, 10];

        let ca_cert_pem = der_to_pem(&ca_cert_der, "CERTIFICATE");
        let ca_key_pem = der_to_pem(&ca_key_der, "PRIVATE KEY");

        let ca = CertificateAuthority::from_pem(&ca_cert_pem, &ca_key_pem).unwrap();

        // Verify we can export back to PEM
        assert_eq!(ca.ca_cert_pem(), ca_cert_pem);
        assert_eq!(ca.ca_key_pem(), ca_key_pem);
    }

    #[test]
    fn test_ca_der_access() {
        let ca_cert_der = vec![1, 2, 3, 4, 5];
        let ca_key_der = vec![6, 7, 8, 9, 10];

        let ca = CertificateAuthority::from_der(ca_cert_der.clone(), ca_key_der.clone()).unwrap();

        assert_eq!(ca.ca_cert_der(), ca_cert_der);
        assert_eq!(ca.ca_key_der(), ca_key_der);
    }

    #[test]
    fn test_sign_for_hostname() {
        // Generate a CA
        let ca = CertificateAuthority::generate().unwrap();

        // Sign a certificate for a hostname
        let (cert_der, key_der) = ca.sign_for_hostname("example.com", None).unwrap();

        // Certificate and key should be non-empty
        assert!(!cert_der.is_empty());
        assert!(!key_der.is_empty());

        // The certificate should be different from the CA certificate
        let ca_cert_der = ca.ca_cert_der();
        assert_ne!(cert_der, ca_cert_der);
    }

    #[test]
    fn test_certificate_caching() {
        let ca = CertificateAuthority::generate().unwrap();

        // First call should generate a new certificate
        let (cert1, key1) = ca.sign_for_hostname("example.com", None).unwrap();

        // Second call should return the cached certificate
        let (cert2, key2) = ca.sign_for_hostname("example.com", None).unwrap();

        // Should be the same certificate (cached)
        assert_eq!(cert1, cert2);
        assert_eq!(key1, key2);

        // Different hostname should generate a different certificate
        let (cert3, _) = ca.sign_for_hostname("different.com", None).unwrap();
        assert_ne!(cert1, cert3);
    }

    #[test]
    fn test_cache_expiry() {
        let ca = CertificateAuthority::generate().unwrap();

        // Generate a certificate with very short validity (1 second)
        let validity = Duration::from_secs(1);
        let (cert1, _) = ca.sign_for_hostname("example.com", Some(validity)).unwrap();

        // Wait for it to expire
        std::thread::sleep(Duration::from_secs(2));

        // Should generate a new certificate (cache expired)
        let (cert2, _) = ca.sign_for_hostname("example.com", Some(validity)).unwrap();

        // Certificates should be different due to different validity periods
        assert_ne!(cert1, cert2);
    }

    #[test]
    fn test_cache_clear() {
        let ca_cert_der = vec![1, 2, 3, 4, 5];
        let ca_key_der = vec![6, 7, 8, 9, 10];

        let ca = CertificateAuthority::from_der(ca_cert_der, ca_key_der).unwrap();

        // Should be able to clear cache even when empty
        assert!(ca.clear_cache().is_ok());
    }

    #[test]
    fn test_sign_server_cert_dns_only() {
        // Generate a CA
        let ca = CertificateAuthority::generate().unwrap();

        // Sign a server certificate with DNS SANs only
        let sans = vec![
            "DNS:localhost".to_string(),
            "DNS:example.com".to_string(),
            "DNS:*.example.com".to_string(),
        ];
        let (cert_der, key_der) = ca.sign_server_cert(&sans).unwrap();

        // Certificate and key should be non-empty
        assert!(!cert_der.is_empty());
        assert!(!key_der.is_empty());

        // The certificate should be different from the CA certificate
        let ca_cert_der = ca.ca_cert_der();
        assert_ne!(cert_der, ca_cert_der);
    }

    #[test]
    fn test_sign_server_cert_ip_only() {
        // Generate a CA
        let ca = CertificateAuthority::generate().unwrap();

        // Sign a server certificate with IP SANs only
        let sans = vec![
            "IP:127.0.0.1".to_string(),
            "IP:::1".to_string(),
        ];
        let (cert_der, key_der) = ca.sign_server_cert(&sans).unwrap();

        // Certificate and key should be non-empty
        assert!(!cert_der.is_empty());
        assert!(!key_der.is_empty());

        // The certificate should be different from the CA certificate
        let ca_cert_der = ca.ca_cert_der();
        assert_ne!(cert_der, ca_cert_der);
    }

    #[test]
    fn test_sign_server_cert_mixed_sans() {
        // Generate a CA
        let ca = CertificateAuthority::generate().unwrap();

        // Sign a server certificate with mixed DNS and IP SANs
        let sans = vec![
            "DNS:localhost".to_string(),
            "IP:127.0.0.1".to_string(),
            "IP:::1".to_string(),
            "DNS:example.com".to_string(),
        ];
        let (cert_der, key_der) = ca.sign_server_cert(&sans).unwrap();

        // Certificate and key should be non-empty
        assert!(!cert_der.is_empty());
        assert!(!key_der.is_empty());

        // The certificate should be different from the CA certificate
        let ca_cert_der = ca.ca_cert_der();
        assert_ne!(cert_der, ca_cert_der);
    }

    #[test]
    fn test_sign_for_hostname_ip_address_has_ip_san() {
        // Verify that sign_for_hostname with an IP address produces an IP SAN,
        // not a DNS SAN (which would fail TLS validation for IP connections)
        let ca = CertificateAuthority::generate().unwrap();
        let (cert_der, _key_der) = ca.sign_for_hostname("192.168.1.5", None).unwrap();

        // Use openssl to inspect the cert SANs
        use std::io::Write;
        let cert_pem = der_to_pem(&cert_der, "CERTIFICATE");
        let mut cert_file = tempfile::NamedTempFile::new().unwrap();
        cert_file.write_all(cert_pem.as_bytes()).unwrap();
        cert_file.flush().unwrap();

        let output = std::process::Command::new("openssl")
            .args(["x509", "-in", cert_file.path().to_str().unwrap(), "-text", "-noout"])
            .output()
            .expect("Failed to run openssl");

        let text = String::from_utf8_lossy(&output.stdout);

        // Should contain IP Address SAN, not DNS SAN
        assert!(
            text.contains("IP Address:192.168.1.5"),
            "Expected IP Address SAN but got:\n{}",
            text
        );
        assert!(
            !text.contains("DNS:192.168.1.5"),
            "Should NOT have DNS SAN for IP address:\n{}",
            text
        );
    }

    #[test]
    fn test_sign_for_hostname_ipv6_has_ip_san() {
        let ca = CertificateAuthority::generate().unwrap();
        let (cert_der, _key_der) = ca.sign_for_hostname("::1", None).unwrap();

        use std::io::Write;
        let cert_pem = der_to_pem(&cert_der, "CERTIFICATE");
        let mut cert_file = tempfile::NamedTempFile::new().unwrap();
        cert_file.write_all(cert_pem.as_bytes()).unwrap();
        cert_file.flush().unwrap();

        let output = std::process::Command::new("openssl")
            .args(["x509", "-in", cert_file.path().to_str().unwrap(), "-text", "-noout"])
            .output()
            .expect("Failed to run openssl");

        let text = String::from_utf8_lossy(&output.stdout);

        // Should contain IP Address SAN for IPv6
        assert!(
            text.contains("IP Address:0:0:0:0:0:0:0:1") || text.contains("IP Address:::1"),
            "Expected IPv6 IP Address SAN but got:\n{}",
            text
        );
    }

    #[test]
    fn test_sign_for_hostname_dns_still_works() {
        // Ensure regular hostnames still get DNS SANs
        let ca = CertificateAuthority::generate().unwrap();
        let (cert_der, _key_der) = ca.sign_for_hostname("example.com", None).unwrap();

        use std::io::Write;
        let cert_pem = der_to_pem(&cert_der, "CERTIFICATE");
        let mut cert_file = tempfile::NamedTempFile::new().unwrap();
        cert_file.write_all(cert_pem.as_bytes()).unwrap();
        cert_file.flush().unwrap();

        let output = std::process::Command::new("openssl")
            .args(["x509", "-in", cert_file.path().to_str().unwrap(), "-text", "-noout"])
            .output()
            .expect("Failed to run openssl");

        let text = String::from_utf8_lossy(&output.stdout);

        assert!(
            text.contains("DNS:example.com"),
            "Expected DNS SAN for hostname but got:\n{}",
            text
        );
    }

    #[test]
    fn test_sign_for_hostname_localhost_produces_valid_cert() {
        // This tests the no-SNI fallback path — "localhost" is what
        // DynamicCertResolver uses when no SNI is provided
        let ca = CertificateAuthority::generate().unwrap();
        let (cert_der, key_der) = ca.sign_for_hostname("localhost", None).unwrap();

        assert!(!cert_der.is_empty());
        assert!(!key_der.is_empty());

        // Verify the cert is valid against the CA
        use std::io::Write;
        let cert_pem = der_to_pem(&cert_der, "CERTIFICATE");
        let ca_cert_pem = ca.ca_cert_pem();

        let mut ca_file = tempfile::NamedTempFile::new().unwrap();
        ca_file.write_all(ca_cert_pem.as_bytes()).unwrap();
        ca_file.flush().unwrap();

        let mut cert_file = tempfile::NamedTempFile::new().unwrap();
        cert_file.write_all(cert_pem.as_bytes()).unwrap();
        cert_file.flush().unwrap();

        let output = std::process::Command::new("openssl")
            .args([
                "verify",
                "-CAfile", ca_file.path().to_str().unwrap(),
                cert_file.path().to_str().unwrap(),
            ])
            .output()
            .expect("Failed to run openssl verify");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("OK"),
            "localhost cert should verify against CA:\n{}",
            stdout
        );
    }

    #[test]
    fn test_dynamic_cert_resolver_is_debug_send_sync() {
        // Compile-time check: DynamicCertResolver must be Debug + Send + Sync
        // because ResolvesServerCert requires it
        fn assert_traits<T: std::fmt::Debug + Send + Sync>() {}
        assert_traits::<DynamicCertResolver>();
    }

    #[test]
    fn test_dynamic_cert_resolver_construction() {
        let ca = CertificateAuthority::generate().unwrap();
        let resolver = DynamicCertResolver::new(Arc::new(ca));

        // Verify Debug works
        let debug_str = format!("{:?}", resolver);
        assert!(debug_str.contains("DynamicCertResolver"));
    }

    #[test]
    fn test_certificate_authority_is_debug() {
        let ca = CertificateAuthority::generate().unwrap();
        let debug_str = format!("{:?}", ca);
        assert!(debug_str.contains("CertificateAuthority"));
    }
}

#[cfg(test)]
mod cert_verify_tests {
    use super::*;

    #[test]
    #[ignore = "Requires CA to exist at specific path"]
    fn test_generated_cert_is_valid() {
        use std::fs;
        use std::process::Command;

        // Load CA
        let ca_cert = fs::read_to_string("/Users/mike/.config/gap/ca.crt").unwrap();
        let ca_key = fs::read_to_string("/Users/mike/.config/gap/ca.key").unwrap();

        let ca = CertificateAuthority::from_pem(&ca_cert, &ca_key).unwrap();

        // Generate cert for a test hostname
        let (cert_der, _key_der) = ca.sign_for_hostname("test.example.com", None).unwrap();

        // Save cert and convert to PEM
        fs::write("/tmp/test_cert.der", &cert_der).unwrap();

        let convert = Command::new("openssl")
            .args(&["x509", "-in", "/tmp/test_cert.der", "-inform", "DER", "-out", "/tmp/test_cert.pem"])
            .output()
            .unwrap();

        assert!(convert.status.success(), "Failed to convert to PEM");

        // Verify the certificate against the CA
        let verify = Command::new("openssl")
            .args(&["verify", "-CAfile", "/Users/mike/.config/gap/ca.crt", "/tmp/test_cert.pem"])
            .output()
            .unwrap();

        let verify_output = String::from_utf8_lossy(&verify.stdout);
        let verify_error = String::from_utf8_lossy(&verify.stderr);

        println!("Verify output: {}", verify_output);
        if !verify_error.is_empty() {
            println!("Verify errors: {}", verify_error);
        }

        assert!(
            verify_output.contains("OK"),
            "Certificate verification failed!\nOutput: {}\nError: {}",
            verify_output,
            verify_error
        );
    }

    #[test]
    fn test_signed_cert_verifies_against_original_ca() {
        // This test reproduces the bug: when CA is saved/loaded through PEM,
        // certs signed afterwards should still verify against the original CA cert

        // Step 1: Generate a CA (mimics server startup)
        let ca_original = CertificateAuthority::generate().unwrap();
        let ca_cert_pem = ca_original.ca_cert_pem();
        let ca_key_pem = ca_original.ca_key_pem();

        // Step 2: Wait a bit to ensure time difference
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Step 3: Save and reload the CA (mimics persistence)
        let ca_reloaded = CertificateAuthority::from_pem(&ca_cert_pem, &ca_key_pem).unwrap();

        // Step 4: Sign a server certificate using the RELOADED CA
        let sans = vec!["DNS:localhost".to_string(), "IP:127.0.0.1".to_string()];
        let (cert_der, _key_der) = ca_reloaded.sign_server_cert(&sans).unwrap();

        // Step 5: Write CA cert (from original) and signed cert to temp files
        use std::io::Write;
        let mut ca_file = tempfile::NamedTempFile::new().unwrap();
        ca_file.write_all(ca_cert_pem.as_bytes()).unwrap();
        ca_file.flush().unwrap();

        let mut cert_file = tempfile::NamedTempFile::new().unwrap();
        let cert_pem = der_to_pem(&cert_der, "CERTIFICATE");
        cert_file.write_all(cert_pem.as_bytes()).unwrap();
        cert_file.flush().unwrap();

        // Step 6: Verify the certificate using openssl
        let output = std::process::Command::new("openssl")
            .args(&[
                "verify",
                "-CAfile", ca_file.path().to_str().unwrap(),
                cert_file.path().to_str().unwrap()
            ])
            .output()
            .expect("Failed to run openssl verify");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Debug: print the cert details
        if !output.status.success() || !stdout.contains("OK") {
            eprintln!("Verification failed!");
            eprintln!("stdout: {}", stdout);
            eprintln!("stderr: {}", stderr);

            // Show CA cert details
            let ca_output = std::process::Command::new("openssl")
                .args(&["x509", "-in", ca_file.path().to_str().unwrap(), "-text", "-noout"])
                .output()
                .expect("openssl ca");
            eprintln!("CA cert:\n{}", String::from_utf8_lossy(&ca_output.stdout));

            // Show signed cert details
            let cert_output = std::process::Command::new("openssl")
                .args(&["x509", "-in", cert_file.path().to_str().unwrap(), "-text", "-noout"])
                .output()
                .expect("openssl cert");
            eprintln!("Signed cert:\n{}", String::from_utf8_lossy(&cert_output.stdout));
        }

        // This assertion will FAIL if the bug exists - the reconstructed CA
        // creates a different certificate than the original
        assert!(
            output.status.success() && stdout.contains("OK"),
            "Certificate verification failed!\nstdout: {}\nstderr: {}",
            stdout,
            stderr
        );
    }

    #[test]
    fn test_custom_dn_ca_leaf_issuer_matches_ca_subject() {
        // Generate a CA with custom DN (non-default CN and O)
        // to verify that reconstruct_ca_for_signing() extracts the actual DN
        // rather than using hardcoded values.
        //
        // We create a custom CA using rcgen directly, then load it via from_pem,
        // sign a leaf cert, and verify the leaf's issuer matches the CA's subject.
        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
        use time::{Duration as TimeDuration, OffsetDateTime};

        let key_pair = KeyPair::generate().unwrap();

        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "My Custom CA");
        dn.push(DnType::OrganizationName, "Custom Org");
        dn.push(DnType::CountryName, "NZ");
        params.distinguished_name = dn;

        let now = OffsetDateTime::now_utc();
        params.not_before = now - TimeDuration::minutes(5);
        params.not_after = now + TimeDuration::days(3650);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];

        let cert = params.self_signed(&key_pair).unwrap();
        let ca_cert_pem = cert.pem();
        let ca_key_pem = key_pair.serialize_pem();

        // Load the custom CA
        let ca = CertificateAuthority::from_pem(&ca_cert_pem, &ca_key_pem).unwrap();

        // Sign a leaf certificate
        let (leaf_der, _key_der) = ca.sign_for_hostname("example.com", None).unwrap();

        // Verify the leaf cert's issuer matches the CA's subject using openssl
        use std::io::Write;
        let leaf_pem = der_to_pem(&leaf_der, "CERTIFICATE");

        let mut ca_file = tempfile::NamedTempFile::new().unwrap();
        ca_file.write_all(ca_cert_pem.as_bytes()).unwrap();
        ca_file.flush().unwrap();

        let mut leaf_file = tempfile::NamedTempFile::new().unwrap();
        leaf_file.write_all(leaf_pem.as_bytes()).unwrap();
        leaf_file.flush().unwrap();

        // Get the leaf cert's issuer
        let leaf_output = std::process::Command::new("openssl")
            .args(["x509", "-in", leaf_file.path().to_str().unwrap(), "-issuer", "-noout"])
            .output()
            .expect("Failed to run openssl");
        let leaf_issuer = String::from_utf8_lossy(&leaf_output.stdout);

        // Get the CA cert's subject
        let ca_output = std::process::Command::new("openssl")
            .args(["x509", "-in", ca_file.path().to_str().unwrap(), "-subject", "-noout"])
            .output()
            .expect("Failed to run openssl");
        let ca_subject = String::from_utf8_lossy(&ca_output.stdout);

        // The issuer of the leaf should contain the same DN components as the CA subject
        // openssl outputs "issuer=CN = ..., O = ..., C = ..." and "subject=CN = ..., O = ..., C = ..."
        let issuer_dn = leaf_issuer.trim().strip_prefix("issuer=").unwrap_or(leaf_issuer.trim());
        let subject_dn = ca_subject.trim().strip_prefix("subject=").unwrap_or(ca_subject.trim());

        assert_eq!(
            issuer_dn, subject_dn,
            "Leaf cert issuer DN should match CA subject DN.\nLeaf issuer: {}\nCA subject: {}",
            issuer_dn, subject_dn
        );

        // Also verify the leaf cert is valid against the CA
        let verify_output = std::process::Command::new("openssl")
            .args([
                "verify",
                "-CAfile", ca_file.path().to_str().unwrap(),
                leaf_file.path().to_str().unwrap(),
            ])
            .output()
            .expect("Failed to run openssl verify");
        let stdout = String::from_utf8_lossy(&verify_output.stdout);
        assert!(
            stdout.contains("OK"),
            "Leaf cert should verify against the custom CA:\n{}",
            stdout
        );
    }

    #[test]
    fn test_validate_cert_key_match_success() {
        // Generate a CA and verify that validation passes for matching cert+key
        let ca = CertificateAuthority::generate().unwrap();
        let cert_der = ca.ca_cert_der();
        let key_der = ca.ca_key_der();

        let result = validate_cert_key_match(&cert_der, &key_der);
        assert!(result.is_ok(), "Matching cert+key should validate: {:?}", result.err());
    }

    #[test]
    fn test_validate_cert_key_match_mismatch() {
        // Generate two different CAs and cross their cert+key
        let ca1 = CertificateAuthority::generate().unwrap();
        let ca2 = CertificateAuthority::generate().unwrap();

        let cert_der = ca1.ca_cert_der();
        let key_der = ca2.ca_key_der();

        let result = validate_cert_key_match(&cert_der, &key_der);
        assert!(result.is_err(), "Mismatched cert+key should fail validation");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("do not match"),
            "Error should mention mismatch: {}",
            err_msg
        );
    }
}
