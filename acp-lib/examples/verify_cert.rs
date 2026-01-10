use acp_lib::tls::CertificateAuthority;
use std::fs;
use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ca_cert = fs::read_to_string("/tmp/ca_test.crt")?;
    let ca_key = fs::read_to_string("/tmp/ca_test.key")?;

    let ca = CertificateAuthority::from_pem(&ca_cert, &ca_key)?;

    println!("Generating certificate for test.example.com...");
    let (cert_der, _key_der) = ca.sign_for_hostname("test.example.com", None)?;

    fs::write("/tmp/test_cert.der", &cert_der)?;
    println!("Saved certificate to /tmp/test_cert.der");

    // Convert to PEM
    let convert = Command::new("openssl")
        .args(&["x509", "-in", "/tmp/test_cert.der", "-inform", "DER", "-out", "/tmp/test_cert.pem"])
        .output()?;

    if !convert.status.success() {
        eprintln!("Failed to convert: {}", String::from_utf8_lossy(&convert.stderr));
        std::process::exit(1);
    }
    println!("Converted to PEM: /tmp/test_cert.pem");

    // Display certificate info
    println!("\n=== Certificate Info ===");
    let info = Command::new("openssl")
        .args(&["x509", "-in", "/tmp/test_cert.pem", "-text", "-noout"])
        .output()?;
    println!("{}", String::from_utf8_lossy(&info.stdout));

    // Verify
    println!("\n=== Verification ===");
    let verify = Command::new("openssl")
        .args(&["verify", "-CAfile", "/tmp/ca_test.crt", "/tmp/test_cert.pem"])
        .output()?;

    let verify_out = String::from_utf8_lossy(&verify.stdout);
    let verify_err = String::from_utf8_lossy(&verify.stderr);

    println!("{}", verify_out);
    if !verify_err.is_empty() {
        println!("Errors: {}", verify_err);
    }

    if verify_out.contains("OK") {
        println!("\n SUCCESS: Certificate is valid!");
    } else {
        println!("\n FAILED: Certificate verification failed");
        std::process::exit(1);
    }

    Ok(())
}
