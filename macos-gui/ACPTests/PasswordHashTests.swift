import XCTest
@testable import ACP

/// Tests for SHA512 password hashing.
///
/// The hash function must produce identical output to the CLI's Rust implementation,
/// which uses SHA512 with no salt. This ensures password verification works across
/// the macOS GUI and CLI.
final class PasswordHashTests: XCTestCase {

    /// Test that empty string hashes correctly.
    ///
    /// Known hash generated via: echo -n "" | shasum -a 512
    func testEmptyStringHash() {
        let expected = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        let result = hashPassword("")
        XCTAssertEqual(result, expected, "Empty string should hash to known SHA512 value")
    }

    /// Test that "test" hashes correctly.
    ///
    /// Known hash generated via: echo -n "test" | shasum -a 512
    func testSimplePasswordHash() {
        let expected = "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff"
        let result = hashPassword("test")
        XCTAssertEqual(result, expected, "Password 'test' should hash to known SHA512 value")
    }

    /// Test that output format is always 128 lowercase hex characters.
    ///
    /// SHA512 produces 512 bits = 64 bytes = 128 hex characters.
    func testOutputFormat() {
        let result = hashPassword("any password")
        XCTAssertEqual(result.count, 128, "Hash should be exactly 128 characters (64 bytes as hex)")
        XCTAssertTrue(result.allSatisfy { $0.isHexDigit && ($0.isLowercase || $0.isNumber) },
                     "Hash should contain only lowercase hex characters")
    }

    /// Test that same input always produces same output (determinism).
    ///
    /// Critical for password verification to work reliably.
    func testDeterminism() {
        let password = "consistent"
        let hash1 = hashPassword(password)
        let hash2 = hashPassword(password)
        XCTAssertEqual(hash1, hash2, "Same password should always produce same hash")
    }
}
