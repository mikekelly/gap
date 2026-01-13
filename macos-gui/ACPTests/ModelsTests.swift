import XCTest
@testable import ACP

final class ModelsTests: XCTestCase {

    // MARK: - StatusResponse Tests

    func testStatusResponseDecoding() throws {
        let json = """
        {
            "version": "0.1.0",
            "uptime_seconds": 3600,
            "proxy_port": 8080,
            "api_port": 9080
        }
        """

        let data = json.data(using: .utf8)!
        let decoder = JSONDecoder()
        let response = try decoder.decode(StatusResponse.self, from: data)

        XCTAssertEqual(response.version, "0.1.0")
        XCTAssertEqual(response.uptimeSeconds, 3600)
        XCTAssertEqual(response.proxyPort, 8080)
        XCTAssertEqual(response.apiPort, 9080)
    }

    // MARK: - Plugin Tests

    func testPluginDecoding() throws {
        let json = """
        {
            "name": "github",
            "match_patterns": ["api.github.com"],
            "credential_schema": ["token"]
        }
        """

        let data = json.data(using: .utf8)!
        let decoder = JSONDecoder()
        let plugin = try decoder.decode(Plugin.self, from: data)

        XCTAssertEqual(plugin.name, "github")
        XCTAssertEqual(plugin.matchPatterns, ["api.github.com"])
        XCTAssertEqual(plugin.credentialSchema, ["token"])
        XCTAssertEqual(plugin.id, "github") // Identifiable conformance
    }

    func testPluginsResponseDecoding() throws {
        let json = """
        {
            "plugins": [
                {
                    "name": "github",
                    "match_patterns": ["api.github.com"],
                    "credential_schema": ["token"]
                }
            ]
        }
        """

        let data = json.data(using: .utf8)!
        let decoder = JSONDecoder()
        let response = try decoder.decode(PluginsResponse.self, from: data)

        XCTAssertEqual(response.plugins.count, 1)
        XCTAssertEqual(response.plugins.first?.name, "github")
    }

    // MARK: - PluginInstallResponse Tests

    func testPluginInstallResponseDecoding() throws {
        let json = """
        {
            "name": "github",
            "installed": true,
            "commit_sha": "abc123"
        }
        """

        let data = json.data(using: .utf8)!
        let decoder = JSONDecoder()
        let response = try decoder.decode(PluginInstallResponse.self, from: data)

        XCTAssertEqual(response.name, "github")
        XCTAssertEqual(response.installed, true)
        XCTAssertNil(response.updated)
        XCTAssertEqual(response.commitSha, "abc123")
    }

    func testPluginUpdateResponseDecoding() throws {
        let json = """
        {
            "name": "github",
            "updated": true,
            "commit_sha": "def456"
        }
        """

        let data = json.data(using: .utf8)!
        let decoder = JSONDecoder()
        let response = try decoder.decode(PluginInstallResponse.self, from: data)

        XCTAssertEqual(response.name, "github")
        XCTAssertNil(response.installed)
        XCTAssertEqual(response.updated, true)
        XCTAssertEqual(response.commitSha, "def456")
    }

    // MARK: - PluginUninstallResponse Tests

    func testPluginUninstallResponseDecoding() throws {
        let json = """
        {
            "name": "github",
            "uninstalled": true
        }
        """

        let data = json.data(using: .utf8)!
        let decoder = JSONDecoder()
        let response = try decoder.decode(PluginUninstallResponse.self, from: data)

        XCTAssertEqual(response.name, "github")
        XCTAssertEqual(response.uninstalled, true)
    }

    // MARK: - Token Tests

    func testTokenDecoding() throws {
        let json = """
        {
            "id": "tok_123",
            "name": "my-token",
            "prefix": "tok_",
            "created_at": "2024-01-01T00:00:00Z"
        }
        """

        let data = json.data(using: .utf8)!
        let decoder = JSONDecoder()
        let token = try decoder.decode(Token.self, from: data)

        XCTAssertEqual(token.id, "tok_123")
        XCTAssertEqual(token.name, "my-token")
        XCTAssertEqual(token.prefix, "tok_")
        XCTAssertNil(token.token) // Token only present in create response
        XCTAssertEqual(token.createdAt, "2024-01-01T00:00:00Z")
    }

    func testTokensResponseDecoding() throws {
        let json = """
        {
            "tokens": [
                {
                    "id": "tok_123",
                    "name": "my-token",
                    "prefix": "tok_",
                    "created_at": "2024-01-01T00:00:00Z"
                }
            ]
        }
        """

        let data = json.data(using: .utf8)!
        let decoder = JSONDecoder()
        let response = try decoder.decode(TokensResponse.self, from: data)

        XCTAssertEqual(response.tokens.count, 1)
        XCTAssertEqual(response.tokens.first?.id, "tok_123")
    }

    // MARK: - TokenCreateResponse Tests

    func testTokenCreateResponseDecoding() throws {
        let json = """
        {
            "id": "tok_123",
            "name": "my-token",
            "prefix": "tok_",
            "token": "tok_123456789abcdef",
            "created_at": "2024-01-01T00:00:00Z"
        }
        """

        let data = json.data(using: .utf8)!
        let decoder = JSONDecoder()
        let response = try decoder.decode(TokenCreateResponse.self, from: data)

        XCTAssertEqual(response.id, "tok_123")
        XCTAssertEqual(response.name, "my-token")
        XCTAssertEqual(response.prefix, "tok_")
        XCTAssertEqual(response.token, "tok_123456789abcdef")
        XCTAssertEqual(response.createdAt, "2024-01-01T00:00:00Z")
    }

    // MARK: - TokenRevokeResponse Tests

    func testTokenRevokeResponseDecoding() throws {
        let json = """
        {
            "id": "tok_123",
            "revoked": true
        }
        """

        let data = json.data(using: .utf8)!
        let decoder = JSONDecoder()
        let response = try decoder.decode(TokenRevokeResponse.self, from: data)

        XCTAssertEqual(response.id, "tok_123")
        XCTAssertEqual(response.revoked, true)
    }

    // MARK: - CredentialSetResponse Tests

    func testCredentialSetResponseDecoding() throws {
        let json = """
        {
            "plugin": "github",
            "key": "token",
            "set": true
        }
        """

        let data = json.data(using: .utf8)!
        let decoder = JSONDecoder()
        let response = try decoder.decode(CredentialSetResponse.self, from: data)

        XCTAssertEqual(response.plugin, "github")
        XCTAssertEqual(response.key, "token")
        XCTAssertEqual(response.set, true)
    }

    // MARK: - ActivityEntry Tests

    func testActivityEntryDecoding() throws {
        let json = """
        {
            "timestamp": "2024-01-01T00:00:00Z",
            "method": "GET",
            "url": "https://api.github.com/user",
            "agent_id": "agent_123",
            "status": 200
        }
        """

        let data = json.data(using: .utf8)!
        let decoder = JSONDecoder()
        let entry = try decoder.decode(ActivityEntry.self, from: data)

        XCTAssertEqual(entry.timestamp, "2024-01-01T00:00:00Z")
        XCTAssertEqual(entry.method, "GET")
        XCTAssertEqual(entry.url, "https://api.github.com/user")
        XCTAssertEqual(entry.agentId, "agent_123")
        XCTAssertEqual(entry.status, 200)
        XCTAssertEqual(entry.id, "2024-01-01T00:00:00Z-https://api.github.com/user") // Identifiable conformance
    }

    func testActivityEntryDecodingWithoutAgentId() throws {
        let json = """
        {
            "timestamp": "2024-01-01T00:00:00Z",
            "method": "POST",
            "url": "https://api.example.com/test",
            "status": 201
        }
        """

        let data = json.data(using: .utf8)!
        let decoder = JSONDecoder()
        let entry = try decoder.decode(ActivityEntry.self, from: data)

        XCTAssertEqual(entry.timestamp, "2024-01-01T00:00:00Z")
        XCTAssertEqual(entry.method, "POST")
        XCTAssertEqual(entry.url, "https://api.example.com/test")
        XCTAssertNil(entry.agentId) // Should be optional
        XCTAssertEqual(entry.status, 201)
    }

    func testActivityResponseDecoding() throws {
        let json = """
        {
            "entries": [
                {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "method": "GET",
                    "url": "https://api.github.com/user",
                    "status": 200
                }
            ]
        }
        """

        let data = json.data(using: .utf8)!
        let decoder = JSONDecoder()
        let response = try decoder.decode(ActivityResponse.self, from: data)

        XCTAssertEqual(response.entries.count, 1)
        XCTAssertEqual(response.entries.first?.method, "GET")
    }
}
