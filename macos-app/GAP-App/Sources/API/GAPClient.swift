import Foundation

// MARK: - GAPError

/// Errors that can occur when communicating with the Management API.
enum GAPError: Error, LocalizedError {
    case invalidURL
    case networkError(Error)
    case httpError(Int, String)
    case decodingError(Error)
    case unauthorized

    var errorDescription: String? {
        switch self {
        case .invalidURL:
            return "Invalid URL: Unable to construct valid URL for API request"
        case .networkError(let error):
            return "Network error: \(error.localizedDescription)"
        case .httpError(let code, let message):
            return "HTTP error \(code): \(message)"
        case .decodingError(let error):
            return "Failed to decode response: \(error.localizedDescription)"
        case .unauthorized:
            return "Unauthorized: Invalid password or insufficient permissions"
        }
    }
}

// MARK: - GAPClient

/// URLSession-based client for the GAP Management API.
///
/// All authenticated endpoints require a password hash in the request body.
/// The client trusts self-signed certificates from localhost to work with
/// the GAP server's self-signed CA.
///
/// Example usage:
/// ```swift
/// let client = GAPClient()
/// let passwordHash = hashPassword("my-password")
///
/// // Check server status (no auth required)
/// let status = try await client.getStatus()
///
/// // List plugins (auth required)
/// let plugins = try await client.getPlugins(passwordHash: passwordHash)
/// ```
class GAPClient {
    private let baseURL: URL
    private let session: URLSession

    /// Initialize a new GAPClient.
    ///
    /// - Parameter baseURL: The base URL for the Management API (default: https://localhost:9080)
    init(baseURL: URL = URL(string: "https://localhost:9080")!) {
        self.baseURL = baseURL
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 30
        self.session = URLSession(
            configuration: config,
            delegate: TrustDelegate(),
            delegateQueue: nil
        )
    }

    // MARK: - Status Endpoint (Unauthenticated)

    /// Get server status information.
    ///
    /// This endpoint does not require authentication.
    ///
    /// - Returns: StatusResponse with version, uptime, and port information
    /// - Throws: GAPError if the request fails
    func getStatus() async throws -> StatusResponse {
        return try await get("/status")
    }

    // MARK: - Initialization Endpoint (Unauthenticated)

    /// Initialize the server with a password.
    ///
    /// This endpoint does not require authentication but can only be called once.
    /// After initialization, all other endpoints require the password hash.
    ///
    /// - Parameter passwordHash: SHA512 hash of the password (hex encoded)
    /// - Returns: InitResponse with CA certificate path
    /// - Throws: GAPError if the request fails or server is already initialized
    func initServer(passwordHash: String) async throws -> InitResponse {
        let body: [String: Any] = ["password_hash": passwordHash]
        return try await post("/init", body: body)
    }

    // MARK: - Plugin Endpoints (Authenticated)

    /// List all installed plugins.
    ///
    /// - Parameter passwordHash: SHA512 hash of the password
    /// - Returns: PluginsResponse containing array of installed plugins
    /// - Throws: GAPError if the request fails or authentication fails
    func getPlugins(passwordHash: String) async throws -> PluginsResponse {
        return try await post("/plugins", body: ["password_hash": passwordHash])
    }

    /// Install a plugin from a GitHub repository.
    ///
    /// - Parameters:
    ///   - repo: GitHub repository in "owner/repo" format
    ///   - passwordHash: SHA512 hash of the password
    /// - Returns: PluginInstallResponse with installation status
    /// - Throws: GAPError if the request fails or authentication fails
    func installPlugin(repo: String, passwordHash: String) async throws -> PluginInstallResponse {
        return try await post("/plugins/install", body: [
            "name": repo,
            "password_hash": passwordHash
        ])
    }

    /// Update an installed plugin to the latest version.
    ///
    /// - Parameters:
    ///   - name: Plugin name (will be URL-encoded)
    ///   - passwordHash: SHA512 hash of the password
    /// - Returns: PluginInstallResponse with update status
    /// - Throws: GAPError if the request fails or authentication fails
    func updatePlugin(name: String, passwordHash: String) async throws -> PluginInstallResponse {
        // Use alphanumerics only to ensure / is encoded (plugin names like "mikekelly/exa-gap")
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-_.")
        guard let encodedName = name.addingPercentEncoding(withAllowedCharacters: allowed) else {
            throw GAPError.invalidURL
        }
        return try await post("/plugins/\(encodedName)/update", body: ["password_hash": passwordHash])
    }

    /// Uninstall a plugin.
    ///
    /// - Parameters:
    ///   - name: Plugin name (will be URL-encoded)
    ///   - passwordHash: SHA512 hash of the password
    /// - Returns: PluginUninstallResponse with uninstall status
    /// - Throws: GAPError if the request fails or authentication fails
    func uninstallPlugin(name: String, passwordHash: String) async throws -> PluginUninstallResponse {
        // Use alphanumerics only to ensure / is encoded (plugin names like "mikekelly/exa-gap")
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-_.")
        guard let encodedName = name.addingPercentEncoding(withAllowedCharacters: allowed) else {
            throw GAPError.invalidURL
        }
        return try await delete("/plugins/\(encodedName)", body: ["password_hash": passwordHash])
    }

    // MARK: - Token Endpoints (Authenticated)

    /// List all agent tokens.
    ///
    /// - Parameter passwordHash: SHA512 hash of the password
    /// - Returns: TokensResponse containing array of tokens
    /// - Throws: GAPError if the request fails or authentication fails
    func getTokens(passwordHash: String) async throws -> TokensResponse {
        return try await post("/tokens", body: ["password_hash": passwordHash])
    }

    /// Create a new agent token.
    ///
    /// - Parameters:
    ///   - name: Human-readable name for the token
    ///   - passwordHash: SHA512 hash of the password
    /// - Returns: TokenCreateResponse with the full token value (only shown once)
    /// - Throws: GAPError if the request fails or authentication fails
    func createToken(name: String, passwordHash: String) async throws -> TokenCreateResponse {
        return try await post("/tokens/create", body: [
            "name": name,
            "password_hash": passwordHash
        ])
    }

    /// Revoke an agent token.
    ///
    /// - Parameters:
    ///   - id: Token ID to revoke
    ///   - passwordHash: SHA512 hash of the password
    /// - Returns: TokenRevokeResponse with revocation status
    /// - Throws: GAPError if the request fails or authentication fails
    func revokeToken(id: String, passwordHash: String) async throws -> TokenRevokeResponse {
        // Use alphanumerics only to ensure / is encoded
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-_.")
        guard let encodedId = id.addingPercentEncoding(withAllowedCharacters: allowed) else {
            throw GAPError.invalidURL
        }
        return try await delete("/tokens/\(encodedId)", body: ["password_hash": passwordHash])
    }

    // MARK: - Credential Endpoints (Authenticated)

    /// Set a credential for a plugin.
    ///
    /// - Parameters:
    ///   - plugin: Plugin name (will be URL-encoded)
    ///   - key: Credential key (will be URL-encoded)
    ///   - value: Credential value
    ///   - passwordHash: SHA512 hash of the password
    /// - Returns: CredentialSetResponse with set status
    /// - Throws: GAPError if the request fails or authentication fails
    func setCredential(plugin: String, key: String, value: String, passwordHash: String) async throws -> CredentialSetResponse {
        // Use alphanumerics only to ensure / is encoded (plugin names like "mikekelly/exa-gap")
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-_.")
        guard let encodedPlugin = plugin.addingPercentEncoding(withAllowedCharacters: allowed),
              let encodedKey = key.addingPercentEncoding(withAllowedCharacters: allowed) else {
            throw GAPError.invalidURL
        }
        return try await post("/credentials/\(encodedPlugin)/\(encodedKey)", body: [
            "value": value,
            "password_hash": passwordHash
        ])
    }

    /// Delete a credential for a plugin.
    ///
    /// - Parameters:
    ///   - plugin: Plugin name (will be URL-encoded)
    ///   - key: Credential key (will be URL-encoded)
    ///   - passwordHash: SHA512 hash of the password
    /// - Throws: GAPError if the request fails or authentication fails
    func deleteCredential(plugin: String, key: String, passwordHash: String) async throws {
        // Use alphanumerics only to ensure / is encoded (plugin names like "mikekelly/exa-gap")
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-_.")
        guard let encodedPlugin = plugin.addingPercentEncoding(withAllowedCharacters: allowed),
              let encodedKey = key.addingPercentEncoding(withAllowedCharacters: allowed) else {
            throw GAPError.invalidURL
        }
        // DELETE returns 204 No Content, so we just verify success without decoding a response
        let _: EmptyResponse = try await delete("/credentials/\(encodedPlugin)/\(encodedKey)", body: ["password_hash": passwordHash])
    }

    // MARK: - Activity Endpoint (Authenticated)

    /// Get recent activity log entries.
    ///
    /// - Parameter passwordHash: SHA512 hash of the password
    /// - Returns: ActivityResponse containing array of activity entries
    /// - Throws: GAPError if the request fails or authentication fails
    func getActivity(passwordHash: String) async throws -> ActivityResponse {
        return try await post("/activity", body: ["password_hash": passwordHash])
    }

    // MARK: - Private Helper Methods

    /// Perform a GET request.
    ///
    /// - Parameter path: API path (e.g., "/status")
    /// - Returns: Decoded response of type T
    /// - Throws: GAPError if the request fails
    private func get<T: Decodable>(_ path: String) async throws -> T {
        guard let url = URL(string: path, relativeTo: baseURL) else {
            throw GAPError.invalidURL
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"

        return try await performRequest(request)
    }

    /// Perform a POST request with JSON body.
    ///
    /// - Parameters:
    ///   - path: API path (e.g., "/plugins")
    ///   - body: Dictionary to encode as JSON
    /// - Returns: Decoded response of type T
    /// - Throws: GAPError if the request fails
    private func post<T: Decodable>(_ path: String, body: [String: Any]) async throws -> T {
        guard let url = URL(string: path, relativeTo: baseURL) else {
            throw GAPError.invalidURL
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
        } catch {
            throw GAPError.networkError(error)
        }

        return try await performRequest(request)
    }

    /// Perform a DELETE request with JSON body.
    ///
    /// - Parameters:
    ///   - path: API path (e.g., "/plugins/name")
    ///   - body: Dictionary to encode as JSON
    /// - Returns: Decoded response of type T
    /// - Throws: GAPError if the request fails
    private func delete<T: Decodable>(_ path: String, body: [String: Any]) async throws -> T {
        guard let url = URL(string: path, relativeTo: baseURL) else {
            throw GAPError.invalidURL
        }

        var request = URLRequest(url: url)
        request.httpMethod = "DELETE"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        do {
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
        } catch {
            throw GAPError.networkError(error)
        }

        return try await performRequest(request)
    }

    /// Execute a URLRequest and decode the response.
    ///
    /// - Parameter request: URLRequest to execute
    /// - Returns: Decoded response of type T
    /// - Throws: GAPError if the request fails
    private func performRequest<T: Decodable>(_ request: URLRequest) async throws -> T {
        let (data, response) = try await session.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw GAPError.networkError(NSError(domain: "GAPClient", code: -1, userInfo: [
                NSLocalizedDescriptionKey: "Invalid response type"
            ]))
        }

        // Handle HTTP errors
        guard (200...299).contains(httpResponse.statusCode) else {
            if httpResponse.statusCode == 401 {
                throw GAPError.unauthorized
            }

            let message = String(data: data, encoding: .utf8) ?? "Unknown error"
            throw GAPError.httpError(httpResponse.statusCode, message)
        }

        // Handle empty responses (e.g., 204 No Content)
        if data.isEmpty && T.self == EmptyResponse.self {
            return EmptyResponse() as! T
        }

        // Decode JSON response
        do {
            let decoder = JSONDecoder()
            return try decoder.decode(T.self, from: data)
        } catch {
            throw GAPError.decodingError(error)
        }
    }
}

// MARK: - TrustDelegate

/// URLSessionDelegate that trusts self-signed certificates from localhost.
///
/// The GAP server uses a self-signed CA for HTTPS. This delegate allows
/// the client to connect without certificate validation failures when
/// connecting to localhost.
///
/// Security note: This only trusts localhost, not arbitrary hosts.
class TrustDelegate: NSObject, URLSessionDelegate {
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge
    ) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        // Only trust localhost
        if challenge.protectionSpace.host == "localhost",
           let trust = challenge.protectionSpace.serverTrust {
            return (.useCredential, URLCredential(trust: trust))
        }
        return (.performDefaultHandling, nil)
    }
}

// MARK: - EmptyResponse

/// Empty response type for endpoints that return 204 No Content.
private struct EmptyResponse: Codable {
    init() {}
}
