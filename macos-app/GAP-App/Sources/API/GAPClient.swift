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
/// All authenticated endpoints require an `Authorization: Bearer <hash>` header.
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
        return try await authenticatedGet("/plugins", passwordHash: passwordHash)
    }

    /// Install a plugin from a GitHub repository.
    ///
    /// - Parameters:
    ///   - repo: GitHub repository in "owner/repo" format
    ///   - passwordHash: SHA512 hash of the password
    /// - Returns: PluginInstallResponse with installation status
    /// - Throws: GAPError if the request fails or authentication fails
    func installPlugin(repo: String, passwordHash: String) async throws -> PluginInstallResponse {
        return try await authenticatedPost("/plugins/install", body: ["name": repo], passwordHash: passwordHash)
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
        return try await authenticatedPost("/plugins/\(encodedName)/update", body: nil, passwordHash: passwordHash)
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
        return try await authenticatedDelete("/plugins/\(encodedName)", passwordHash: passwordHash)
    }

    // MARK: - Token Endpoints (Authenticated)

    /// List all agent tokens.
    ///
    /// - Parameter passwordHash: SHA512 hash of the password
    /// - Returns: TokensResponse containing array of tokens
    /// - Throws: GAPError if the request fails or authentication fails
    func getTokens(passwordHash: String) async throws -> TokensResponse {
        return try await authenticatedGet("/tokens", passwordHash: passwordHash)
    }

    /// Create a new agent token.
    ///
    /// - Parameters:
    ///   - name: Human-readable name for the token
    ///   - passwordHash: SHA512 hash of the password
    /// - Returns: TokenCreateResponse with the full token value (only shown once)
    /// - Throws: GAPError if the request fails or authentication fails
    func createToken(name: String, passwordHash: String) async throws -> TokenCreateResponse {
        return try await authenticatedPost("/tokens/create", body: ["name": name], passwordHash: passwordHash)
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
        return try await authenticatedDelete("/tokens/\(encodedId)", passwordHash: passwordHash)
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
        return try await authenticatedPost("/credentials/\(encodedPlugin)/\(encodedKey)", body: ["value": value], passwordHash: passwordHash)
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
        let _: EmptyResponse = try await authenticatedDelete("/credentials/\(encodedPlugin)/\(encodedKey)", passwordHash: passwordHash)
    }

    // MARK: - Activity Endpoints (Authenticated)

    /// Get recent activity log entries.
    ///
    /// - Parameter passwordHash: SHA512 hash of the password
    /// - Returns: ActivityResponse containing array of activity entries
    /// - Throws: GAPError if the request fails or authentication fails
    func getActivity(passwordHash: String) async throws -> ActivityResponse {
        return try await authenticatedGet("/activity", passwordHash: passwordHash)
    }

    /// Get filtered activity log entries.
    ///
    /// - Parameters:
    ///   - passwordHash: SHA512 hash of the password
    ///   - filter: ActivityFilter with search parameters
    /// - Returns: ActivityResponse containing matching activity entries
    /// - Throws: GAPError if the request fails or authentication fails
    func getActivityFiltered(passwordHash: String, filter: ActivityFilter) async throws -> ActivityResponse {
        var components = URLComponents(url: baseURL.appendingPathComponent("activity"), resolvingAgainstBaseURL: false)!
        components.queryItems = filter.queryItems

        var request = URLRequest(url: components.url!)
        request.httpMethod = "GET"
        request.setValue("Bearer \(passwordHash)", forHTTPHeaderField: "Authorization")

        return try await performRequest(request)
    }

    /// Get detailed request/response data for a specific request.
    ///
    /// - Parameters:
    ///   - requestId: The request correlation ID
    ///   - passwordHash: SHA512 hash of the password
    /// - Returns: RequestDetails with pre-transform, post-transform, and response data
    /// - Throws: GAPError if the request fails or request not found (404)
    func getRequestDetails(requestId: String, passwordHash: String) async throws -> RequestDetails {
        return try await authenticatedGet("/activity/\(requestId)/details", passwordHash: passwordHash)
    }

    /// Connect to the activity SSE stream.
    ///
    /// Returns an AsyncThrowingStream that yields ActivityEntry values as they
    /// arrive from the server-sent events endpoint.
    ///
    /// - Parameters:
    ///   - passwordHash: SHA512 hash of the password
    ///   - filter: Optional stream filter parameters
    /// - Returns: AsyncThrowingStream of ActivityEntry values
    func activityStream(passwordHash: String, filter: ActivityStreamFilter? = nil) -> AsyncThrowingStream<ActivityEntry, Error> {
        AsyncThrowingStream { continuation in
            let task = Task {
                do {
                    var components = URLComponents(url: baseURL.appendingPathComponent("activity/stream"), resolvingAgainstBaseURL: false)!
                    if let filter = filter {
                        components.queryItems = filter.queryItems
                    }

                    var request = URLRequest(url: components.url!)
                    request.httpMethod = "GET"
                    request.setValue("Bearer \(passwordHash)", forHTTPHeaderField: "Authorization")

                    let (bytes, _) = try await session.bytes(for: request)
                    for try await line in bytes.lines {
                        if Task.isCancelled { break }
                        if line.hasPrefix("data: ") {
                            let jsonStr = String(line.dropFirst(6))
                            if let data = jsonStr.data(using: .utf8),
                               let entry = try? JSONDecoder().decode(ActivityEntry.self, from: data) {
                                continuation.yield(entry)
                            }
                        }
                    }
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }

            continuation.onTermination = { _ in
                task.cancel()
            }
        }
    }

    // MARK: - Management Log Endpoint (Authenticated)

    /// Get management log entries with optional filters.
    ///
    /// - Parameters:
    ///   - passwordHash: SHA512 hash of the password
    ///   - operation: Filter by operation type (e.g., "create_token")
    ///   - resourceType: Filter by resource type (e.g., "token", "plugin")
    ///   - resourceId: Filter by resource ID
    ///   - limit: Maximum number of entries to return
    /// - Returns: ManagementLogResponse containing matching log entries
    /// - Throws: GAPError if the request fails or authentication fails
    func getManagementLog(passwordHash: String, operation: String? = nil, resourceType: String? = nil, resourceId: String? = nil, limit: Int? = nil) async throws -> ManagementLogResponse {
        var components = URLComponents(url: baseURL.appendingPathComponent("management-log"), resolvingAgainstBaseURL: false)!
        var queryItems: [URLQueryItem] = []
        if let operation = operation { queryItems.append(.init(name: "operation", value: operation)) }
        if let resourceType = resourceType { queryItems.append(.init(name: "resource_type", value: resourceType)) }
        if let resourceId = resourceId { queryItems.append(.init(name: "resource_id", value: resourceId)) }
        if let limit = limit { queryItems.append(.init(name: "limit", value: "\(limit)")) }
        if !queryItems.isEmpty { components.queryItems = queryItems }

        var request = URLRequest(url: components.url!)
        request.httpMethod = "GET"
        request.setValue("Bearer \(passwordHash)", forHTTPHeaderField: "Authorization")

        return try await performRequest(request)
    }

    // MARK: - Private Helper Methods

    /// Perform an unauthenticated GET request.
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

    /// Perform an unauthenticated POST request with JSON body.
    ///
    /// Used only for the /init endpoint which sends password_hash in the body.
    ///
    /// - Parameters:
    ///   - path: API path (e.g., "/init")
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

    /// Perform an authenticated GET request with Bearer token header.
    ///
    /// - Parameters:
    ///   - path: API path (e.g., "/plugins")
    ///   - passwordHash: SHA512 hash of the password for the Authorization header
    /// - Returns: Decoded response of type T
    /// - Throws: GAPError if the request fails
    private func authenticatedGet<T: Decodable>(_ path: String, passwordHash: String) async throws -> T {
        guard let url = URL(string: path, relativeTo: baseURL) else {
            throw GAPError.invalidURL
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("Bearer \(passwordHash)", forHTTPHeaderField: "Authorization")

        return try await performRequest(request)
    }

    /// Perform an authenticated POST request with Bearer token header and optional JSON body.
    ///
    /// - Parameters:
    ///   - path: API path (e.g., "/plugins/install")
    ///   - body: Optional dictionary to encode as JSON (request data only, no password_hash)
    ///   - passwordHash: SHA512 hash of the password for the Authorization header
    /// - Returns: Decoded response of type T
    /// - Throws: GAPError if the request fails
    private func authenticatedPost<T: Decodable>(_ path: String, body: [String: Any]?, passwordHash: String) async throws -> T {
        guard let url = URL(string: path, relativeTo: baseURL) else {
            throw GAPError.invalidURL
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("Bearer \(passwordHash)", forHTTPHeaderField: "Authorization")

        if let body = body {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            do {
                request.httpBody = try JSONSerialization.data(withJSONObject: body)
            } catch {
                throw GAPError.networkError(error)
            }
        }

        return try await performRequest(request)
    }

    /// Perform an authenticated DELETE request with Bearer token header.
    ///
    /// - Parameters:
    ///   - path: API path (e.g., "/plugins/name")
    ///   - passwordHash: SHA512 hash of the password for the Authorization header
    /// - Returns: Decoded response of type T
    /// - Throws: GAPError if the request fails
    private func authenticatedDelete<T: Decodable>(_ path: String, passwordHash: String) async throws -> T {
        guard let url = URL(string: path, relativeTo: baseURL) else {
            throw GAPError.invalidURL
        }

        var request = URLRequest(url: url)
        request.httpMethod = "DELETE"
        request.setValue("Bearer \(passwordHash)", forHTTPHeaderField: "Authorization")

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
