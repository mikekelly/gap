import Foundation

// MARK: - Status Response

/// Response from GET /status
struct StatusResponse: Codable {
    let version: String
    let uptimeSeconds: Int
    let proxyPort: Int
    let apiPort: Int
    let initialized: Bool

    enum CodingKeys: String, CodingKey {
        case version
        case uptimeSeconds = "uptime_seconds"
        case proxyPort = "proxy_port"
        case apiPort = "api_port"
        case initialized
    }
}

/// Response from POST /init
struct InitResponse: Codable {
    let caPath: String

    enum CodingKeys: String, CodingKey {
        case caPath = "ca_path"
    }
}

// MARK: - Plugin Models

/// Response from POST /plugins
struct PluginsResponse: Codable {
    let plugins: [Plugin]
}

/// A plugin with match patterns and credential schema
struct Plugin: Codable, Identifiable {
    let name: String
    let matchPatterns: [String]
    let credentialSchema: [String]

    var id: String { name }

    enum CodingKeys: String, CodingKey {
        case name
        case matchPatterns = "match_patterns"
        case credentialSchema = "credential_schema"
    }
}

/// Response from POST /plugins/install, POST /plugins/:name/update
struct PluginInstallResponse: Codable {
    let name: String
    let installed: Bool?
    let updated: Bool?
    let commitSha: String?

    enum CodingKeys: String, CodingKey {
        case name
        case installed
        case updated
        case commitSha = "commit_sha"
    }
}

/// Response from DELETE /plugins/:name
struct PluginUninstallResponse: Codable {
    let name: String
    let uninstalled: Bool
}

// MARK: - Token Models

/// Response from POST /tokens
struct TokensResponse: Codable {
    let tokens: [Token]
}

/// A bearer token for agent authentication
struct Token: Codable, Identifiable {
    let id: String
    let name: String
    let prefix: String
    let token: String?
    let createdAt: String

    enum CodingKeys: String, CodingKey {
        case id, name, prefix, token
        case createdAt = "created_at"
    }
}

/// Response from POST /tokens/create
struct TokenCreateResponse: Codable {
    let id: String
    let name: String
    let prefix: String
    let token: String
    let createdAt: String

    enum CodingKeys: String, CodingKey {
        case id, name, prefix, token
        case createdAt = "created_at"
    }
}

/// Response from DELETE /tokens/:id
struct TokenRevokeResponse: Codable {
    let id: String
    let revoked: Bool
}

// MARK: - Credential Models

/// Response from POST /credentials/:plugin/:key
struct CredentialSetResponse: Codable {
    let plugin: String
    let key: String
    let set: Bool
}

// MARK: - Management Log Models

/// Response from GET /management-log
struct ManagementLogResponse: Codable {
    let entries: [ManagementLogEntry]
}

/// A single management log entry recording an administrative operation
struct ManagementLogEntry: Codable, Identifiable {
    var id: String { "\(timestamp)-\(operation)" }

    let timestamp: String
    let operation: String
    let resourceType: String
    let resourceId: String?
    let detail: String?
    let success: Bool
    let errorMessage: String?

    enum CodingKeys: String, CodingKey {
        case timestamp, operation, success, detail
        case resourceType = "resource_type"
        case resourceId = "resource_id"
        case errorMessage = "error_message"
    }
}

// MARK: - Activity Models

/// Response from POST /activity
struct ActivityResponse: Codable {
    let entries: [ActivityEntry]
}

/// A single activity log entry
struct ActivityEntry: Codable, Identifiable {
    let timestamp: String
    let requestId: String?
    let method: String
    let url: String
    let agentId: String?
    let status: Int
    let pluginName: String?
    let pluginSha: String?
    let sourceHash: String?
    let requestHeaders: String?
    let rejectionStage: String?
    let rejectionReason: String?

    var id: String { "\(timestamp)-\(url)-\(requestId ?? "")" }

    enum CodingKeys: String, CodingKey {
        case timestamp, method, url, status
        case requestId = "request_id"
        case agentId = "agent_id"
        case pluginName = "plugin_name"
        case pluginSha = "plugin_sha"
        case sourceHash = "source_hash"
        case requestHeaders = "request_headers"
        case rejectionStage = "rejection_stage"
        case rejectionReason = "rejection_reason"
    }
}

/// Detailed request/response data for a single proxied request
struct RequestDetails: Codable {
    let requestId: String
    // Pre-transform (incoming from agent)
    let reqHeaders: String?
    let reqBody: [UInt8]?
    // Post-transform (after plugin, scrubbed)
    let transformedUrl: String?
    let transformedHeaders: String?
    let transformedBody: [UInt8]?
    // Origin response (scrubbed)
    let responseStatus: Int?
    let responseHeaders: String?
    let responseBody: [UInt8]?
    // Metadata
    let bodyTruncated: Bool

    enum CodingKeys: String, CodingKey {
        case requestId = "request_id"
        case reqHeaders = "req_headers"
        case reqBody = "req_body"
        case transformedUrl = "transformed_url"
        case transformedHeaders = "transformed_headers"
        case transformedBody = "transformed_body"
        case responseStatus = "response_status"
        case responseHeaders = "response_headers"
        case responseBody = "response_body"
        case bodyTruncated = "body_truncated"
    }

    /// Get req_body as a UTF-8 string (or hex for binary)
    var reqBodyString: String? {
        guard let bytes = reqBody, !bytes.isEmpty else { return nil }
        return String(bytes: bytes, encoding: .utf8) ?? "<binary \(bytes.count) bytes>"
    }

    /// Get transformed_body as a UTF-8 string (or hex for binary)
    var transformedBodyString: String? {
        guard let bytes = transformedBody, !bytes.isEmpty else { return nil }
        return String(bytes: bytes, encoding: .utf8) ?? "<binary \(bytes.count) bytes>"
    }

    /// Get response_body as a UTF-8 string (or hex for binary)
    var responseBodyString: String? {
        guard let bytes = responseBody, !bytes.isEmpty else { return nil }
        return String(bytes: bytes, encoding: .utf8) ?? "<binary \(bytes.count) bytes>"
    }
}

/// Filter parameters for activity search queries
struct ActivityFilter {
    var domain: String = ""
    var method: String = ""
    var plugin: String = ""
    var path: String = ""
    var agent: String = ""
    var requestId: String = ""
    var limit: Int = 100
    var since: Date? = nil

    var queryItems: [URLQueryItem] {
        var items: [URLQueryItem] = []
        if !domain.isEmpty { items.append(.init(name: "domain", value: domain)) }
        if !method.isEmpty { items.append(.init(name: "method", value: method)) }
        if !plugin.isEmpty { items.append(.init(name: "plugin", value: plugin)) }
        if !path.isEmpty { items.append(.init(name: "path", value: path)) }
        if !agent.isEmpty { items.append(.init(name: "agent", value: agent)) }
        if !requestId.isEmpty { items.append(.init(name: "request_id", value: requestId)) }
        items.append(.init(name: "limit", value: "\(limit)"))
        if let since = since {
            let formatter = ISO8601DateFormatter()
            items.append(.init(name: "since", value: formatter.string(from: since)))
        }
        return items
    }
}

/// Filter parameters for activity SSE stream
struct ActivityStreamFilter {
    var domain: String = ""
    var method: String = ""
    var plugin: String = ""

    var queryItems: [URLQueryItem] {
        var items: [URLQueryItem] = []
        if !domain.isEmpty { items.append(.init(name: "domain", value: domain)) }
        if !method.isEmpty { items.append(.init(name: "method", value: method)) }
        if !plugin.isEmpty { items.append(.init(name: "plugin", value: plugin)) }
        return items
    }
}
