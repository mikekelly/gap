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

    var id: String { "\(timestamp)-\(url)-\(requestId ?? "")" }

    enum CodingKeys: String, CodingKey {
        case timestamp, method, url, status
        case requestId = "request_id"
        case agentId = "agent_id"
        case pluginName = "plugin_name"
        case pluginSha = "plugin_sha"
        case sourceHash = "source_hash"
        case requestHeaders = "request_headers"
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
