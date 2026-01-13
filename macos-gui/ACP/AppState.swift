import SwiftUI

/// Global application state
///
/// This class manages:
/// - Password hash (in memory only)
/// - Connection status to acp-server
/// - Current data (plugins, tokens, activity)
///
/// All authenticated operations require the password hash to be set.
/// The hash is verified on first use and stored in memory.
@MainActor
class AppState: ObservableObject {
    @Published var passwordHash: String?
    @Published var isConnected: Bool = false
    @Published var connectionError: String?

    @Published var plugins: [Plugin] = []
    @Published var tokens: [Token] = []
    @Published var activity: [ActivityEntry] = []

    let client = ACPClient()

    /// Whether the user has successfully authenticated
    var isAuthenticated: Bool { passwordHash != nil }

    /// Authenticate with a password by hashing and verifying against the API.
    ///
    /// - Parameter password: Plain text password
    /// - Throws: ACPError if authentication fails
    func authenticate(password: String) async throws {
        let hash = hashPassword(password)
        // Verify by calling an authenticated endpoint
        _ = try await client.getPlugins(passwordHash: hash)
        self.passwordHash = hash
        self.isConnected = true
        self.connectionError = nil
    }

    /// Refresh the list of installed plugins from the server.
    ///
    /// - Throws: ACPError if the request fails
    func refreshPlugins() async throws {
        guard let hash = passwordHash else { return }
        let response = try await client.getPlugins(passwordHash: hash)
        self.plugins = response.plugins
    }

    /// Refresh the list of agent tokens from the server.
    ///
    /// - Throws: ACPError if the request fails
    func refreshTokens() async throws {
        guard let hash = passwordHash else { return }
        let response = try await client.getTokens(passwordHash: hash)
        self.tokens = response.tokens
    }

    /// Refresh the activity log from the server.
    ///
    /// - Throws: ACPError if the request fails
    func refreshActivity() async throws {
        guard let hash = passwordHash else { return }
        let response = try await client.getActivity(passwordHash: hash)
        self.activity = response.entries
    }

    /// Log out and clear all state.
    func logout() {
        passwordHash = nil
        isConnected = false
        plugins = []
        tokens = []
        activity = []
    }
}
