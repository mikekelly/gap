import Combine
import SwiftUI

/// Global application state
///
/// This class manages:
/// - Server lifecycle (via ServerManager)
/// - Password hash (in memory only)
/// - Connection status to gap-server
/// - Current data (plugins, tokens, activity)
///
/// All authenticated operations require both the server to be running and
/// the password hash to be set. The hash is verified on first use and stored in memory.
@MainActor
class AppState: ObservableObject {
    @Published var serverManager: ServerManager
    @Published var passwordHash: String?
    @Published var isConnected: Bool = false
    @Published var connectionError: String?
    @Published var serverInitialized: Bool = false

    @Published var plugins: [Plugin] = []
    @Published var tokens: [Token] = []
    @Published var activity: [ActivityEntry] = []
    @Published var managementLog: [ManagementLogEntry] = []

    // Activity stream state
    @Published var activityFilter = ActivityFilter()
    @Published var streamEntries: [ActivityEntry] = []
    @Published var isStreaming = false
    @Published var streamError: String? = nil

    // Request details state
    @Published var selectedRequestDetails: RequestDetails? = nil

    private var streamTask: Task<Void, Never>? = nil
    private var serverManagerCancellable: AnyCancellable?

    let client = GAPClient()

    /// Whether the server is installed (delegates to ServerManager)
    var serverInstalled: Bool { serverManager.isInstalled }

    /// Whether the server is running (delegates to ServerManager)
    var serverRunning: Bool { serverManager.isRunning }

    /// Whether the server is currently being installed (delegates to ServerManager)
    var serverInstalling: Bool { serverManager.isInstalling }

    /// Whether the user has successfully authenticated
    var isAuthenticated: Bool { passwordHash != nil }

    init() {
        self.serverManager = ServerManager()

        // Forward ServerManager's objectWillChange to AppState's objectWillChange.
        // Computed properties that delegate to ServerManager (serverInstalled, serverRunning,
        // serverInstalling) don't trigger @Published change notifications on their own —
        // we must manually propagate so SwiftUI views observing AppState re-render.
        serverManagerCancellable = serverManager.objectWillChange.sink { [weak self] _ in
            self?.objectWillChange.send()
        }

        // Auto-install server on app launch
        // This is idempotent - safe to call even if already installed
        serverManager.ensureInstalled()
    }

    /// Check server status and update initialization state
    func checkServerStatus() async {
        guard serverRunning else {
            serverInitialized = false
            return
        }
        do {
            let status = try await client.getStatus()
            serverInitialized = status.initialized
        } catch {
            serverInitialized = false
        }
    }

    /// Initialize the server with a new password
    func initializeServer(password: String) async throws {
        guard serverRunning else {
            throw GAPError.networkError(NSError(
                domain: "AppState",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Server is not running"]
            ))
        }

        let hash = hashPassword(password)
        _ = try await client.initServer(passwordHash: hash)
        serverInitialized = true
    }

    // MARK: - Server Management

    /// Install the server (delegates to ServerManager)
    func installServer() {
        NSLog("GAP: AppState.installServer() called")
        try? "AppState.installServer at \(Date())".write(toFile: "/tmp/gap-appstate-install.txt", atomically: true, encoding: .utf8)
        serverManager.install()
    }

    /// Start the server (delegates to ServerManager)
    func startServer() {
        serverManager.start()
    }

    /// Stop the server (delegates to ServerManager)
    func stopServer() {
        serverManager.stop()
    }

    /// Uninstall the server (delegates to ServerManager)
    func uninstallServer() {
        serverManager.uninstall()
    }

    // MARK: - Authentication

    /// Authenticate with a password by hashing and verifying against the API.
    ///
    /// This method requires the server to be running. If the server is not running,
    /// authentication will fail with a network error.
    ///
    /// - Parameter password: Plain text password
    /// - Throws: GAPError if authentication fails
    func authenticate(password: String) async throws {
        guard serverRunning else {
            throw GAPError.networkError(NSError(
                domain: "AppState",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Server is not running"]
            ))
        }

        let hash = hashPassword(password)
        // Verify by calling an authenticated endpoint
        _ = try await client.getPlugins(passwordHash: hash)
        self.passwordHash = hash
        self.isConnected = true
        self.connectionError = nil
    }

    // MARK: - Data Refresh

    /// Refresh the list of installed plugins from the server.
    ///
    /// - Throws: GAPError if the request fails
    func refreshPlugins() async throws {
        guard serverRunning else { return }
        guard let hash = passwordHash else { return }
        let response = try await client.getPlugins(passwordHash: hash)
        self.plugins = response.plugins
    }

    /// Refresh the list of agent tokens from the server.
    ///
    /// - Throws: GAPError if the request fails
    func refreshTokens() async throws {
        guard serverRunning else { return }
        guard let hash = passwordHash else { return }
        let response = try await client.getTokens(passwordHash: hash)
        self.tokens = response.tokens
    }

    /// Refresh the activity log from the server using current filter.
    ///
    /// - Throws: GAPError if the request fails
    func refreshActivity() async throws {
        guard serverRunning else { return }
        guard let hash = passwordHash else { return }
        let response = try await client.getActivityFiltered(passwordHash: hash, filter: activityFilter)
        self.activity = response.entries
    }

    /// Refresh the management log from the server with optional filters.
    ///
    /// - Parameters:
    ///   - operation: Filter by operation type (e.g., "token_create")
    ///   - resourceType: Filter by resource type (e.g., "token", "plugin")
    ///   - resourceId: Filter by resource ID
    /// - Throws: GAPError if the request fails
    func refreshManagementLog(operation: String? = nil, resourceType: String? = nil, resourceId: String? = nil) async throws {
        guard serverRunning else { return }
        guard let hash = passwordHash else { return }
        let response = try await client.getManagementLog(passwordHash: hash, operation: operation, resourceType: resourceType, resourceId: resourceId)
        self.managementLog = response.entries
    }

    /// Load detailed request/response data for a specific request.
    ///
    /// - Parameter requestId: The request correlation ID
    /// - Throws: GAPError if the request fails
    func loadRequestDetails(requestId: String) async throws {
        guard serverRunning else { return }
        guard let hash = passwordHash else { return }
        let details = try await client.getRequestDetails(requestId: requestId, passwordHash: hash)
        self.selectedRequestDetails = details
    }

    /// Start the SSE activity stream. Entries are inserted at the front of streamEntries.
    func startStream() {
        guard let hash = passwordHash else { return }
        stopStream()
        isStreaming = true
        streamError = nil
        streamTask = Task {
            do {
                for try await entry in client.activityStream(passwordHash: hash) {
                    self.streamEntries.insert(entry, at: 0)
                    // Cap at 500 entries to prevent memory growth
                    if self.streamEntries.count > 500 {
                        self.streamEntries.removeLast()
                    }
                }
                self.isStreaming = false
            } catch {
                if !Task.isCancelled {
                    self.streamError = error.localizedDescription
                    self.isStreaming = false
                }
            }
        }
    }

    /// Stop the SSE activity stream.
    func stopStream() {
        streamTask?.cancel()
        streamTask = nil
        isStreaming = false
    }

    // MARK: - Session Management

    /// Log out and clear all state.
    func logout() {
        stopStream()
        passwordHash = nil
        isConnected = false
        plugins = []
        tokens = []
        activity = []
        managementLog = []
        streamEntries = []
        activityFilter = ActivityFilter()
        selectedRequestDetails = nil
    }
}
