import SwiftUI

/// Main application window with tab-based navigation.
///
/// This window provides access to all major features:
/// - Plugins: View and manage installed plugins
/// - Tokens: Create, view, and revoke agent tokens
/// - Credentials: Set and manage plugin credentials
/// - Activity: View recent proxy request activity
///
/// The window uses a NavigationSplitView with a sidebar for tab selection
/// and a detail view that updates based on the selected tab.
struct MainWindow: View {
    @EnvironmentObject var appState: AppState
    @State private var selectedTab: Tab = .plugins

    enum Tab: String, CaseIterable {
        case plugins = "Plugins"
        case tokens = "Tokens"
        case credentials = "Credentials"
        case activity = "Activity"

        var icon: String {
            switch self {
            case .plugins: return "puzzlepiece"
            case .tokens: return "key"
            case .credentials: return "lock"
            case .activity: return "list.bullet"
            }
        }
    }

    var body: some View {
        NavigationSplitView {
            List(Tab.allCases, id: \.self, selection: $selectedTab) { tab in
                Label(tab.rawValue, systemImage: tab.icon)
            }
            .navigationSplitViewColumnWidth(min: 150, ideal: 180)
        } detail: {
            switch selectedTab {
            case .plugins:
                PluginsView()
            case .tokens:
                TokensView()
            case .credentials:
                CredentialsView()
            case .activity:
                ActivityView()
            }
        }
        .frame(minWidth: 600, minHeight: 400)
    }
}

// MARK: - Placeholder Views
// These will be implemented in separate tasks

/// Plugin management view.
///
/// Displays installed plugins with their names and URL patterns,
/// and provides controls to install, update, and uninstall plugins.
struct PluginsView: View {
    @EnvironmentObject var appState: AppState
    @State private var newPluginRepo: String = ""
    @State private var isInstalling: Bool = false
    @State private var isLoading: Bool = false
    @State private var errorMessage: String?
    @State private var successMessage: String?

    var body: some View {
        VStack(spacing: 0) {
            // Header with install form
            VStack(alignment: .leading, spacing: 12) {
                Text("Installed Plugins")
                    .font(.title2)
                    .fontWeight(.semibold)

                HStack {
                    TextField("owner/repo (e.g., mikekelly/exa-acp)", text: $newPluginRepo)
                        .textFieldStyle(.roundedBorder)
                        .frame(maxWidth: 300)

                    Button(action: installPlugin) {
                        if isInstalling {
                            ProgressView()
                                .scaleEffect(0.7)
                        } else {
                            Text("Install")
                        }
                    }
                    .disabled(newPluginRepo.isEmpty || isInstalling)

                    Spacer()

                    Button(action: { Task { await refresh() } }) {
                        Image(systemName: "arrow.clockwise")
                    }
                    .disabled(isLoading)
                }

                if let error = errorMessage {
                    Text(error)
                        .foregroundColor(.red)
                        .font(.caption)
                }

                if let success = successMessage {
                    Text(success)
                        .foregroundColor(.green)
                        .font(.caption)
                }
            }
            .padding()

            Divider()

            // Plugin list
            if isLoading && appState.plugins.isEmpty {
                Spacer()
                ProgressView("Loading plugins...")
                Spacer()
            } else if appState.plugins.isEmpty {
                Spacer()
                Text("No plugins installed")
                    .foregroundColor(.secondary)
                Spacer()
            } else {
                List(appState.plugins) { plugin in
                    PluginRow(
                        plugin: plugin,
                        onUpdate: { updatePlugin(plugin.name) },
                        onUninstall: { uninstallPlugin(plugin.name) }
                    )
                }
            }
        }
        .task { await refresh() }
    }

    private func refresh() async {
        isLoading = true
        errorMessage = nil
        do {
            try await appState.refreshPlugins()
        } catch {
            errorMessage = error.localizedDescription
        }
        isLoading = false
    }

    private func installPlugin() {
        guard !newPluginRepo.isEmpty else { return }
        isInstalling = true
        errorMessage = nil
        successMessage = nil

        Task {
            do {
                guard let hash = appState.passwordHash else { return }
                let response = try await appState.client.installPlugin(repo: newPluginRepo, passwordHash: hash)
                successMessage = "Installed \(response.name)"
                newPluginRepo = ""
                try await appState.refreshPlugins()
            } catch {
                errorMessage = error.localizedDescription
            }
            isInstalling = false
        }
    }

    private func updatePlugin(_ name: String) {
        errorMessage = nil
        successMessage = nil

        Task {
            do {
                guard let hash = appState.passwordHash else { return }
                let response = try await appState.client.updatePlugin(name: name, passwordHash: hash)
                successMessage = "Updated \(response.name)"
                try await appState.refreshPlugins()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }

    private func uninstallPlugin(_ name: String) {
        errorMessage = nil
        successMessage = nil

        Task {
            do {
                guard let hash = appState.passwordHash else { return }
                _ = try await appState.client.uninstallPlugin(name: name, passwordHash: hash)
                successMessage = "Uninstalled \(name)"
                try await appState.refreshPlugins()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}

struct PluginRow: View {
    let plugin: Plugin
    let onUpdate: () -> Void
    let onUninstall: () -> Void

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(plugin.name)
                    .font(.headline)
                Text(plugin.matchPatterns.joined(separator: ", "))
                    .font(.caption)
                    .foregroundColor(.secondary)
                if !plugin.credentialSchema.isEmpty {
                    Text("Credentials: \(plugin.credentialSchema.joined(separator: ", "))")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
            }

            Spacer()

            Button("Update", action: onUpdate)
                .buttonStyle(.bordered)

            Button("Uninstall", action: onUninstall)
                .buttonStyle(.bordered)
                .tint(.red)
        }
        .padding(.vertical, 4)
    }
}

/// View for token management.
///
/// Displays agent tokens with names, prefixes, and creation dates,
/// and provides controls to create and revoke tokens.
struct TokensView: View {
    @EnvironmentObject var appState: AppState
    @State private var newTokenName: String = ""
    @State private var isCreating: Bool = false
    @State private var isLoading: Bool = false
    @State private var createdToken: String?
    @State private var errorMessage: String?

    var body: some View {
        VStack(spacing: 0) {
            // Header with create form
            VStack(alignment: .leading, spacing: 12) {
                Text("Agent Tokens")
                    .font(.title2)
                    .fontWeight(.semibold)

                HStack {
                    TextField("Token name (e.g., claude-code)", text: $newTokenName)
                        .textFieldStyle(.roundedBorder)
                        .frame(maxWidth: 250)

                    Button(action: createToken) {
                        if isCreating {
                            ProgressView()
                                .scaleEffect(0.7)
                        } else {
                            Text("Create")
                        }
                    }
                    .disabled(newTokenName.isEmpty || isCreating)

                    Spacer()

                    Button(action: { Task { await refresh() } }) {
                        Image(systemName: "arrow.clockwise")
                    }
                    .disabled(isLoading)
                }

                // Show created token (only visible once!)
                if let token = createdToken {
                    HStack {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundColor(.green)
                        Text("Token created:")
                        Text(token)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                        Button(action: { copyToClipboard(token) }) {
                            Image(systemName: "doc.on.doc")
                        }
                        .help("Copy to clipboard")
                        Button("Dismiss") {
                            createdToken = nil
                        }
                    }
                    .padding(8)
                    .background(Color.green.opacity(0.1))
                    .cornerRadius(8)
                }

                if let error = errorMessage {
                    Text(error)
                        .foregroundColor(.red)
                        .font(.caption)
                }
            }
            .padding()

            Divider()

            // Token list
            if isLoading && appState.tokens.isEmpty {
                Spacer()
                ProgressView("Loading tokens...")
                Spacer()
            } else if appState.tokens.isEmpty {
                Spacer()
                Text("No tokens created")
                    .foregroundColor(.secondary)
                Spacer()
            } else {
                List(appState.tokens) { token in
                    TokenRow(token: token, onRevoke: { revokeToken(token.id) })
                }
            }
        }
        .task { await refresh() }
    }

    private func refresh() async {
        isLoading = true
        errorMessage = nil
        do {
            try await appState.refreshTokens()
        } catch {
            errorMessage = error.localizedDescription
        }
        isLoading = false
    }

    private func createToken() {
        guard !newTokenName.isEmpty else { return }
        isCreating = true
        errorMessage = nil
        createdToken = nil

        Task {
            do {
                guard let hash = appState.passwordHash else { return }
                let response = try await appState.client.createToken(name: newTokenName, passwordHash: hash)
                createdToken = response.token  // Show full token ONCE
                newTokenName = ""
                try await appState.refreshTokens()
            } catch {
                errorMessage = error.localizedDescription
            }
            isCreating = false
        }
    }

    private func revokeToken(_ id: String) {
        errorMessage = nil

        Task {
            do {
                guard let hash = appState.passwordHash else { return }
                _ = try await appState.client.revokeToken(id: id, passwordHash: hash)
                try await appState.refreshTokens()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }

    private func copyToClipboard(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}

struct TokenRow: View {
    let token: Token
    let onRevoke: () -> Void

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(token.name)
                    .font(.headline)
                HStack(spacing: 8) {
                    Text(token.prefix + "...")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundColor(.secondary)
                    Text("Created: \(formatDate(token.createdAt))")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }

            Spacer()

            Button("Revoke", action: onRevoke)
                .buttonStyle(.bordered)
                .tint(.red)
        }
        .padding(.vertical, 4)
    }

    private func formatDate(_ isoString: String) -> String {
        // Simple date formatting - just show date part
        if let range = isoString.range(of: "T") {
            return String(isoString[..<range.lowerBound])
        }
        return isoString
    }
}

/// View for managing plugin credentials.
///
/// Credentials are write-only for security. This view allows setting and deleting
/// credential values, but never displays them. The view shows which credentials
/// each plugin requires via its credentialSchema.
struct CredentialsView: View {
    @EnvironmentObject var appState: AppState
    @State private var selectedPlugin: String = ""
    @State private var selectedKey: String = ""
    @State private var credentialValue: String = ""
    @State private var isSubmitting: Bool = false
    @State private var successMessage: String?
    @State private var errorMessage: String?

    private var selectedPluginObj: Plugin? {
        appState.plugins.first { $0.name == selectedPlugin }
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            VStack(alignment: .leading, spacing: 12) {
                Text("Credential Management")
                    .font(.title2)
                    .fontWeight(.semibold)

                Text("Credentials are write-only for security. You can set or delete them, but not view their values.")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding()

            Divider()

            // Set credential form
            GroupBox("Set Credential") {
                VStack(alignment: .leading, spacing: 16) {
                    // Plugin picker
                    HStack {
                        Text("Plugin:")
                            .frame(width: 80, alignment: .trailing)
                        Picker("", selection: $selectedPlugin) {
                            Text("Select a plugin...").tag("")
                            ForEach(appState.plugins) { plugin in
                                Text(plugin.name).tag(plugin.name)
                            }
                        }
                        .frame(width: 250)
                        .onChange(of: selectedPlugin) { _ in
                            selectedKey = ""  // Reset key when plugin changes
                        }
                    }

                    // Credential key picker
                    HStack {
                        Text("Credential:")
                            .frame(width: 80, alignment: .trailing)
                        Picker("", selection: $selectedKey) {
                            Text("Select a credential...").tag("")
                            if let plugin = selectedPluginObj {
                                ForEach(plugin.credentialSchema, id: \.self) { key in
                                    Text(key).tag(key)
                                }
                            }
                        }
                        .frame(width: 250)
                        .disabled(selectedPlugin.isEmpty)
                    }

                    // Value input
                    HStack {
                        Text("Value:")
                            .frame(width: 80, alignment: .trailing)
                        SecureField("Enter credential value", text: $credentialValue)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 250)
                    }

                    // Action buttons
                    HStack {
                        Spacer()
                            .frame(width: 80)

                        Button(action: setCredential) {
                            if isSubmitting {
                                ProgressView()
                                    .scaleEffect(0.7)
                            } else {
                                Text("Set Credential")
                            }
                        }
                        .disabled(!canSubmit || isSubmitting)

                        Button("Delete Credential", action: deleteCredential)
                            .disabled(selectedPlugin.isEmpty || selectedKey.isEmpty || isSubmitting)
                            .foregroundColor(.red)
                    }

                    if let success = successMessage {
                        HStack {
                            Spacer().frame(width: 80)
                            Text(success)
                                .foregroundColor(.green)
                                .font(.caption)
                        }
                    }

                    if let error = errorMessage {
                        HStack {
                            Spacer().frame(width: 80)
                            Text(error)
                                .foregroundColor(.red)
                                .font(.caption)
                        }
                    }
                }
                .padding()
            }
            .padding()

            Divider()

            // Plugin credential requirements
            GroupBox("Plugin Credential Requirements") {
                if appState.plugins.isEmpty {
                    Text("No plugins installed")
                        .foregroundColor(.secondary)
                        .padding()
                } else {
                    List(appState.plugins) { plugin in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(plugin.name)
                                .font(.headline)
                            if plugin.credentialSchema.isEmpty {
                                Text("No credentials required")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            } else {
                                Text("Required: \(plugin.credentialSchema.joined(separator: ", "))")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                        }
                        .padding(.vertical, 2)
                    }
                }
            }
            .padding()

            Spacer()
        }
        .task {
            // Refresh plugins to get credential schemas
            try? await appState.refreshPlugins()
        }
    }

    private var canSubmit: Bool {
        !selectedPlugin.isEmpty && !selectedKey.isEmpty && !credentialValue.isEmpty
    }

    private func setCredential() {
        guard canSubmit else { return }
        isSubmitting = true
        errorMessage = nil
        successMessage = nil

        Task {
            do {
                guard let hash = appState.passwordHash else { return }
                _ = try await appState.client.setCredential(
                    plugin: selectedPlugin,
                    key: selectedKey,
                    value: credentialValue,
                    passwordHash: hash
                )
                successMessage = "Credential '\(selectedKey)' set for \(selectedPlugin)"
                credentialValue = ""  // Clear the value
            } catch {
                errorMessage = error.localizedDescription
            }
            isSubmitting = false
        }
    }

    private func deleteCredential() {
        guard !selectedPlugin.isEmpty, !selectedKey.isEmpty else { return }
        isSubmitting = true
        errorMessage = nil
        successMessage = nil

        Task {
            do {
                guard let hash = appState.passwordHash else { return }
                try await appState.client.deleteCredential(
                    plugin: selectedPlugin,
                    key: selectedKey,
                    passwordHash: hash
                )
                successMessage = "Credential '\(selectedKey)' deleted from \(selectedPlugin)"
            } catch {
                errorMessage = error.localizedDescription
            }
            isSubmitting = false
        }
    }
}

/// Activity monitoring view.
///
/// Displays recent proxy requests with timestamps, methods, URLs,
/// agent names, and status codes. Supports manual and auto-refresh.
struct ActivityView: View {
    @EnvironmentObject var appState: AppState
    @State private var isLoading: Bool = false
    @State private var autoRefresh: Bool = false
    @State private var errorMessage: String?
    @State private var refreshTask: Task<Void, Never>?

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Text("Activity Log")
                    .font(.title2)
                    .fontWeight(.semibold)

                Spacer()

                Toggle("Auto-refresh", isOn: $autoRefresh)
                    .toggleStyle(.switch)
                    .onChange(of: autoRefresh) { newValue in
                        if newValue {
                            startAutoRefresh()
                        } else {
                            stopAutoRefresh()
                        }
                    }

                Button(action: { Task { await refresh() } }) {
                    Image(systemName: "arrow.clockwise")
                }
                .disabled(isLoading)
            }
            .padding()

            if let error = errorMessage {
                Text(error)
                    .foregroundColor(.red)
                    .font(.caption)
                    .padding(.horizontal)
            }

            Divider()

            // Activity table
            if isLoading && appState.activity.isEmpty {
                Spacer()
                ProgressView("Loading activity...")
                Spacer()
            } else if appState.activity.isEmpty {
                Spacer()
                Text("No activity recorded")
                    .foregroundColor(.secondary)
                Spacer()
            } else {
                Table(appState.activity) {
                    TableColumn("Time") { entry in
                        Text(formatTimestamp(entry.timestamp))
                            .font(.system(.caption, design: .monospaced))
                    }
                    .width(min: 70, ideal: 80)

                    TableColumn("Method") { entry in
                        Text(entry.method)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundColor(methodColor(entry.method))
                    }
                    .width(min: 50, ideal: 60)

                    TableColumn("URL") { entry in
                        Text(entry.url)
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .help(entry.url)
                    }
                    .width(min: 200, ideal: 300)

                    TableColumn("Agent") { entry in
                        Text(entry.agentId ?? "-")
                            .font(.caption)
                    }
                    .width(min: 80, ideal: 100)

                    TableColumn("Status") { entry in
                        Text("\(entry.status)")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundColor(statusColor(entry.status))
                    }
                    .width(min: 45, ideal: 50)
                }
            }
        }
        .task { await refresh() }
        .onDisappear { stopAutoRefresh() }
    }

    private func refresh() async {
        isLoading = true
        errorMessage = nil
        do {
            try await appState.refreshActivity()
        } catch {
            errorMessage = error.localizedDescription
        }
        isLoading = false
    }

    private func startAutoRefresh() {
        refreshTask = Task {
            while !Task.isCancelled {
                await refresh()
                try? await Task.sleep(for: .seconds(5))
            }
        }
    }

    private func stopAutoRefresh() {
        refreshTask?.cancel()
        refreshTask = nil
    }

    private func formatTimestamp(_ ts: String) -> String {
        // Parse ISO8601 and format as HH:MM:SS
        // Simple approach: extract time part
        if let tIndex = ts.firstIndex(of: "T"),
           let dotIndex = ts.firstIndex(of: ".") ?? ts.firstIndex(of: "Z") {
            let timeStart = ts.index(after: tIndex)
            return String(ts[timeStart..<dotIndex])
        }
        return ts
    }

    private func methodColor(_ method: String) -> Color {
        switch method.uppercased() {
        case "GET": return .blue
        case "POST": return .green
        case "PUT": return .orange
        case "DELETE": return .red
        case "PATCH": return .purple
        default: return .primary
        }
    }

    private func statusColor(_ status: Int) -> Color {
        switch status {
        case 200..<300: return .green
        case 300..<400: return .blue
        case 400..<500: return .orange
        case 500..<600: return .red
        default: return .primary
        }
    }
}
