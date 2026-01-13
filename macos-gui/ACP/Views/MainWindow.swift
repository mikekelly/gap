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

/// Placeholder view for plugin management.
///
/// Will display installed plugins with their names and URL patterns,
/// and provide controls to install, update, and uninstall plugins.
struct PluginsView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        Text("Plugins View - Coming Soon")
            .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// Placeholder view for token management.
///
/// Will display agent tokens with names, prefixes, and creation dates,
/// and provide controls to create and revoke tokens.
struct TokensView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        Text("Tokens View - Coming Soon")
            .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// Placeholder view for credential management.
///
/// Will display credentials grouped by plugin, and provide controls
/// to set and delete credential values. Credential values are write-only
/// and cannot be retrieved.
struct CredentialsView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        Text("Credentials View - Coming Soon")
            .frame(maxWidth: .infinity, maxHeight: .infinity)
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
