import SwiftUI

/// Activity monitoring view with live stream and filtered search tabs.
///
/// Uses a segmented control to switch between:
/// - Live Stream: real-time SSE connection showing activity as it happens
/// - Search: filtered query against the activity log with configurable parameters
struct ActivityView: View {
    @EnvironmentObject var appState: AppState
    @State private var selectedTab = 0  // 0 = Live, 1 = Search

    var body: some View {
        VStack(spacing: 0) {
            Picker("", selection: $selectedTab) {
                Text("Live Stream").tag(0)
                Text("Search").tag(1)
            }
            .pickerStyle(.segmented)
            .padding()

            Divider()

            if selectedTab == 0 {
                LiveStreamView()
            } else {
                FilteredActivityView()
            }
        }
    }
}

// MARK: - Live Stream View

/// Real-time activity stream via SSE connection.
///
/// Shows a connection indicator, play/pause controls, and a scrollable
/// list of activity entries as they arrive from the server.
struct LiveStreamView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        VStack(spacing: 0) {
            // Stream controls
            HStack(spacing: 12) {
                // Connection status indicator
                HStack(spacing: 6) {
                    Image(systemName: "circle.fill")
                        .font(.system(size: 8))
                        .foregroundColor(appState.isStreaming ? .green : .red)
                    Text(appState.isStreaming ? "Connected" : "Disconnected")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }

                Button(action: toggleStream) {
                    Image(systemName: appState.isStreaming ? "pause.fill" : "play.fill")
                }
                .help(appState.isStreaming ? "Pause stream" : "Start stream")

                Button(action: { appState.streamEntries.removeAll() }) {
                    Image(systemName: "trash")
                }
                .help("Clear entries")
                .disabled(appState.streamEntries.isEmpty)

                Spacer()

                if !appState.streamEntries.isEmpty {
                    Text("\(appState.streamEntries.count) entries")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 2)
                        .background(Color.secondary.opacity(0.15))
                        .cornerRadius(8)
                }
            }
            .padding(.horizontal)
            .padding(.vertical, 8)

            if let error = appState.streamError {
                HStack {
                    Image(systemName: "exclamationmark.triangle")
                        .foregroundColor(.orange)
                    Text(error)
                        .font(.caption)
                        .foregroundColor(.red)
                    Spacer()
                }
                .padding(.horizontal)
                .padding(.bottom, 4)
            }

            Divider()

            // Stream entries list
            if appState.streamEntries.isEmpty {
                Spacer()
                VStack(spacing: 8) {
                    Image(systemName: appState.isStreaming ? "antenna.radiowaves.left.and.right" : "play.circle")
                        .font(.system(size: 32))
                        .foregroundColor(.secondary)
                    Text(appState.isStreaming
                         ? "Waiting for activity..."
                         : "Press play to start streaming")
                        .foregroundColor(.secondary)
                }
                Spacer()
            } else {
                List(appState.streamEntries) { entry in
                    ActivityEntryRow(entry: entry)
                }
                .listStyle(.inset(alternatesRowBackgrounds: true))
            }
        }
        .onDisappear {
            appState.stopStream()
        }
    }

    private func toggleStream() {
        if appState.isStreaming {
            appState.stopStream()
        } else {
            appState.startStream()
        }
    }
}

// MARK: - Filtered Activity View

/// Filtered activity search with configurable parameters.
///
/// Provides a filter bar with text fields for domain, path, method,
/// plugin, and agent filtering, plus a results table.
struct FilteredActivityView: View {
    @EnvironmentObject var appState: AppState
    @State private var isLoading = false
    @State private var errorMessage: String?

    // Local filter state (applied on search)
    @State private var domain: String = ""
    @State private var path: String = ""
    @State private var method: String = ""
    @State private var plugin: String = ""
    @State private var agent: String = ""
    @State private var limit: Int = 100
    @State private var showFilters = true

    private let methods = ["", "GET", "POST", "PUT", "DELETE", "PATCH"]
    private let limits = [25, 50, 100, 200]

    var body: some View {
        VStack(spacing: 0) {
            // Filter section
            VStack(spacing: 0) {
                // Filter header with toggle and actions
                HStack {
                    Button(action: { withAnimation { showFilters.toggle() } }) {
                        HStack(spacing: 4) {
                            Image(systemName: "line.3.horizontal.decrease.circle")
                            Text("Filters")
                                .font(.headline)
                        }
                    }
                    .buttonStyle(.plain)

                    Spacer()

                    if hasActiveFilters {
                        Button(action: clearFilters) {
                            HStack(spacing: 4) {
                                Image(systemName: "xmark.circle")
                                Text("Clear")
                                    .font(.caption)
                            }
                        }
                        .buttonStyle(.plain)
                        .foregroundColor(.secondary)
                    }

                    Button(action: { Task { await search() } }) {
                        HStack(spacing: 4) {
                            Image(systemName: "arrow.clockwise")
                            Text("Search")
                        }
                    }
                    .disabled(isLoading)
                }
                .padding(.horizontal)
                .padding(.vertical, 8)

                if showFilters {
                    GroupBox {
                        VStack(spacing: 8) {
                            HStack(spacing: 12) {
                                FilterField(label: "Domain", text: $domain, placeholder: "e.g., api.example.com")
                                FilterField(label: "Path", text: $path, placeholder: "e.g., /v1/chat")
                            }
                            HStack(spacing: 12) {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("Method")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                    Picker("", selection: $method) {
                                        Text("Any").tag("")
                                        ForEach(methods.dropFirst(), id: \.self) { m in
                                            Text(m).tag(m)
                                        }
                                    }
                                    .frame(width: 100)
                                }
                                FilterField(label: "Plugin", text: $plugin, placeholder: "e.g., mikekelly/exa-gap")
                                FilterField(label: "Agent", text: $agent, placeholder: "Agent ID")
                            }
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("Limit")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                    Picker("", selection: $limit) {
                                        ForEach(limits, id: \.self) { l in
                                            Text("\(l)").tag(l)
                                        }
                                    }
                                    .frame(width: 80)
                                }
                                Spacer()
                            }
                        }
                    }
                    .padding(.horizontal)
                    .padding(.bottom, 8)
                }
            }
            .background(Color(NSColor.controlBackgroundColor))

            Divider()

            if let error = errorMessage {
                HStack {
                    Image(systemName: "exclamationmark.triangle")
                        .foregroundColor(.orange)
                    Text(error)
                        .font(.caption)
                        .foregroundColor(.red)
                    Spacer()
                }
                .padding(.horizontal)
                .padding(.vertical, 4)
            }

            // Results
            if isLoading && appState.activity.isEmpty {
                Spacer()
                ProgressView("Searching...")
                Spacer()
            } else if appState.activity.isEmpty {
                Spacer()
                VStack(spacing: 8) {
                    Image(systemName: "magnifyingglass")
                        .font(.system(size: 32))
                        .foregroundColor(.secondary)
                    Text("No activity entries found")
                        .foregroundColor(.secondary)
                }
                Spacer()
            } else {
                HStack {
                    Text("\(appState.activity.count) results")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Spacer()
                }
                .padding(.horizontal)
                .padding(.vertical, 4)

                List(appState.activity) { entry in
                    ActivityEntryRow(entry: entry)
                }
                .listStyle(.inset(alternatesRowBackgrounds: true))
            }
        }
        .task { await search() }
    }

    private var hasActiveFilters: Bool {
        !domain.isEmpty || !path.isEmpty || !method.isEmpty || !plugin.isEmpty || !agent.isEmpty
    }

    private func clearFilters() {
        domain = ""
        path = ""
        method = ""
        plugin = ""
        agent = ""
        limit = 100
    }

    private func search() async {
        isLoading = true
        errorMessage = nil

        appState.activityFilter = ActivityFilter(
            domain: domain,
            method: method,
            plugin: plugin,
            path: path,
            agent: agent,
            limit: limit
        )

        do {
            try await appState.refreshActivity()
        } catch {
            errorMessage = error.localizedDescription
        }
        isLoading = false
    }
}

// MARK: - Filter Field

/// Reusable labeled text field for filter inputs.
struct FilterField: View {
    let label: String
    @Binding var text: String
    let placeholder: String

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.caption)
                .foregroundColor(.secondary)
            TextField(placeholder, text: $text)
                .textFieldStyle(.roundedBorder)
        }
    }
}

// MARK: - Activity Entry Row

/// A single activity entry row used in both live stream and search results.
///
/// Shows a compact summary with method pill, status badge, URL, and plugin name.
/// Expandable via DisclosureGroup to show full details.
struct ActivityEntryRow: View {
    let entry: ActivityEntry
    @State private var isExpanded = false

    var body: some View {
        DisclosureGroup(isExpanded: $isExpanded) {
            detailView
        } label: {
            compactRow
        }
    }

    private var compactRow: some View {
        HStack(spacing: 8) {
            // Timestamp
            Text(formatTimestamp(entry.timestamp))
                .font(.system(.caption, design: .monospaced))
                .foregroundColor(.secondary)
                .frame(minWidth: 60, alignment: .leading)

            // Method pill
            Text(entry.method)
                .font(.system(.caption2, design: .monospaced))
                .fontWeight(.semibold)
                .foregroundColor(.white)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(methodColor(entry.method))
                .cornerRadius(4)

            // Status badge
            Text("\(entry.status)")
                .font(.system(.caption, design: .monospaced))
                .fontWeight(.medium)
                .foregroundColor(statusColor(entry.status))

            // URL (truncated)
            Text(entry.url)
                .font(.system(.caption, design: .monospaced))
                .lineLimit(1)
                .truncationMode(.middle)

            Spacer()

            // Plugin name
            if let pluginName = entry.pluginName {
                Text(pluginName)
                    .font(.caption2)
                    .foregroundColor(.secondary)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 1)
                    .background(Color.secondary.opacity(0.1))
                    .cornerRadius(3)
            }
        }
    }

    private var detailView: some View {
        VStack(alignment: .leading, spacing: 6) {
            if let requestId = entry.requestId, !requestId.isEmpty {
                DetailRow(label: "Request ID", value: requestId, monospaced: true)
            }

            if let agentId = entry.agentId, !agentId.isEmpty {
                DetailRow(label: "Agent", value: agentId, monospaced: true)
            }

            if let pluginName = entry.pluginName {
                let shaDisplay = entry.pluginSha.map { " (\(String($0.prefix(8))))" } ?? ""
                DetailRow(label: "Plugin", value: pluginName + shaDisplay, monospaced: false)
            }

            if let sourceHash = entry.sourceHash, !sourceHash.isEmpty {
                DetailRow(label: "Source Hash", value: sourceHash, monospaced: true)
            }

            if let headers = entry.requestHeaders, !headers.isEmpty {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Request Headers")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .fontWeight(.medium)
                    Text(formatHeaders(headers))
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(6)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color(NSColor.textBackgroundColor))
                        .cornerRadius(4)
                }
            }

            DetailRow(label: "Full URL", value: entry.url, monospaced: true)

            DetailRow(label: "Timestamp", value: entry.timestamp, monospaced: true)
        }
        .padding(.vertical, 4)
    }

    // MARK: - Formatting Helpers

    private func formatTimestamp(_ timestamp: String) -> String {
        // Show just the time portion for compact display (HH:MM:SS)
        if let tIndex = timestamp.firstIndex(of: "T") {
            let timeStart = timestamp.index(after: tIndex)
            let timePart = String(timestamp[timeStart...])
            // Strip timezone info and fractional seconds for compact display
            if let dotIndex = timePart.firstIndex(of: ".") {
                return String(timePart[..<dotIndex])
            }
            if let zIndex = timePart.firstIndex(of: "Z") {
                return String(timePart[..<zIndex])
            }
            return String(timePart.prefix(8))
        }
        return timestamp
    }

    private func methodColor(_ method: String) -> Color {
        switch method.uppercased() {
        case "GET": return .blue
        case "POST": return .green
        case "PUT": return .orange
        case "DELETE": return .red
        case "PATCH": return .purple
        default: return .gray
        }
    }

    private func statusColor(_ status: Int) -> Color {
        switch status {
        case 200..<300: return .green
        case 300..<400: return .yellow
        case 400..<500: return .orange
        case 500...: return .red
        default: return .secondary
        }
    }

    private func formatHeaders(_ headers: String) -> String {
        // Try to pretty-print if it looks like JSON
        if let data = headers.data(using: .utf8),
           let json = try? JSONSerialization.jsonObject(with: data),
           let pretty = try? JSONSerialization.data(withJSONObject: json, options: .prettyPrinted),
           let prettyStr = String(data: pretty, encoding: .utf8) {
            return prettyStr
        }
        return headers
    }
}

// MARK: - Detail Row

/// A label-value pair for the expanded entry detail view.
struct DetailRow: View {
    let label: String
    let value: String
    var monospaced: Bool = false

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Text(label)
                .font(.caption)
                .foregroundColor(.secondary)
                .fontWeight(.medium)
                .frame(width: 90, alignment: .trailing)
            if monospaced {
                Text(value)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
            } else {
                Text(value)
                    .font(.caption)
                    .textSelection(.enabled)
            }
        }
    }
}
