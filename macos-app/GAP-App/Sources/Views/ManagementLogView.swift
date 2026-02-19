import SwiftUI

/// Management log view showing audit entries for management API operations.
///
/// Provides filters for operation type, resource type, and resource ID,
/// with a results list showing each entry's outcome and expandable details.
struct ManagementLogView: View {
    @EnvironmentObject var appState: AppState

    @State private var operationFilter: String = ""
    @State private var resourceTypeFilter: String = ""
    @State private var resourceIdFilter: String = ""
    @State private var isLoading = false
    @State private var errorMessage: String?

    var body: some View {
        VStack(spacing: 0) {
            filterBar
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

            if isLoading && appState.managementLog.isEmpty {
                Spacer()
                ProgressView("Loading...")
                Spacer()
            } else if appState.managementLog.isEmpty {
                Spacer()
                VStack(spacing: 8) {
                    Image(systemName: "doc.text.magnifyingglass")
                        .font(.system(size: 32))
                        .foregroundColor(.secondary)
                    Text("No management log entries found")
                        .foregroundColor(.secondary)
                }
                Spacer()
            } else {
                HStack {
                    Text("\(appState.managementLog.count) results")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Spacer()
                }
                .padding(.horizontal)
                .padding(.vertical, 4)

                List(appState.managementLog) { entry in
                    ManagementLogEntryRow(entry: entry)
                }
                .listStyle(.inset(alternatesRowBackgrounds: true))
            }
        }
        .task { await search() }
    }

    private var filterBar: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Filters")
                    .font(.headline)

                Spacer()

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

            GroupBox {
                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Operation")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Picker("", selection: $operationFilter) {
                            Text("All Operations").tag("")
                            Text("server_init").tag("server_init")
                            Text("token_create").tag("token_create")
                            Text("token_delete").tag("token_delete")
                            Text("plugin_install").tag("plugin_install")
                            Text("plugin_uninstall").tag("plugin_uninstall")
                            Text("plugin_update").tag("plugin_update")
                            Text("credential_set").tag("credential_set")
                            Text("credential_delete").tag("credential_delete")
                        }
                        .frame(width: 180)
                    }

                    VStack(alignment: .leading, spacing: 2) {
                        Text("Resource Type")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Picker("", selection: $resourceTypeFilter) {
                            Text("All Types").tag("")
                            Text("server").tag("server")
                            Text("token").tag("token")
                            Text("plugin").tag("plugin")
                            Text("credential").tag("credential")
                        }
                        .frame(width: 140)
                    }

                    FilterField(label: "Resource ID", text: $resourceIdFilter, placeholder: "Filter by ID")
                }
            }
            .padding(.horizontal)
            .padding(.bottom, 8)
        }
    }

    private func search() async {
        isLoading = true
        errorMessage = nil
        do {
            try await appState.refreshManagementLog(
                operation: operationFilter.isEmpty ? nil : operationFilter,
                resourceType: resourceTypeFilter.isEmpty ? nil : resourceTypeFilter,
                resourceId: resourceIdFilter.isEmpty ? nil : resourceIdFilter
            )
        } catch {
            errorMessage = error.localizedDescription
        }
        isLoading = false
    }
}

// MARK: - Management Log Entry Row

/// A single management log entry row with expandable detail.
///
/// Shows a compact summary with success indicator, timestamp, operation,
/// and resource info. Expandable via DisclosureGroup to show detail JSON
/// and error message when present.
struct ManagementLogEntryRow: View {
    let entry: ManagementLogEntry
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
            // Success/failure indicator
            Image(systemName: entry.success ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundColor(entry.success ? .green : .red)
                .font(.system(size: 14))

            // Timestamp
            Text(formatTimestamp(entry.timestamp))
                .font(.system(.caption, design: .monospaced))
                .foregroundColor(.secondary)
                .frame(minWidth: 60, alignment: .leading)

            // Operation
            Text(entry.operation)
                .font(.system(.body, design: .monospaced))
                .fontWeight(.medium)

            // Resource type badge
            Text(entry.resourceType)
                .font(.caption2)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(Color.secondary.opacity(0.2))
                .cornerRadius(4)

            // Resource ID (truncated)
            if let resourceId = entry.resourceId, !resourceId.isEmpty {
                Text(resourceId)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            Spacer()
        }
    }

    private var detailView: some View {
        VStack(alignment: .leading, spacing: 6) {
            DetailRow(label: "Timestamp", value: entry.timestamp, monospaced: true)
            DetailRow(label: "Operation", value: entry.operation, monospaced: true)
            DetailRow(label: "Resource Type", value: entry.resourceType, monospaced: false)

            if let resourceId = entry.resourceId, !resourceId.isEmpty {
                DetailRow(label: "Resource ID", value: resourceId, monospaced: true)
            }

            if let detail = entry.detail, !detail.isEmpty {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Detail")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .fontWeight(.medium)
                    Text(detail)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(6)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color(NSColor.textBackgroundColor))
                        .cornerRadius(4)
                }
            }

            if let errorMsg = entry.errorMessage, !errorMsg.isEmpty {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Error")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .fontWeight(.medium)
                    Text(errorMsg)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundColor(.red)
                        .textSelection(.enabled)
                        .padding(6)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.red.opacity(0.05))
                        .cornerRadius(4)
                }
            }
        }
        .padding(.vertical, 4)
    }

    private func formatTimestamp(_ timestamp: String) -> String {
        // Show just the time portion for compact display (HH:MM:SS), matching ActivityEntryRow
        if let tIndex = timestamp.firstIndex(of: "T") {
            let timeStart = timestamp.index(after: tIndex)
            let timePart = String(timestamp[timeStart...])
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
}
