import SwiftUI

/// Menu bar dropdown view showing connection status and quick actions.
///
/// This view appears when the user clicks the menu bar icon and provides:
/// - Connection status indicator
/// - Open main window button
/// - Lock/logout button (when authenticated)
/// - Quit button
struct MenuBarView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.openWindow) var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Circle()
                    .fill(appState.isConnected ? Color.green : Color.red)
                    .frame(width: 8, height: 8)
                Text(appState.isConnected ? "Connected" : "Not Connected")
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 4)

            Divider()

            Button("Open ACP") {
                openWindow(id: "main")
                NSApp.activate(ignoringOtherApps: true)
            }
            .padding(.horizontal, 8)

            if appState.isAuthenticated {
                Button("Lock") {
                    appState.logout()
                }
                .padding(.horizontal, 8)
            }

            Divider()

            Button("Quit") {
                NSApplication.shared.terminate(nil)
            }
            .padding(.horizontal, 8)
        }
        .padding(.vertical, 8)
        .frame(width: 180)
    }
}
