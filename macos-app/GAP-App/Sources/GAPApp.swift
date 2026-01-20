import SwiftUI

class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        // Menu bar apps should not terminate when windows close
        return false
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Disable Cmd+Q by removing the Quit menu item from the app menu
        // Menu bar Quit button still works via NSApp.terminate()
        if let appMenu = NSApp.mainMenu?.items.first?.submenu {
            // Find and remove the Quit menu item
            if let quitIndex = appMenu.items.firstIndex(where: { $0.action == #selector(NSApplication.terminate(_:)) }) {
                appMenu.removeItem(at: quitIndex)
            }
        }
    }
}

@main
struct GAPApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @StateObject private var appState = AppState()

    var body: some Scene {
        MenuBarExtra {
            MenuBarView()
                .environmentObject(appState)
        } label: {
            Image(systemName: appState.serverRunning ? "lock.shield.fill" : "lock.shield")
        }
        .menuBarExtraStyle(.window)

        Window("GAP", id: "main") {
            ContentView()
                .environmentObject(appState)
        }
        .defaultSize(width: 700, height: 500)
    }
}

struct ContentView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        if !appState.serverInstalled {
            ServerInstallView()
        } else if !appState.serverRunning {
            ServerStartView()
        } else if appState.isAuthenticated {
            MainWindow()
        } else {
            PasswordPrompt()
        }
    }
}

/// View shown when the server is not installed
struct ServerInstallView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "arrow.down.circle")
                .font(.system(size: 48))
                .foregroundColor(.accentColor)

            Text("GAP Server Not Installed")
                .font(.headline)

            Text("The GAP server needs to be installed before you can use the app.")
                .multilineTextAlignment(.center)
                .foregroundColor(.secondary)
                .frame(width: 300)

            Button("Install Server") {
                appState.installServer()
            }
            .buttonStyle(.borderedProminent)
        }
        .padding(40)
        .frame(width: 400, height: 300)
    }
}

/// View shown when the server is installed but not running
struct ServerStartView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "play.circle")
                .font(.system(size: 48))
                .foregroundColor(.accentColor)

            Text("GAP Server Stopped")
                .font(.headline)

            Text("The server is installed but not currently running.")
                .multilineTextAlignment(.center)
                .foregroundColor(.secondary)
                .frame(width: 300)

            HStack(spacing: 12) {
                Button("Start Server") {
                    appState.startServer()
                }
                .buttonStyle(.borderedProminent)

                Button("Uninstall") {
                    appState.uninstallServer()
                }
            }
        }
        .padding(40)
        .frame(width: 400, height: 300)
    }
}
