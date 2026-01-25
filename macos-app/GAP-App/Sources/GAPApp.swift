import SwiftUI

class AppDelegate: NSObject, NSApplicationDelegate {
    private var serverManager: ServerManager?
    private var bundleMonitor: BundlePathMonitor?

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

        // Initialize ServerManager for cleanup operations
        Task { @MainActor in
            serverManager = ServerManager()
        }

        // Start monitoring our app bundle for deletion/move to trash
        bundleMonitor = BundlePathMonitor { [weak self] in
            self?.performCleanupAndQuit()
        }
        bundleMonitor?.startMonitoring()
    }

    func applicationWillTerminate(_ notification: Notification) {
        bundleMonitor?.stopMonitoring()
    }

    private func performCleanupAndQuit() {
        NSLog("GAP: App moved to Trash or deleted, performing cleanup")

        // Perform cleanup on main thread
        Task { @MainActor in
            serverManager?.cleanup()

            // Small delay to allow cleanup to complete
            try? await Task.sleep(nanoseconds: 500_000_000) // 0.5 seconds

            NSLog("GAP: Cleanup complete, terminating")
            NSApplication.shared.terminate(nil)
        }
    }
}

/// Monitors the app bundle path to detect when the app is moved to Trash
class BundlePathMonitor {
    private var dispatchSource: DispatchSourceFileSystemObject?
    private var fileDescriptor: Int32 = -1
    private let onDeleted: () -> Void
    private let bundlePath: String

    init(onDeleted: @escaping () -> Void) {
        self.onDeleted = onDeleted
        // Get the app bundle path - typically /Applications/GAP.app
        self.bundlePath = Bundle.main.bundlePath
    }

    func startMonitoring() {
        // Only monitor if we're running from a typical install location
        guard bundlePath.contains("/Applications/") ||
              bundlePath.contains("/Users/") else {
            NSLog("GAP: Not monitoring bundle path - not in standard location: \(bundlePath)")
            return
        }

        // Open the bundle directory for monitoring
        fileDescriptor = open(bundlePath, O_EVTONLY)
        guard fileDescriptor >= 0 else {
            NSLog("GAP: Failed to open bundle path for monitoring: \(bundlePath)")
            return
        }

        // Create dispatch source to monitor file system events
        dispatchSource = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fileDescriptor,
            eventMask: [.delete, .rename, .revoke],
            queue: .main
        )

        dispatchSource?.setEventHandler { [weak self] in
            guard let self = self else { return }

            // Check which event occurred
            let flags = self.dispatchSource?.data ?? []

            if flags.contains(.delete) || flags.contains(.rename) || flags.contains(.revoke) {
                NSLog("GAP: Bundle path event detected - delete:\(flags.contains(.delete)), rename:\(flags.contains(.rename)), revoke:\(flags.contains(.revoke))")

                // Verify the app is actually gone or in Trash
                // Small delay to let the move complete
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                    if self.isAppInTrashOrDeleted() {
                        self.onDeleted()
                    }
                }
            }
        }

        dispatchSource?.setCancelHandler { [weak self] in
            guard let self = self, self.fileDescriptor >= 0 else { return }
            close(self.fileDescriptor)
            self.fileDescriptor = -1
        }

        dispatchSource?.resume()
        NSLog("GAP: Started monitoring bundle path: \(bundlePath)")
    }

    func stopMonitoring() {
        dispatchSource?.cancel()
        dispatchSource = nil
    }

    private func isAppInTrashOrDeleted() -> Bool {
        // Check if original path still exists
        if !FileManager.default.fileExists(atPath: bundlePath) {
            NSLog("GAP: App no longer exists at original path")
            return true
        }

        // Check if we've been moved to Trash
        // When an app is in Trash, its path changes to ~/.Trash/
        if let currentPath = Bundle.main.executablePath {
            if currentPath.contains("/.Trash/") {
                NSLog("GAP: App is now in Trash")
                return true
            }
        }

        return false
    }
}

@main
struct GAPApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @StateObject private var appState = AppState()

    @Environment(\.openWindow) var openWindow

    var body: some Scene {
        MenuBarExtra {
            // Use standard menu items for reliability
            if !appState.serverInstalled {
                Button("Install Server") {
                    try? "Menu Install at \(Date())".write(toFile: "/tmp/gap-menu-install.txt", atomically: true, encoding: .utf8)
                    appState.installServer()
                }
            } else if appState.serverRunning {
                Text("✓ Server Running")
                Button("Stop Server") {
                    appState.stopServer()
                }
            } else {
                Text("○ Server Stopped")
                Button("Start Server") {
                    appState.startServer()
                }
            }

            Divider()

            Button("Open Gap...") {
                openWindow(id: "main")
                NSApp.activate(ignoringOtherApps: true)
            }

            Divider()

            Button("Quit Gap") {
                NSApplication.shared.terminate(nil)
            }
        } label: {
            Image(systemName: appState.serverRunning ? "lock.shield.fill" : "lock.shield")
        }

        Window("Gap", id: "main") {
            ContentView()
                .environmentObject(appState)
        }
        .defaultSize(width: 700, height: 500)
    }
}

struct ContentView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        let _ = try? "ContentView: installed=\(appState.serverInstalled), running=\(appState.serverRunning), initialized=\(appState.serverInitialized), auth=\(appState.isAuthenticated) at \(Date())".write(toFile: "/tmp/gap-state.txt", atomically: true, encoding: .utf8)

        if !appState.serverInstalled {
            ServerInstallView()
        } else if !appState.serverRunning {
            ServerStartView()
        } else if !appState.serverInitialized {
            ServerInitView()
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

            Text("Gap Server Not Installed")
                .font(.headline)

            Text("The Gap server needs to be installed before you can use the app.")
                .multilineTextAlignment(.center)
                .foregroundColor(.secondary)
                .frame(width: 300)

            Button("Install Server") {
                print("BUTTON PRESSED")
                NSLog("Gap: Install button clicked!")
                let result = "Button clicked at \(Date())"
                do {
                    try result.write(toFile: "/tmp/gap-button-click.txt", atomically: true, encoding: .utf8)
                    print("Wrote to file")
                } catch {
                    print("Write failed: \(error)")
                }
                appState.installServer()
            }
            .buttonStyle(.borderedProminent)
            .onHover { hovering in
                if hovering {
                    try? "Hovering at \(Date())".write(toFile: "/tmp/gap-hover.txt", atomically: true, encoding: .utf8)
                }
            }
        }
        .padding(40)
        .frame(width: 400, height: 300)
        .onAppear {
            try? "ServerInstallView appeared at \(Date())".write(toFile: "/tmp/gap-view-appeared.txt", atomically: true, encoding: .utf8)
            print("ServerInstallView onAppear")
        }
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

            Text("Gap Server Stopped")
                .font(.headline)

            Text("The server is installed but not currently running.")
                .multilineTextAlignment(.center)
                .foregroundColor(.secondary)
                .frame(width: 300)

            HStack(spacing: 12) {
                Button("Start Server") {
                    appState.startServer()
                    // Check status after starting to update initialized state
                    Task {
                        try? await Task.sleep(nanoseconds: 2_000_000_000) // Wait 2 seconds
                        await appState.checkServerStatus()
                    }
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

/// View shown when the server is running but not initialized
struct ServerInitView: View {
    @EnvironmentObject var appState: AppState
    @State private var password = ""
    @State private var confirmPassword = ""
    @State private var errorMessage: String?
    @State private var isLoading = false

    var passwordsMatch: Bool {
        !password.isEmpty && password == confirmPassword
    }

    var passwordValid: Bool {
        password.count >= 8
    }

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "key.fill")
                .font(.system(size: 48))
                .foregroundColor(.accentColor)

            Text("Set Up Gap Password")
                .font(.headline)

            Text("Create a password to secure your Gap server. This password will be required to manage plugins and tokens.")
                .multilineTextAlignment(.center)
                .foregroundColor(.secondary)
                .frame(width: 300)

            VStack(spacing: 12) {
                SecureField("Password (min 8 characters)", text: $password)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 280)

                SecureField("Confirm Password", text: $confirmPassword)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 280)
            }

            if let error = errorMessage {
                Text(error)
                    .foregroundColor(.red)
                    .font(.caption)
            }

            Button(action: initializeServer) {
                if isLoading {
                    ProgressView()
                        .scaleEffect(0.8)
                } else {
                    Text("Initialize Server")
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(!passwordsMatch || !passwordValid || isLoading)

            if !password.isEmpty && !passwordValid {
                Text("Password must be at least 8 characters")
                    .foregroundColor(.orange)
                    .font(.caption)
            } else if !password.isEmpty && !confirmPassword.isEmpty && !passwordsMatch {
                Text("Passwords do not match")
                    .foregroundColor(.orange)
                    .font(.caption)
            }
        }
        .padding(40)
        .frame(width: 400, height: 400)
        .onAppear {
            // Check status when view appears
            Task {
                await appState.checkServerStatus()
            }
        }
    }

    private func initializeServer() {
        isLoading = true
        errorMessage = nil

        Task {
            do {
                try await appState.initializeServer(password: password)
            } catch {
                errorMessage = error.localizedDescription
            }
            isLoading = false
        }
    }
}
