import SwiftUI

@main
struct ACPApp: App {
    @StateObject private var appState = AppState()

    var body: some Scene {
        MenuBarExtra {
            Button("Quit ACP") {
                NSApplication.shared.terminate(nil)
            }
        } label: {
            Image(systemName: "shield.checkered")
        }
    }
}
