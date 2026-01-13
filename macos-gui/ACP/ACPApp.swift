import SwiftUI

@main
struct ACPApp: App {
    @StateObject private var appState = AppState()

    var body: some Scene {
        MenuBarExtra {
            MenuBarView()
                .environmentObject(appState)
        } label: {
            Image(systemName: appState.isConnected ? "shield.checkered" : "shield.slash")
        }

        Window("ACP", id: "main") {
            ContentView()
                .environmentObject(appState)
        }
        .defaultSize(width: 700, height: 500)
    }
}

struct ContentView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        if appState.isAuthenticated {
            Text("Authenticated! Main UI coming soon...")
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            PasswordPrompt()
        }
    }
}
