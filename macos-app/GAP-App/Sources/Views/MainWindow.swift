import SwiftUI

/// Main application window with tab-based navigation.
///
/// This window provides access to all major features:
/// - Plugins: View and manage installed plugins (including credentials)
/// - Tokens: Create, view, and revoke agent tokens
/// - Activity: View recent proxy request activity
/// - Management Log: View audit log entries for management API operations
///
/// The window uses a NavigationSplitView with a sidebar for tab selection
/// and a detail view that updates based on the selected tab.
struct MainWindow: View {
    @EnvironmentObject var appState: AppState
    @State private var selectedTab: Tab = .plugins

    enum Tab: String, CaseIterable {
        case plugins = "Plugins"
        case tokens = "Tokens"
        case activity = "Activity"
        case managementLog = "Management Log"

        var icon: String {
            switch self {
            case .plugins: return "puzzlepiece"
            case .tokens: return "key"
            case .activity: return "list.bullet"
            case .managementLog: return "doc.text.magnifyingglass"
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
            case .activity:
                ActivityView()
            case .managementLog:
                ManagementLogView()
            }
        }
        .frame(minWidth: 600, minHeight: 400)
    }
}
