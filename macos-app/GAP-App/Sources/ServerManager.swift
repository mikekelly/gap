import Foundation
import ServiceManagement

@MainActor
class ServerManager: ObservableObject {
    @Published var isRunning = false
    @Published var isInstalled = false

    private let helperBundleID = "com.mikekelly.gap-server"
    private let launchAgentLabel = "com.mikekelly.gap-server"
    private let launchAgentPath: String
    private let helperPath = "/Applications/GAP.app/Contents/Library/LoginItems/gap-server.app/Contents/MacOS/gap-server"

    init() {
        launchAgentPath = NSHomeDirectory() + "/Library/LaunchAgents/\(launchAgentLabel).plist"
        checkStatus()

        // Poll status every 5 seconds on main thread
        Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.checkStatus()
            }
        }
    }

    func checkStatus() {
        // Check if LaunchAgent is installed
        isInstalled = FileManager.default.fileExists(atPath: launchAgentPath)

        // Check if server is running by trying to connect to API
        isRunning = checkServerRunning()
    }

    private func checkServerRunning() -> Bool {
        guard let url = URL(string: "https://127.0.0.1:9080/status") else { return false }
        var request = URLRequest(url: url)
        request.timeoutInterval = 1

        let semaphore = DispatchSemaphore(value: 0)
        var running = false

        // Use custom session that trusts the self-signed certificate
        let delegate = InsecureURLSessionDelegate()
        let session = URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)

        session.dataTask(with: request) { data, response, error in
            if let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 {
                running = true
            }
            semaphore.signal()
        }.resume()

        semaphore.wait()
        return running
    }

    func install() {
        // Debug: write a marker file to verify this function is called
        try? "install() called at \(Date())".write(toFile: "/tmp/gap-install-debug.txt", atomically: true, encoding: .utf8)
        NSLog("GAP: install() called")

        // 1. Register as Login Item via SMAppService
        let service = SMAppService.loginItem(identifier: helperBundleID)
        do {
            try service.register()
            NSLog("GAP: Registered login item")
        } catch {
            NSLog("GAP: Failed to register login item: \(error)")
        }

        // 2. Install LaunchAgent for KeepAlive
        installLaunchAgent()

        // 3. Start the server
        start()
    }

    private func installLaunchAgent() {
        let plist: [String: Any] = [
            "Label": launchAgentLabel,
            "ProgramArguments": [helperPath],
            "RunAtLoad": true,
            "KeepAlive": true,
            "StandardOutPath": "/tmp/gap-server.log",
            "StandardErrorPath": "/tmp/gap-server.log"
        ]

        // Create LaunchAgents directory if needed
        let launchAgentsDir = NSHomeDirectory() + "/Library/LaunchAgents"
        do {
            try FileManager.default.createDirectory(atPath: launchAgentsDir, withIntermediateDirectories: true)
        } catch {
            NSLog("Failed to create LaunchAgents directory: \(error)")
        }

        // Write plist
        do {
            let plistData = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
            try plistData.write(to: URL(fileURLWithPath: launchAgentPath))
            NSLog("Installed LaunchAgent at \(launchAgentPath)")
        } catch {
            NSLog("Failed to write LaunchAgent plist: \(error)")
        }
    }

    func start() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        task.arguments = ["load", launchAgentPath]
        try? task.run()
        task.waitUntilExit()

        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
            self.checkStatus()
        }
    }

    func stop() {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        task.arguments = ["unload", launchAgentPath]
        try? task.run()
        task.waitUntilExit()

        checkStatus()
    }

    func uninstall() {
        // 1. Stop the server
        stop()

        // 2. Remove LaunchAgent
        try? FileManager.default.removeItem(atPath: launchAgentPath)

        // 3. Unregister Login Item
        let service = SMAppService.loginItem(identifier: helperBundleID)
        do {
            try service.unregister()
            print("Unregistered login item")
        } catch {
            print("Failed to unregister login item: \(error)")
        }

        checkStatus()
    }
}

// Delegate to accept self-signed certificates for localhost only
class InsecureURLSessionDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // Only trust localhost connections
        guard challenge.protectionSpace.host == "127.0.0.1" else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        if let serverTrust = challenge.protectionSpace.serverTrust {
            let credential = URLCredential(trust: serverTrust)
            completionHandler(.useCredential, credential)
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }
}
