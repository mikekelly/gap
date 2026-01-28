#!/usr/bin/env swift

import Foundation

// Delegate to accept self-signed certificates for localhost only
class InsecureURLSessionDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        print("Certificate challenge received for host: \(challenge.protectionSpace.host)")

        // Only trust localhost connections
        guard challenge.protectionSpace.host == "127.0.0.1" else {
            print("Not localhost, using default handling")
            completionHandler(.performDefaultHandling, nil)
            return
        }

        if let serverTrust = challenge.protectionSpace.serverTrust {
            print("Trusting certificate for localhost")
            let credential = URLCredential(trust: serverTrust)
            completionHandler(.useCredential, credential)
        } else {
            print("No server trust available")
            completionHandler(.performDefaultHandling, nil)
        }
    }
}

func checkServerRunning() -> Bool {
    print("Starting server check...")

    guard let url = URL(string: "https://127.0.0.1:9080/status") else {
        print("Invalid URL")
        return false
    }

    var request = URLRequest(url: url)
    request.timeoutInterval = 5
    print("Request configured with 5s timeout")

    let semaphore = DispatchSemaphore(value: 0)
    var running = false

    // Use custom session that trusts the self-signed certificate
    let delegate = InsecureURLSessionDelegate()
    let session = URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
    print("URLSession created with custom delegate")

    let task = session.dataTask(with: request) { data, response, error in
        print("Response received")

        if let error = error {
            print("Error: \(error.localizedDescription)")
        }

        if let httpResponse = response as? HTTPURLResponse {
            print("HTTP Status: \(httpResponse.statusCode)")
            if httpResponse.statusCode == 200 {
                running = true
            }
        }

        if let data = data, let body = String(data: data, encoding: .utf8) {
            print("Response body: \(body)")
        }

        semaphore.signal()
    }

    task.resume()
    print("Task started, waiting for response...")

    let timeout = semaphore.wait(timeout: .now() + 6)
    if timeout == .timedOut {
        print("Semaphore wait timed out!")
        return false
    }

    print("Check complete, running: \(running)")
    return running
}

print("=== Testing Gap Server Connection ===")
let result = checkServerRunning()
print("Final result: \(result)")
print("=== Test Complete ===")

// Keep the program alive for a moment
RunLoop.current.run(until: Date(timeIntervalSinceNow: 1))
