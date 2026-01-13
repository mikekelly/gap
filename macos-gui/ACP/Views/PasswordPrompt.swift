import SwiftUI

/// Password prompt view shown when the user is not authenticated.
///
/// This view presents a secure text field for password entry and authenticates
/// against the ACP Management API by hashing the password and verifying it
/// with an authenticated endpoint.
struct PasswordPrompt: View {
    @EnvironmentObject var appState: AppState
    @State private var password: String = ""
    @State private var isLoading: Bool = false
    @State private var errorMessage: String?

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "lock.shield")
                .font(.system(size: 48))
                .foregroundColor(.accentColor)

            Text("Enter ACP Password")
                .font(.headline)

            SecureField("Password", text: $password)
                .textFieldStyle(.roundedBorder)
                .frame(width: 250)
                .onSubmit { authenticate() }
                .disabled(isLoading)

            if let error = errorMessage {
                Text(error)
                    .foregroundColor(.red)
                    .font(.caption)
                    .multilineTextAlignment(.center)
                    .frame(width: 250)
            }

            Button(action: authenticate) {
                if isLoading {
                    ProgressView()
                        .scaleEffect(0.8)
                } else {
                    Text("Unlock")
                        .frame(width: 80)
                }
            }
            .disabled(password.isEmpty || isLoading)
            .keyboardShortcut(.defaultAction)
        }
        .padding(40)
        .frame(width: 350, height: 300)
    }

    private func authenticate() {
        guard !password.isEmpty else { return }
        isLoading = true
        errorMessage = nil

        Task {
            do {
                try await appState.authenticate(password: password)
            } catch let error as ACPError {
                errorMessage = error.localizedDescription
            } catch {
                errorMessage = error.localizedDescription
            }
            isLoading = false
        }
    }
}
