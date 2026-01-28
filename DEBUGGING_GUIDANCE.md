# Debugging Guidance

## URL Encoding in API Clients

**Pattern:** When building REST API URLs with path parameters that may contain special characters (especially forward slashes), always use a restrictive character set for URL encoding.

**Why:** Swift's `.urlPathAllowed` includes forward slash as an allowed character, which breaks URL routing when the parameter itself contains slashes (e.g., GitHub "owner/repo" format).

**Diagnostic:** If seeing HTTP 404 errors for endpoints that should exist, check if path parameters are being properly encoded. Plugin names, credential keys, and other identifiers may contain slashes.

**Fix:** Use a custom character set instead of `.urlPathAllowed`:
```swift
// Use alphanumerics only to ensure / is encoded
var allowed = CharacterSet.alphanumerics
allowed.insert(charactersIn: "-_.")
guard let encoded = value.addingPercentEncoding(withAllowedCharacters: allowed) else {
    throw GAPError.invalidURL
}
```

## Silent Failures in SwiftUI Async Functions

**Pattern:** SwiftUI views calling async functions that have guard clauses returning early may appear "broken" with no error feedback.

**Example:** AppState methods that check `guard serverRunning else { return }` or `guard let hash = passwordHash else { return }` will silently do nothing if preconditions aren't met.

**Diagnostic:** If a button appears not to work with no error message:
1. Check if the async function has guard clauses that return early
2. Verify app state (server running, authenticated, etc.)
3. Add logging or error handling for guard failures

**Fix:** Either propagate errors through guard clauses or add UX feedback for precondition failures.
