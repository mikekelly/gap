# Xcode Project Setup

## Adding Files to the Project

The following files have been created but need to be manually added to the Xcode project:

### Source Files
- `ACP/API/PasswordHash.swift` - Must be added to the ACP target

### Test Files
- `ACPTests/PasswordHashTests.swift` - Must be added to a test target (create if needed)

## Steps to Add Files

1. Open `ACP.xcodeproj` in Xcode
2. Add PasswordHash.swift to the main target:
   - Right-click the `API` folder in the project navigator
   - Select "Add Files to ACP..."
   - Navigate to `ACP/API/PasswordHash.swift`
   - Ensure the ACP target is checked
   - Click Add

3. Create and configure a test target (if not already exists):
   - File > New > Target
   - Select "Unit Testing Bundle" for macOS
   - Name it "ACPTests"
   - Set the target to be tested as "ACP"

4. Add PasswordHashTests.swift to the test target:
   - Right-click the test target in the project navigator
   - Select "Add Files to ACPTests..."
   - Navigate to `ACPTests/PasswordHashTests.swift`
   - Ensure the ACPTests target is checked
   - Click Add

5. Run tests:
   - Product > Test (Cmd+U)
   - Or click the test diamond next to each test function

## Verification

All tests have been verified to pass using standalone Swift compilation:
- Empty string hash matches expected SHA512 output
- "test" string hash matches expected SHA512 output
- Output format is always 128 lowercase hex characters
- Same input always produces same output (determinism)
