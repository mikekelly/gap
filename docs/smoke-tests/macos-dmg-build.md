# Smoke Test: macOS DMG Build and Installation

> Last verified: 2026-01-20 | Status: PASS

## Prerequisites
- [ ] macOS development environment with Xcode tools
- [ ] Rust toolchain installed
- [ ] Build dependencies available (see macos-app/build-dmg.sh)
- [ ] Write access to /Applications directory

## Critical Path 1: Clean Existing Installation

**Goal:** Remove any running GAP processes and LaunchAgents to ensure clean slate for testing

### Steps
1. Unload existing LaunchAgent
   ```bash
   launchctl unload ~/Library/LaunchAgents/com.mikekelly.gap-server.plist 2>/dev/null || true
   ```
   - Expected: Command completes (may warn if plist doesn't exist)
   - [x] Pass
   - Result: Command completed successfully

2. Kill existing Gap.app processes
   ```bash
   pkill -f "Gap.app" 2>/dev/null || true
   ```
   - Expected: Command completes (may have no output if no processes found)
   - [x] Pass
   - Result: Command completed successfully

3. Kill existing gap-server processes
   ```bash
   pkill -f "com.mikekelly.gap-server" 2>/dev/null || true
   ```
   - Expected: Command completes (may have no output if no processes found)
   - [x] Pass
   - Result: Command completed successfully

### Result
- Status: PASS
- Notes: All cleanup steps completed without errors

## Critical Path 2: Build DMG Package

**Goal:** Execute build script and produce Gap.app bundle with all required components

### Steps
1. Run build-dmg.sh script
   ```bash
   cd /Users/mike/code/gap/macos-app
   ./build-dmg.sh
   ```
   - Expected: Script completes without errors, creates build/Gap.app
   - [x] Pass
   - Result: Build completed successfully in 1.89s. Created Gap.app bundle with Swift main app and gap-server LoginItem.

### Result
- Status: PASS
- Notes: Build script executed successfully, produced complete app bundle structure

## Critical Path 3: Verify Bundle Structure

**Goal:** Confirm app bundle has correct structure with main app and LoginItem executables

### Steps
1. Check main app MacOS directory
   ```bash
   ls -la /Users/mike/code/gap/macos-app/build/Gap.app/Contents/MacOS/
   ```
   - Expected: Directory exists with GAP executable
   - [x] Pass
   - Result: GAP executable present (996 KB, executable permissions set)

2. Check gap-server LoginItem MacOS directory
   ```bash
   ls -la /Users/mike/code/gap/macos-app/build/Gap.app/Contents/Library/LoginItems/gap-server.app/Contents/MacOS/
   ```
   - Expected: Directory exists with gap-server executable
   - [x] Pass
   - Result: gap-server executable present (19.1 MB, executable permissions set)

### Result
- Status: PASS
- Notes: Both executables present with correct structure and permissions

## Critical Path 4: Install to /Applications

**Goal:** Install built app to system Applications directory

### Steps
1. Remove existing installation
   ```bash
   rm -rf /Applications/Gap.app
   ```
   - Expected: Command completes (may have no output if app wasn't installed)
   - [x] Pass
   - Result: Command completed successfully

2. Copy new build to Applications
   ```bash
   cp -R /Users/mike/code/gap/macos-app/build/Gap.app /Applications/
   ```
   - Expected: Command completes, /Applications/Gap.app exists
   - [x] Pass
   - Result: App successfully copied to /Applications

### Result
- Status: PASS
- Notes: Installation to /Applications completed without errors

## Critical Path 5: Launch and Verify

**Goal:** Launch app and verify it runs correctly with expected runtime artifacts

### Steps
1. Launch the app
   ```bash
   open /Applications/Gap.app
   ```
   - Expected: Command completes, app launches (may appear in menu bar)
   - [x] Pass
   - Result: App launched successfully

2. Wait for startup (3 seconds)
   ```bash
   sleep 3
   ```
   - Expected: Delay completes
   - [x] Pass
   - Result: Delay completed

3. Check if Gap.app process is running
   ```bash
   pgrep -f "Gap.app"
   ```
   - Expected: Returns process ID(s)
   - [x] Pass
   - Result: Process running with PID 65410

4. Check for debug file creation
   ```bash
   cat /tmp/gap-app-started.txt
   ```
   - Expected: File exists with startup timestamp or debug info
   - [x] Pass
   - Result: File exists with content "GAPApp init at 2026-01-20 09:20:41 +0000"

5. Manual verification: Check menu bar for GAP icon
   - Expected: Icon visible in macOS menu bar
   - [ ] Pending
   - Notes: Requires visual inspection, cannot verify programmatically

### Result
- Status: PASS
- Notes: App launched successfully, process running, debug file created with timestamp

## Summary
| Path | Status | Notes |
|------|--------|-------|
| Clean Existing Installation | PASS | All cleanup steps completed successfully |
| Build DMG Package | PASS | Build completed in 1.89s with Swift app |
| Verify Bundle Structure | PASS | Both executables present with correct permissions |
| Install to /Applications | PASS | Installation completed without errors |
| Launch and Verify | PASS | App running (PID 65410), debug file created |

## Known Issues
None discovered during this smoke test run.
