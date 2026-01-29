#!/bin/bash
# Build Gap.app with embedded gap-server helper and create DMG
set -e

cd "$(dirname "$0")"

APP_NAME="Gap"
HELPER_NAME="gap-server"
BUNDLE_ID="com.mikekelly.gap"
HELPER_BUNDLE_ID="com.mikekelly.gap-server"
TEAM_ID="3R44BTH39W"

echo "=== Building Gap.app with embedded helper ==="

# Clean previous build
rm -rf build/${APP_NAME}.app build/*.dmg

# 1. Build gap-server if not already built
if [ ! -f "../target/release/gap-server" ]; then
    echo "Building gap-server..."
    (cd .. && cargo build --release --bin gap-server)
fi

# 2. Create main app bundle structure
echo "Creating app bundle structure..."
mkdir -p "build/${APP_NAME}.app/Contents/MacOS"
mkdir -p "build/${APP_NAME}.app/Contents/Resources"

# 3. Create main app Info.plist
cat > "build/${APP_NAME}.app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>${BUNDLE_ID}</string>
    <key>CFBundleName</key>
    <string>${APP_NAME}</string>
    <key>CFBundleDisplayName</key>
    <string>Gap</string>
    <key>CFBundleExecutable</key>
    <string>${APP_NAME}</string>
    <key>CFBundleVersion</key>
    <string>1.0.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
    <key>LSApplicationCategoryType</key>
    <string>public.app-category.developer-tools</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>CFBundleIconName</key>
    <string>AppIcon</string>
</dict>
</plist>
EOF

# 4. Copy gap-server binary to Resources
echo "Copying gap-server binary..."
cp "../target/release/gap-server" "build/${APP_NAME}.app/Contents/Resources/"

# 6. Build Swift main app
echo "Building Swift main app..."
if [ -d "GAP-App" ]; then
    (cd GAP-App && swift build -c release) || {
        echo "Swift build failed, using shell script fallback"
        USE_SHELL_FALLBACK=true
    }
fi

# 7. Copy main app binary and resources
if [ -f "GAP-App/.build/release/GAP" ] && [ -z "$USE_SHELL_FALLBACK" ]; then
    echo "Using Swift main app"
    cp "GAP-App/.build/release/GAP" "build/${APP_NAME}.app/Contents/MacOS/${APP_NAME}"

    # Compile asset catalog if it exists
    if [ -d "GAP-App/Sources/Assets.xcassets" ]; then
        echo "Compiling app icon assets..."
        xcrun actool "GAP-App/Sources/Assets.xcassets" \
            --compile "build/${APP_NAME}.app/Contents/Resources" \
            --platform macosx \
            --minimum-deployment-target 13.0 \
            --app-icon AppIcon \
            --output-partial-info-plist /tmp/assetcatalog_generated_info.plist
    fi
else
    echo "Using shell script fallback for main app"
    cat > "build/${APP_NAME}.app/Contents/MacOS/${APP_NAME}" <<'MAINAPP'
#!/bin/bash

PLIST_NAME="com.mikekelly.gap-server.plist"
LAUNCH_AGENTS_DIR="$HOME/Library/LaunchAgents"
HELPER_PATH="/Applications/Gap.app/Contents/Resources/gap-server"
PLIST_DST="$LAUNCH_AGENTS_DIR/$PLIST_NAME"

create_plist() {
    # Create logs directory if it doesn't exist
    mkdir -p "$HOME/.gap/logs"

    cat > "$PLIST_DST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.mikekelly.gap-server</string>
    <key>ProgramArguments</key>
    <array>
        <string>$HELPER_PATH</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$HOME/.gap/logs/gap-server.log</string>
    <key>StandardErrorPath</key>
    <string>$HOME/.gap/logs/gap-server.err</string>
</dict>
</plist>
PLIST
}

install_and_start() {
    mkdir -p "$LAUNCH_AGENTS_DIR"
    launchctl unload "$PLIST_DST" 2>/dev/null
    create_plist
    launchctl load "$PLIST_DST"
    sleep 1

    if launchctl list | grep -q "com.mikekelly.gap-server"; then
        osascript -e 'display dialog "GAP Server installed and running!\n\nIt will start automatically at login.\n\nUse the gap CLI to manage credentials and tokens." buttons {"OK"} default button "OK" with title "Gap"'
    else
        osascript -e 'display dialog "GAP Server installation failed.\n\nCheck /tmp/gap-server.log for details." buttons {"OK"} default button "OK" with icon stop with title "Gap - Error"'
    fi
}

show_status() {
    if launchctl list | grep -q "com.mikekelly.gap-server"; then
        STATUS="Running"
    else
        STATUS="Stopped"
    fi

    CHOICE=$(osascript -e 'display dialog "GAP Server Status: '"$STATUS"'\n\nThe server runs automatically at login." buttons {"Uninstall", "Reinstall", "OK"} default button "OK" with title "Gap"' -e 'button returned of result' 2>/dev/null)

    case "$CHOICE" in
        "Uninstall")
            launchctl unload "$PLIST_DST" 2>/dev/null
            rm -f "$PLIST_DST"
            osascript -e 'display dialog "GAP Server uninstalled." buttons {"OK"} default button "OK" with title "Gap"'
            ;;
        "Reinstall")
            install_and_start
            ;;
    esac
}

if [ ! -f "$PLIST_DST" ]; then
    install_and_start
else
    show_status
fi
MAINAPP
    chmod +x "build/${APP_NAME}.app/Contents/MacOS/${APP_NAME}"
fi

# 8. Create entitlements file
cat > "build/main.entitlements" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.app-sandbox</key>
    <false/>
</dict>
</plist>
EOF

echo ""
echo "=== App bundle created ==="
echo "To sign and create DMG, run: ./sign-and-package.sh"
echo ""
echo "Bundle structure:"
find "build/${APP_NAME}.app" -type f | head -20
