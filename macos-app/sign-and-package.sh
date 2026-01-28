#!/bin/bash
# Sign the app bundle and create DMG
# Run this after build-dmg.sh and setup-provisioning.sh (to get provisioning profile)
set -e

cd "$(dirname "$0")"

APP_NAME="Gap"
HELPER_NAME="gap-server"
BUNDLE_ID="com.mikekelly.gap"
HELPER_BUNDLE_ID="com.mikekelly.gap-server"

echo "=== Signing and Packaging Gap.app ==="

# Check app bundle exists
if [ ! -d "build/${APP_NAME}.app" ]; then
    echo "ERROR: build/${APP_NAME}.app not found. Run ./build-dmg.sh first."
    exit 1
fi

# Note: For Developer ID distribution, we do NOT embed provisioning profiles.
# Development profiles are restricted to specific device UDIDs and conflict with Developer ID signing.
# The Data Protection Keychain works with Developer ID + keychain-access-groups entitlement.
echo "Skipping provisioning profiles (not needed for Developer ID distribution)"

# Sign INSIDE-OUT (critical!)
echo ""
echo "=== Step 1: Signing gap-server binary (inside) ==="
codesign --sign "Developer ID Application: Mike Kelly (3R44BTH39W)" \
    --force \
    --options runtime \
    --timestamp \
    --entitlements "build/helper.entitlements" \
    "build/${APP_NAME}.app/Contents/Resources/${HELPER_NAME}"

echo "=== Step 2: Signing main app (outside) ==="
codesign --sign "Developer ID Application: Mike Kelly (3R44BTH39W)" \
    --force \
    --options runtime \
    --timestamp \
    --entitlements "build/main.entitlements" \
    "build/${APP_NAME}.app"

echo ""
echo "=== Step 3: Verifying signatures ==="
codesign --verify --deep --verbose=2 "build/${APP_NAME}.app"

echo ""
echo "=== Step 4: Creating DMG with Applications symlink ==="

# Create staging directory for DMG contents
STAGING_DIR="build/dmg-staging"
rm -rf "$STAGING_DIR"
mkdir -p "$STAGING_DIR"

# Copy signed app to staging
cp -R "build/${APP_NAME}.app" "$STAGING_DIR/"

# Check if create-dmg is installed
if command -v create-dmg &> /dev/null; then
    echo "Staging directory prepared (create-dmg will add Applications symlink)"
    # Use create-dmg/create-dmg with maximum icon size
    DMG_FILE="build/Gap Installer.dmg"
    rm -f "$DMG_FILE"

    create-dmg \
        --volname "${APP_NAME}" \
        --window-size 600 400 \
        --icon-size 128 \
        --icon "${APP_NAME}.app" 150 200 \
        --app-drop-link 450 200 \
        "$DMG_FILE" \
        "$STAGING_DIR"

    # Clean up staging directory
    rm -rf "$STAGING_DIR"

    echo ""
    echo "=== Step 5: Signing DMG ==="
    codesign -s "Developer ID Application: Mike Kelly (3R44BTH39W)" --timestamp "$DMG_FILE"
    echo "DMG signed: $DMG_FILE"

    echo ""
    echo "=== Done! ==="
    echo "DMG created and signed: $DMG_FILE"
    echo ""
    echo "To install:"
    echo "  1. Open the DMG"
    echo "  2. Drag GAP to Applications folder"
    echo "  3. First launch: right-click > Open (to bypass Gatekeeper)"
    echo "  4. Approve 'GAP Server' in System Settings > Login Items"
else
    echo "create-dmg not found. Install with: brew install create-dmg"
    echo ""
    echo "Creating DMG manually with hdiutil..."

    # Create Applications symlink for drag-and-drop installation (manual fallback)
    ln -s /Applications "$STAGING_DIR/Applications"
    echo "Staging directory prepared with Applications symlink"

    # Fallback to hdiutil
    rm -f "build/Gap Installer.dmg"
    hdiutil create -srcfolder "$STAGING_DIR" \
        -volname "${APP_NAME}" \
        -fs HFS+ \
        -format UDZO \
        "build/Gap Installer.dmg"

    # Clean up staging directory
    rm -rf "$STAGING_DIR"

    echo ""
    echo "=== Step 5: Signing DMG ==="
    codesign -s "Developer ID Application: Mike Kelly (3R44BTH39W)" --timestamp "build/Gap Installer.dmg"
    echo "DMG signed: build/Gap Installer.dmg"

    echo ""
    echo "=== Done! ==="
    echo "DMG created and signed: build/Gap Installer.dmg"
    echo ""
    echo "The DMG includes an Applications folder symlink for easy drag-and-drop installation."
fi
