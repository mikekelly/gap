#!/bin/bash
# Verify that app icons are properly generated from source logo
set -e

cd "$(dirname "$0")/.."

SOURCE_LOGO="gap_logo.png"
BUILT_ICON="macos-app/build/Gap.app/Contents/Resources/AppIcon.icns"
ICONSET_DIR="macos-app/GAP-App/Sources/Assets.xcassets/AppIcon.appiconset"

if [ ! -f "$BUILT_ICON" ]; then
    echo "ERROR: Built app icon not found at $BUILT_ICON"
    echo "Run ./macos-app/build-dmg.sh first"
    exit 1
fi

# Extract built icon to temp location
TEMP_DIR=$(mktemp -d)
TEMP_ICONSET="$TEMP_DIR/icons.iconset"
iconutil -c iconset "$BUILT_ICON" -o "$TEMP_ICONSET" 2>/dev/null

# Check that extracted icons are not empty
if [ ! -f "$TEMP_ICONSET/icon_128x128.png" ]; then
    echo "ERROR: Built icon does not contain 128x128 size"
    rm -rf "$TEMP_DIR"
    exit 1
fi

# Check file size - new gradient icons should be larger than old text icons
SIZE=$(stat -f%z "$TEMP_ICONSET/icon_128x128.png")
if [ "$SIZE" -lt 10000 ]; then
    echo "ERROR: Icon file size too small ($SIZE bytes)"
    echo "Icon may not have been regenerated from updated source logo"
    echo "Run ./macos-app/regenerate-icons.sh and rebuild"
    rm -rf "$TEMP_DIR"
    exit 1
fi

rm -rf "$TEMP_DIR"
echo "OK: App icons verified successfully"
echo "Icon size: $SIZE bytes (128x128)"
