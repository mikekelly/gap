#!/bin/bash
# Test script to verify DMG staging directory structure
set -e

cd "$(dirname "$0")"

APP_NAME="Gap"
STAGING_DIR="build/dmg-staging"

echo "=== Testing DMG Staging Directory Creation ==="
echo ""

# Simulate the staging directory creation steps
echo "1. Creating staging directory..."
rm -rf "$STAGING_DIR"
mkdir -p "$STAGING_DIR"

# Create a dummy app bundle for testing
echo "2. Creating dummy Gap.app bundle..."
mkdir -p "build/${APP_NAME}.app/Contents"
echo "dummy" > "build/${APP_NAME}.app/Contents/dummy.txt"

# Copy app to staging
echo "3. Copying app to staging directory..."
cp -R "build/${APP_NAME}.app" "$STAGING_DIR/"

# Create Applications symlink
echo "4. Creating Applications symlink..."
ln -s /Applications "$STAGING_DIR/Applications"

# Verify the structure
echo ""
echo "=== Verification ==="
echo ""

if [ -d "$STAGING_DIR/${APP_NAME}.app" ]; then
    echo "✓ Gap.app exists in staging directory"
else
    echo "✗ Gap.app NOT found in staging directory"
    exit 1
fi

if [ -L "$STAGING_DIR/Applications" ]; then
    LINK_TARGET=$(readlink "$STAGING_DIR/Applications")
    if [ "$LINK_TARGET" = "/Applications" ]; then
        echo "✓ Applications symlink exists and points to /Applications"
    else
        echo "✗ Applications symlink points to wrong target: $LINK_TARGET"
        exit 1
    fi
else
    echo "✗ Applications symlink NOT found"
    exit 1
fi

# Show directory contents
echo ""
echo "Staging directory contents:"
ls -la "$STAGING_DIR"

# Clean up
echo ""
echo "Cleaning up test artifacts..."
rm -rf "$STAGING_DIR"
rm -rf "build/${APP_NAME}.app"

echo ""
echo "=== Test Passed! ==="
echo "The staging directory structure is created correctly."
