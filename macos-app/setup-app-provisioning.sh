#!/bin/bash
# Set up provisioning profiles for Gap.app and gap-server helper
set -e

cd "$(dirname "$0")"

MAIN_BUNDLE_ID="com.mikekelly.gap"
HELPER_BUNDLE_ID="com.mikekelly.gap-server"

echo "=== Setting up Provisioning for Gap.app ==="
echo ""
echo "This will create:"
echo "1. App ID: ${MAIN_BUNDLE_ID}"
echo "2. App ID: ${HELPER_BUNDLE_ID}"
echo "3. Development provisioning profiles for both"
echo ""
echo "You'll be prompted for your Apple ID password and 2FA code."
echo ""

# Get current device UDID
DEVICE_UDID=$(system_profiler SPHardwareDataType | grep "Provisioning UDID" | awk '{print $3}')
DEVICE_NAME=$(scutil --get ComputerName)
echo "Device UDID: $DEVICE_UDID"
echo "Device Name: $DEVICE_NAME"

# Register device
echo ""
echo "=== Step 1: Registering Device ==="
fastlane run register_device udid:"$DEVICE_UDID" name:"$DEVICE_NAME" platform:mac || echo "Device may already be registered, continuing..."

# Create main app ID
echo ""
echo "=== Step 2: Creating Main App ID ==="
fastlane produce -u mikekelly321@gmail.com -a "$MAIN_BUNDLE_ID" --app_name "GAP" --skip_itc --platform osx || echo "App ID may already exist, continuing..."

# Create helper app ID
echo ""
echo "=== Step 3: Creating Helper App ID ==="
fastlane produce -u mikekelly321@gmail.com -a "$HELPER_BUNDLE_ID" --app_name "GAP Server" --skip_itc --platform osx || echo "App ID may already exist, continuing..."

# Download/create provisioning profiles
mkdir -p build

echo ""
echo "=== Step 4: Creating Main App Provisioning Profile ==="
fastlane sigh -u mikekelly321@gmail.com -a "$MAIN_BUNDLE_ID" --development --platform macos --output_path build/ --filename "main.mobileprovision" --force

echo ""
echo "=== Step 5: Creating Helper Provisioning Profile ==="
fastlane sigh -u mikekelly321@gmail.com -a "$HELPER_BUNDLE_ID" --development --platform macos --output_path build/ --filename "helper.mobileprovision" --force

echo ""
echo "=== Done! ==="
echo ""
echo "Provisioning profiles created:"
echo "  - build/main.mobileprovision (for Gap.app)"
echo "  - build/helper.mobileprovision (for gap-server.app)"
echo ""
echo "Next steps:"
echo "  1. Run ./build-dmg.sh to create the app bundle"
echo "  2. Run ./sign-and-package.sh to sign and create DMG"
