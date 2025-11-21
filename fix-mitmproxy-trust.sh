#!/bin/bash
#
# Fix mitmproxy certificate trust issues
#
# This script properly trusts the mitmproxy certificate for SSL/TLS

set -e

CERT_FILE="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"

echo "🔐 Fixing mitmproxy certificate trust..."
echo ""

# Check if certificate exists
if [ ! -f "$CERT_FILE" ]; then
    echo "❌ Certificate not found at: $CERT_FILE"
    echo ""
    echo "   Run mitmproxy first to generate it:"
    echo "   mitmproxy"
    echo "   (Press 'q' then 'y' to quit after it starts)"
    exit 1
fi

echo "✅ Certificate found: $CERT_FILE"
echo ""

# Remove existing certificate if present (to start fresh)
echo "🗑️  Removing old certificate if present..."
sudo security delete-certificate -c mitmproxy -t 2>/dev/null || true
security delete-certificate -c mitmproxy 2>/dev/null || true

echo ""
echo "📥 Installing certificate to System keychain..."
echo "   (You'll need to enter your password)"
echo ""

# Add to system keychain with trust settings
sudo security add-trusted-cert \
    -d \
    -r trustRoot \
    -k /Library/Keychains/System.keychain \
    "$CERT_FILE"

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Certificate installed and trusted!"
    echo ""
    echo "🔍 Verifying trust settings..."
    security verify-cert -c "$CERT_FILE" && echo "✅ Certificate is trusted!" || echo "⚠️  Still not trusted, see manual steps below"
    echo ""
    echo "🎉 You should now be able to use mitmproxy!"
    echo ""
    echo "Next steps:"
    echo "  1. Completely quit Cursor (Cmd+Q)"
    echo "  2. Make sure mitmproxy is running"
    echo "  3. Launch Cursor again: ./launch-cursor-with-mitmproxy.sh"
    echo ""
else
    echo ""
    echo "❌ Automatic installation failed. Try manual steps:"
    echo ""
    echo "1. Open Keychain Access app"
    echo "2. In the search box, type: mitmproxy"
    echo "3. Double-click the 'mitmproxy' certificate"
    echo "4. Expand the 'Trust' section"
    echo "5. Set 'When using this certificate' to: Always Trust"
    echo "6. Close the window (enter password when prompted)"
    echo "7. Completely quit Cursor (Cmd+Q)"
    echo "8. Relaunch with: ./launch-cursor-with-mitmproxy.sh"
fi




