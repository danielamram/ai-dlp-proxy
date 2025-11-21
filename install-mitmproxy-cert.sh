#!/bin/bash
#
# Install and trust mitmproxy CA certificate
#
# This script automates the certificate installation process

CERT_DIR="$HOME/.mitmproxy"
CERT_FILE="$CERT_DIR/mitmproxy-ca-cert.pem"

echo "🔐 Installing mitmproxy CA Certificate..."
echo ""

# Check if certificate exists
if [ ! -f "$CERT_FILE" ]; then
    echo "❌ Certificate not found at: $CERT_FILE"
    echo ""
    echo "   Please run mitmproxy once to generate the certificate:"
    echo "   mitmproxy"
    echo ""
    echo "   Then run this script again."
    exit 1
fi

echo "✅ Certificate found: $CERT_FILE"
echo ""

# Remove any existing certificate first (to avoid duplicates)
echo "🗑️  Removing old certificate if present..."
sudo security delete-certificate -c mitmproxy -t 2>/dev/null || true

# Add to system keychain with trust
echo "📥 Adding certificate to system keychain..."
echo "   (You'll need to enter your password)"
echo ""
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$CERT_FILE"

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Certificate installed successfully!"
    echo ""
    echo "🔍 Verifying trust settings..."
    if security verify-cert -c "$CERT_FILE" 2>/dev/null; then
        echo "✅ Certificate is properly trusted!"
    else
        echo "⚠️  Certificate installed but may need manual trust"
        echo ""
        echo "If you get TLS handshake errors, run:"
        echo "  ./fix-mitmproxy-trust.sh"
        echo ""
        echo "Or manually trust in Keychain Access:"
        echo "  1. Open Keychain Access"
        echo "  2. Search for 'mitmproxy'"
        echo "  3. Double-click certificate"
        echo "  4. Set Trust to 'Always Trust'"
    fi
    echo ""
    echo "🎉 You can now use mitmproxy to inspect HTTPS traffic!"
    echo ""
    echo "Next steps:"
    echo "  1. Start mitmproxy: ./start-mitmproxy-analyzer.sh"
    echo "  2. Launch Cursor: ./launch-cursor-with-mitmproxy.sh"
    echo "  3. Use Cursor normally - all traffic will be visible"
    echo ""
    echo "If you see TLS handshake errors:"
    echo "  ./fix-mitmproxy-trust.sh"
else
    echo ""
    echo "❌ Failed to install certificate"
    echo ""
    echo "Manual installation:"
    echo "  1. Open: $CERT_FILE"
    echo "  2. Double-click to add to Keychain"
    echo "  3. Open Keychain Access"
    echo "  4. Find 'mitmproxy' certificate"
    echo "  5. Double-click it"
    echo "  6. Expand 'Trust' section"
    echo "  7. Set 'When using this certificate' to 'Always Trust'"
    echo "  8. Close (enter your password when prompted)"
fi

