#!/bin/bash
#
# Start mitmproxy to inspect HTTPS traffic from Cursor
#
# This script starts mitmproxy with optimal settings for monitoring AI tool traffic

PORT=${1:-8889}

echo "Starting mitmproxy on port $PORT..."
echo ""
echo "📋 Quick Guide:"
echo "  - Press 'q' then 'y' to quit"
echo "  - Press 'f' to filter traffic (e.g., '~d api2.cursor.sh')"
echo "  - Press 'enter' on a request to see details"
echo "  - Press 'tab' to switch between request/response"
echo "  - Press 'z' to clear the flow list"
echo ""
echo "🔐 First time? You need to install the CA certificate:"
echo "  1. After mitmproxy starts, open: ~/.mitmproxy/mitmproxy-ca-cert.pem"
echo "  2. Double-click to add to Keychain"
echo "  3. Find 'mitmproxy' in Keychain Access"
echo "  4. Right-click → Get Info → Trust → Always Trust"
echo "  5. Restart Cursor"
echo ""
echo "🚀 Launch Cursor with: ./launch-cursor-with-mitmproxy.sh"
echo ""
echo "Press Enter to continue..."
read

# Start mitmproxy with useful options
mitmproxy \
  --listen-port "$PORT" \
  --set flow_detail=3 \
  --set console_focus_follow=true

