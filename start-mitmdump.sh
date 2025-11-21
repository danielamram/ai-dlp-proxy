#!/bin/bash
#
# Start mitmdump to log HTTPS traffic from Cursor
#
# This is the non-interactive version that logs all traffic to console

PORT=${1:-8889}
LOG_FILE="mitmproxy-traffic-$(date +%Y%m%d-%H%M%S).log"

echo "Starting mitmdump on port $PORT..."
echo "📝 Logging to: $LOG_FILE"
echo ""
echo "🔐 First time? You need to install the CA certificate:"
echo "  1. After mitmdump starts, open: ~/.mitmproxy/mitmproxy-ca-cert.pem"
echo "  2. Double-click to add to Keychain"
echo "  3. Find 'mitmproxy' in Keychain Access"
echo "  4. Right-click → Get Info → Trust → Always Trust"
echo "  5. Restart Cursor"
echo ""
echo "🚀 Launch Cursor with: ./launch-cursor-with-mitmproxy.sh"
echo ""
echo "Press Ctrl+C to stop..."
echo ""

# Start mitmdump with detailed logging
mitmdump \
  --listen-port "$PORT" \
  --set flow_detail=3 \
  --set hardump=true \
  --set termlog_verbosity=info \
  2>&1 | tee "$LOG_FILE"

