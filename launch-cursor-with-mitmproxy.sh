#!/bin/bash
#
# Launch Cursor with mitmproxy configured
#
# This script sets the proxy environment variables and launches Cursor

PORT=${1:-8889}

echo "🚀 Launching Cursor with mitmproxy proxy..."
echo "   Proxy: http://localhost:$PORT"
echo ""
echo "⚠️  Make sure mitmproxy is running first!"
echo "   Run: ./start-mitmproxy.sh"
echo "   or:  ./start-mitmdump.sh"
echo ""

# Check if mitmproxy is running
if ! lsof -i ":$PORT" > /dev/null 2>&1; then
    echo "❌ ERROR: No proxy listening on port $PORT"
    echo "   Please start mitmproxy first with: ./start-mitmproxy.sh"
    exit 1
fi

echo "✅ Proxy detected on port $PORT"
echo "   Starting Cursor..."
echo ""

# Set proxy environment variables and launch Cursor
export HTTP_PROXY="http://localhost:$PORT"
export HTTPS_PROXY="http://localhost:$PORT"
export NO_PROXY="localhost,127.0.0.1"

# Launch Cursor
/Applications/Cursor.app/Contents/MacOS/Cursor &

echo "✅ Cursor launched with proxy configuration"
echo ""
echo "📊 All HTTPS traffic will now be visible in mitmproxy!"
echo ""
echo "To stop using the proxy:"
echo "  1. Close Cursor"
echo "  2. Stop mitmproxy (Ctrl+C or 'q' then 'y')"
echo "  3. Launch Cursor normally"

