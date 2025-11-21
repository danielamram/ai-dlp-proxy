#!/bin/bash
#
# Start mitmdump with the Python analyzer script
#
# This combines mitmproxy with automatic sensitive data detection

PORT=${1:-8889}

echo "🔍 Starting mitmproxy with DLP analyzer..."
echo "   Port: $PORT"
echo ""
echo "🔐 First time? You need to install the CA certificate:"
echo "   Run: ./install-mitmproxy-cert.sh"
echo ""
echo "🚀 Launch Cursor with: ./launch-cursor-with-mitmproxy.sh"
echo ""
echo "This will show detailed analysis of all Cursor traffic including:"
echo "  • 🔴 BLOCKED - Critical patterns (API keys, passwords, etc.)"
echo "  • 🟡 SUSPICIOUS - Code patterns, file paths, SQL, etc."
echo "  • 🟢 SAFE - No sensitive data detected"
echo ""
echo "Press Ctrl+C to stop..."
echo ""

# Start mitmdump with the analyzer script
mitmdump --listen-port "$PORT" -s mitmproxy-analyzer.py

