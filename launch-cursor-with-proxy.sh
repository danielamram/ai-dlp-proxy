#!/bin/bash
# Launch Cursor with proxy configuration

export HTTP_PROXY=http://localhost:8888
export HTTPS_PROXY=http://localhost:8888
export NO_PROXY=localhost,127.0.0.1

echo "🚀 Launching Cursor with proxy settings:"
echo "   HTTP_PROXY=$HTTP_PROXY"
echo "   HTTPS_PROXY=$HTTPS_PROXY"
echo ""

/Applications/Cursor.app/Contents/MacOS/Cursor

