# Using mitmproxy to Inspect Cursor Traffic

This guide will help you use mitmproxy to see the actual content being sent to/from Cursor's AI API.

## Why mitmproxy?

Your current DLP proxy can only see:
- ✅ Connection metadata (host, port)
- ✅ Data transfer sizes
- ❌ **NOT** the actual encrypted HTTPS content

mitmproxy can decrypt HTTPS traffic by acting as a man-in-the-middle (with your permission via a trusted CA certificate).

## Quick Start (3 Steps)

### Step 1: Install & Trust the Certificate

First, generate the mitmproxy certificate:

```bash
# Start mitmproxy once to generate the certificate
mitmproxy

# Press 'q' then 'y' to quit after it starts
```

Then install the certificate:

```bash
# Automated installation (requires sudo password)
./install-mitmproxy-cert.sh

# OR manual installation:
# 1. Open ~/.mitmproxy/mitmproxy-ca-cert.pem
# 2. Double-click to add to Keychain
# 3. Open Keychain Access, find 'mitmproxy'
# 4. Right-click → Get Info → Trust → Always Trust
```

### Step 2: Start mitmproxy

Choose one:

**Option A: Interactive UI (recommended for exploration)**
```bash
./start-mitmproxy.sh
```

**Option B: Console logging (better for monitoring)**
```bash
./start-mitmdump.sh
```

### Step 3: Launch Cursor with Proxy

```bash
./launch-cursor-with-mitmproxy.sh
```

This script:
- Checks if mitmproxy is running
- Sets proxy environment variables
- Launches Cursor with proxy configuration

## Using mitmproxy Interactive UI

Once mitmproxy is running and Cursor is connected:

### Navigation
- **Arrow keys** - Navigate through requests
- **Enter** - View request/response details
- **Tab** - Switch between request/response/detail tabs
- **q** - Go back / Quit (then 'y' to confirm)
- **z** - Clear the flow list

### Filtering
Press **f** to filter traffic:

```
~d api2.cursor.sh           # Only show Cursor API traffic
~d api2.cursor.sh ~m POST   # Only POST requests to Cursor
~s                          # Only show responses
~b "code"                   # Bodies containing "code"
```

### Useful Commands
- **e** - Edit request/response (before sending)
- **r** - Replay request
- **C** - Export flow (save request/response)
- **/** - Search in current view
- **?** - Help menu

## What to Look For

When you use Cursor (e.g., ask a question, use autocomplete), you'll see:

### 1. Request Details
```
POST https://api2.cursor.sh/v1/chat/completions
Content-Type: application/json
Authorization: Bearer ...

{
  "model": "claude-3.5-sonnet",
  "messages": [
    {
      "role": "user",
      "content": "YOUR ACTUAL PROMPT HERE"
    }
  ],
  "context": {
    "files": [...],  // Your open files
    "code": "..."    // Your code snippets
  }
}
```

### 2. Response Details
```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": "chatcmpl-...",
  "choices": [
    {
      "message": {
        "role": "assistant",
        "content": "AI RESPONSE HERE"
      }
    }
  ]
}
```

## Detecting Data Leakage

Look for sensitive data in the request bodies:

### 🔴 High Risk (Should Block)
- API keys: `"api_key": "sk-..."`
- Passwords: `"password": "..."`
- Tokens: `"token": "..."`
- Private keys: `-----BEGIN RSA PRIVATE KEY-----`
- Database credentials: `mongodb://user:pass@...`

### 🟡 Medium Risk (Suspicious)
- Complete function implementations
- Database schemas
- File paths revealing project structure
- Large code blocks
- Environment variables

### 🟢 Low Risk (Safe)
- Short prompts
- Error messages (without stack traces)
- Documentation snippets
- Simple queries

## Saving Traffic for Analysis

### Save all traffic to file:
```bash
mitmdump --listen-port 8889 -w traffic.dump

# Later, view the saved traffic:
mitmproxy -r traffic.dump
```

### Filter and save specific traffic:
```bash
# Only save Cursor API traffic
mitmdump --listen-port 8889 "~d api2.cursor.sh" -w cursor-traffic.dump
```

### Export as JSON:
Press **C** in mitmproxy interactive mode to export the current flow.

## Comparing with Your DLP Proxy

You can run **both** proxies simultaneously:

### Terminal 1: Your DLP Proxy
```bash
npm start
# Runs on port 8888
```

### Terminal 2: mitmproxy
```bash
./start-mitmproxy.sh 8889
# Runs on port 8889
```

### Terminal 3: Test with curl
```bash
# Test DLP proxy (tunneled, no content inspection)
curl -x http://localhost:8888 https://httpbin.org/get

# Test mitmproxy (full content inspection)
curl -x http://localhost:8889 https://httpbin.org/get
```

## Creating Custom Scripts

You can create Python scripts to analyze traffic automatically:

```python
# save as analyze_traffic.py
from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    # Analyze request
    if "api2.cursor.sh" in flow.request.pretty_host:
        print(f"\n🔍 Cursor Request:")
        print(f"  URL: {flow.request.url}")
        print(f"  Body: {flow.request.text[:500]}")  # First 500 chars
        
        # Check for sensitive patterns
        body = flow.request.text or ""
        if "api_key" in body.lower():
            print(f"  ⚠️  API KEY DETECTED!")
        if "password" in body.lower():
            print(f"  ⚠️  PASSWORD DETECTED!")

def response(flow: http.HTTPFlow) -> None:
    # Analyze response
    if "api2.cursor.sh" in flow.request.pretty_host:
        print(f"\n📥 Cursor Response:")
        print(f"  Status: {flow.response.status_code}")
        print(f"  Body: {flow.response.text[:500]}")

# Run with:
# mitmdump --listen-port 8889 -s analyze_traffic.py
```

## Troubleshooting

### Certificate Errors in Cursor
If Cursor shows SSL/certificate errors:

1. **Verify certificate is installed and trusted:**
   ```bash
   security find-certificate -c mitmproxy -a -p
   ```

2. **Restart Cursor completely** (Cmd+Q then relaunch)

3. **Check certificate in Keychain Access:**
   - Open Keychain Access app
   - Search for "mitmproxy"
   - Verify it shows "This certificate is marked as trusted"

### No Traffic in mitmproxy
1. Verify Cursor is running with proxy settings
2. Check mitmproxy is listening: `lsof -i :8889`
3. Try a test request: `curl -x http://localhost:8889 https://httpbin.org/get`

### Cursor Won't Connect
1. Stop mitmproxy
2. Launch Cursor normally (without proxy)
3. Check Cursor works normally
4. Restart mitmproxy and try again

### Remove Proxy Settings
To stop using the proxy:

1. Close Cursor (Cmd+Q)
2. Stop mitmproxy (Ctrl+C)
3. Launch Cursor normally (just click the app icon)

The environment variables only affect the Terminal-launched instance.

## Next Steps

Once you see what data Cursor is sending:

1. **Identify patterns** - What code/data is being sent?
2. **Update your DLP proxy** - Add detection for those patterns
3. **Test blocking** - Use `BLOCK_MODE=true` to prevent leakage
4. **Create policies** - Define what should/shouldn't be sent

## Resources

- [mitmproxy Documentation](https://docs.mitmproxy.org/)
- [mitmproxy Addon Examples](https://docs.mitmproxy.org/stable/addons-examples/)
- [Filter Expressions](https://docs.mitmproxy.org/stable/concepts-filters/)

