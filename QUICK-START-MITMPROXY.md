# Quick Start: Inspect Cursor Traffic with mitmproxy

## 🎯 Goal
See the actual content being sent to/from Cursor's AI API, including your code, prompts, and responses.

## ⚡ 3-Step Setup

### Step 1: Install & Trust the Certificate

```bash
# Generate the certificate (first time only)
mitmproxy
# Wait for it to start, then press 'q' and 'y' to quit

# Install and trust the certificate
./install-mitmproxy-cert.sh
# You'll need to enter your password when prompted
```

✅ **Verify**: Check that "mitmproxy" appears in Keychain Access as a trusted certificate.

### Step 2: Start mitmproxy

**Choose one option:**

```bash
# Option A: With automatic DLP analysis (RECOMMENDED)
./start-mitmproxy-analyzer.sh
```
This shows color-coded analysis:
- 🔴 BLOCKED - API keys, passwords, secrets
- 🟡 SUSPICIOUS - Code patterns, SQL, file paths
- 🟢 SAFE - No sensitive data

```bash
# Option B: Interactive UI (for manual exploration)
./start-mitmproxy.sh
```
Navigate with arrow keys, press Enter to view details.

```bash
# Option C: Simple console logging
./start-mitmdump.sh
```
Just logs all traffic to console.

### Step 3: Launch Cursor

```bash
# In a NEW terminal window:
./launch-cursor-with-mitmproxy.sh
```

This automatically:
- Checks if mitmproxy is running
- Sets proxy environment variables
- Launches Cursor with proxy configured

## 🎉 You're Done!

Now use Cursor normally (ask questions, use autocomplete, etc.) and watch the mitmproxy terminal to see:

- **Every request** sent to Cursor's API
- **Your actual code** and prompts
- **AI responses** and completions
- **Sensitive data detection** (if using the analyzer)

## 📊 Example Output (with analyzer)

When you ask Cursor a question, you'll see:

```
================================================================================
[SUSPICIOUS] REQUEST - 2024-11-21 14:30:45
================================================================================
Request Details:
  Method: POST
  URL: https://api2.cursor.sh/v1/chat/completions
  Host: api2.cursor.sh
  Size: 9876 bytes

Headers:
  authorization: Bearer eyJhbGc***
  content-type: application/json

Body Preview:
  {
    "model": "claude-3.5-sonnet",
    "messages": [
      {
        "role": "user",
        "content": "function calculateTotal(items) {\n  return items..."
      }
    ]
  }

⚠️  SUSPICIOUS FINDINGS:
  • function: 3 occurrence(s)
  • file_path: 5 occurrence(s)
================================================================================
```

## 🛑 To Stop

1. **Close Cursor** (Cmd+Q or just quit normally)
2. **Stop mitmproxy** (Press Ctrl+C in the mitmproxy terminal)
3. **Launch Cursor normally** (just click the app icon)

The proxy settings only affect the Terminal-launched instance.

## 🔍 Navigation Tips (Interactive Mode)

When using `./start-mitmproxy.sh`:

| Key | Action |
|-----|--------|
| **Arrow keys** | Navigate requests |
| **Enter** | View request details |
| **Tab** | Switch request/response/detail |
| **f** | Filter (e.g., `~d api2.cursor.sh`) |
| **z** | Clear the list |
| **q** | Go back / Quit |

## 📁 Files Created

- `start-mitmproxy.sh` - Interactive UI
- `start-mitmdump.sh` - Console logging
- `start-mitmproxy-analyzer.sh` - With DLP analysis
- `launch-cursor-with-mitmproxy.sh` - Launch Cursor with proxy
- `install-mitmproxy-cert.sh` - Install CA certificate
- `mitmproxy-analyzer.py` - Python DLP analyzer
- `MITMPROXY-GUIDE.md` - Full documentation

## 🆘 Troubleshooting

### Certificate Errors
```bash
# Check if certificate is installed
security find-certificate -c mitmproxy

# Reinstall if needed
./install-mitmproxy-cert.sh
```

### No Traffic Visible
```bash
# Check if mitmproxy is running
lsof -i :8889

# Test the proxy
curl -x http://localhost:8889 https://httpbin.org/get
```

### Cursor Won't Connect
1. Make sure mitmproxy is running BEFORE launching Cursor
2. Try closing Cursor completely (Cmd+Q)
3. Launch again with `./launch-cursor-with-mitmproxy.sh`

## 💡 What to Look For

### 🚨 Data You DON'T Want Sent
- API keys, passwords, tokens
- SSH private keys
- Database credentials
- Complete proprietary code
- Customer data
- Internal URLs/infrastructure

### ✅ Data That's Probably OK
- Short code snippets for context
- Public library imports
- Error messages (without secrets)
- General programming questions

## 📖 Next Steps

1. **Use Cursor normally** and observe what's being sent
2. **Take notes** on what data you see
3. **Update your DLP proxy** to detect similar patterns
4. **Test blocking** with `BLOCK_MODE=true` in your main proxy

See **[MITMPROXY-GUIDE.md](MITMPROXY-GUIDE.md)** for advanced usage!

