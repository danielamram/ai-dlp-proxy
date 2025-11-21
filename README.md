# AI DLP Proxy

A Node.js Data Leakage Prevention (DLP) proxy for monitoring outbound traffic from AI tools like Cursor, GitHub Copilot, and other AI-assisted development tools.

## Features

- **HTTP/HTTPS proxy** with CONNECT tunnel support
- **Content analysis** for detecting sensitive data patterns
- **Classification system**: SAFE, SUSPICIOUS, BLOCKED
- **Pattern detection** for:
  - Credentials (API keys, passwords, tokens, SSH keys)
  - Code snippets (functions, classes, imports)
  - Database schemas (SQL statements, table definitions)
  - File paths (source files, project structure)
  - Environment variables

## Quick Start

```bash
# Install dependencies
npm install

# Setup CA certificate for TLS interception (required for HTTPS inspection)
npm run setup

# Start the proxy
npm start

# Or with options
PROXY_PORT=8888 BLOCK_MODE=true npm start
```

> **Note**: TLS interception is enabled by default. You must install and trust the CA certificate to inspect HTTPS traffic. Without it, applications will show certificate errors.

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_PORT` | 8888 | Port for the proxy server |
| `BLOCK_MODE` | false | Set to `true` to block suspicious requests |
| `LOG_FULL_BODY` | false | Log complete request bodies |
| `TARGET_HOSTS` | (all) | Comma-separated list of hosts to monitor |
| `TLS_INTERCEPT` | true | Enable TLS interception for HTTPS inspection |

Example:
```bash
PROXY_PORT=8080 BLOCK_MODE=true TARGET_HOSTS=api.openai.com,api.anthropic.com npm start
```

### TLS Interception Mode

**Enabled (default)**: Full HTTPS content inspection
- Decrypts HTTPS traffic for analysis
- Requires CA certificate installation
- Shows detailed findings (SAFE/SUSPICIOUS/BLOCKED)

**Disabled**: Transparent tunnel mode
```bash
TLS_INTERCEPT=false npm start
```
- Creates encrypted tunnels without inspection
- No certificate installation needed
- Only logs connection metadata (host, bytes transferred)

## Configuring Cursor/Apps to Use the Proxy

### Method 1: Environment Variables (Recommended for Cursor)

```bash
# Set for current terminal session
export HTTP_PROXY=http://localhost:8888
export HTTPS_PROXY=http://localhost:8888
export NO_PROXY=localhost,127.0.0.1

# Then launch Cursor from terminal
/Applications/Cursor.app/Contents/MacOS/Cursor
```

Or create a launcher script:
```bash
#!/bin/bash
export HTTP_PROXY=http://localhost:8888
export HTTPS_PROXY=http://localhost:8888
/Applications/Cursor.app/Contents/MacOS/Cursor
```

### Method 2: macOS System Proxy (Global)

1. Open **System Preferences** → **Network**
2. Select your active network (WiFi/Ethernet)
3. Click **Advanced** → **Proxies**
4. Enable **Web Proxy (HTTP)** and **Secure Web Proxy (HTTPS)**
5. Set server to `localhost` and port to `8888`
6. Click **OK** → **Apply**

### Method 3: Cursor Settings

Check Cursor's settings for proxy configuration:
- **Settings** → **Proxy** → Set `http://localhost:8888`

## Understanding the Logs

### Classification Levels

**SAFE** (Green)
- Request contains metadata only
- No sensitive patterns detected
- Typical API handshakes, version checks

**SUSPICIOUS** (Yellow)
- Code patterns detected (functions, classes, imports)
- File paths found
- Database schema references
- Environment variable references
- Large request body (>5KB)

**BLOCKED** (Red)
- Credentials detected (API keys, passwords, tokens)
- SSH/private keys found
- Database connection strings
- Request blocked if `BLOCK_MODE=true`

### Example Output

```
════════════════════════════════════════════════════════════════════════════════
[SUSPICIOUS] 2024-01-15T10:30:45.123Z
────────────────────────────────────────────────────────────────────────────────
Request:
  Method: POST
  URL: https://api.openai.com/v1/chat/completions
  Host: api.openai.com

Headers:
  content-type: application/json
  authorization: Bear***

Body Preview:
  {"model": "gpt-4", "messages": [{"role": "user", "content": "function calculateTotal...

Findings:
  • Code patterns detected: 5 occurrences
  • File paths detected: 3 paths

Code Patterns:
  - function calculateTotal(items) {
  - const taxRate = 0.08;
  - export default calculateTotal;
════════════════════════════════════════════════════════════════════════════════
```

## What Qualifies as "Raw Code Leakage"

### High Risk (BLOCKED)
- API keys: `API_KEY=sk-abc123...`
- Passwords: `password: "mysecret123"`
- Tokens: `Bearer eyJ...`
- SSH keys: `-----BEGIN RSA PRIVATE KEY-----`
- Connection strings: `mongodb://user:pass@host/db`

### Medium Risk (SUSPICIOUS)
- Complete functions/classes
- Import/export statements
- SQL queries with table names
- File paths revealing project structure
- Environment variable references

### Low Risk (SAFE)
- Short text queries
- Error messages (without stack traces)
- Documentation snippets
- Configuration metadata

## Validating with External Tools

### Using tcpdump

```bash
# Monitor HTTPS traffic on macOS
sudo tcpdump -i en0 -A port 443

# Filter for specific host
sudo tcpdump -i en0 host api.openai.com

# Save to file for analysis
sudo tcpdump -i en0 -w capture.pcap port 443
```

### Using Wireshark

1. Install Wireshark: `brew install wireshark`
2. Capture on main interface
3. Filter: `tcp.port == 443 && ip.dst == <AI-API-IP>`
4. Note: HTTPS content is encrypted; see TLS inspection below

### Using mitmproxy for Full HTTPS Inspection (Recommended)

**Important**: The basic proxy only shows HTTPS connection metadata. To inspect actual encrypted content, use mitmproxy:

#### Quick Start (3 Steps)

**1. Install CA Certificate**
```bash
# Generate certificate (run mitmproxy once)
mitmproxy  # Press 'q' then 'y' to quit

# Install & trust certificate
./install-mitmproxy-cert.sh
```

**2. Start mitmproxy**
```bash
# Interactive UI with full inspection
./start-mitmproxy.sh

# OR: With automatic DLP analysis (recommended)
./start-mitmproxy-analyzer.sh

# OR: Console logging only
./start-mitmdump.sh
```

**3. Launch Cursor with Proxy**
```bash
./launch-cursor-with-mitmproxy.sh
```

#### What You'll See

With mitmproxy, you can inspect:
- ✅ Actual request bodies (your code, prompts, file contents)
- ✅ AI responses (completions, suggestions)
- ✅ Complete headers and metadata
- ✅ Automatic detection of API keys, passwords, code patterns

#### Python Analyzer Script

The included `mitmproxy-analyzer.py` automatically classifies traffic:

- **🔴 BLOCKED**: API keys, passwords, tokens, SSH keys
- **🟡 SUSPICIOUS**: Code patterns, SQL queries, file paths
- **🟢 SAFE**: No sensitive data detected

#### Full Documentation

See **[MITMPROXY-GUIDE.md](MITMPROXY-GUIDE.md)** for:
- Detailed setup instructions
- Navigation and filtering tips
- Custom analysis scripts
- Troubleshooting guide

### Using curl to Test

```bash
# Test proxy with HTTP
curl -x http://localhost:8888 http://httpbin.org/post \
  -X POST -d '{"api_key": "sk-test123"}'

# Test with API key detection
curl -x http://localhost:8888 http://httpbin.org/post \
  -X POST -H "Content-Type: application/json" \
  -d '{"code": "function test() { const API_KEY = \"secret123\"; }"}'
```

## TLS Interception Setup

This proxy includes built-in TLS interception to inspect HTTPS traffic. Follow these steps:

### 1. Install the CA Certificate

Run the setup script:
```bash
npm run setup
```

This will:
- Generate a CA certificate (if not already present)
- Install it to your system's trusted root store
- Guide you through platform-specific steps

**Certificate location**: `certs/ca-cert.pem`

### 2. Manual Installation (if automatic fails)

#### macOS
```bash
# Add to system keychain
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain certs/ca-cert.pem

# Or use Keychain Access app:
# 1. Open Keychain Access
# 2. File → Import Items → Select certs/ca-cert.pem
# 3. Double-click "AI DLP Proxy CA"
# 4. Set Trust to "Always Trust"
```

#### Linux
```bash
# Ubuntu/Debian
sudo cp certs/ca-cert.pem /usr/local/share/ca-certificates/ai-dlp-proxy.crt
sudo update-ca-certificates

# RHEL/CentOS
sudo cp certs/ca-cert.pem /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust
```

#### Windows
```powershell
# Run as Administrator
certutil -addstore -f "ROOT" certs\ca-cert.pem
```

### 3. Restart Applications

After installing the certificate:
1. Restart your browser or application (Cursor, VS Code, etc.)
2. Start the proxy: `npm start`
3. Configure the application to use the proxy

### Troubleshooting TLS Interception

**Certificate Errors**
- Ensure the CA certificate is installed and trusted
- Restart the application after installing the certificate
- Check that TLS_INTERCEPT=true (default)

**No Content Inspection**
- Verify the certificate is in the system's trusted store
- Check proxy logs for "TLS Interception: ENABLED"
- Some apps may pin certificates and reject custom CAs

**Use Transparent Mode Instead**
If you can't install the certificate:
```bash
TLS_INTERCEPT=false npm start
```
This will tunnel HTTPS without inspection (connection metadata only).

## Known AI Tool Endpoints

Monitor these hosts to capture AI tool traffic:

```bash
# OpenAI
api.openai.com

# Anthropic
api.anthropic.com

# Azure OpenAI
*.openai.azure.com

# GitHub Copilot
copilot-proxy.githubusercontent.com
api.github.com

# Cursor
api2.cursor.sh
```

Set these as target hosts:
```bash
TARGET_HOSTS=api.openai.com,api.anthropic.com,api2.cursor.sh npm start
```

## Troubleshooting

### Proxy not receiving traffic
- Verify proxy is running: `curl -x http://localhost:8888 http://example.com`
- Check environment variables are set
- Restart the application after setting proxy

### Certificate errors with HTTPS
- The basic proxy tunnels HTTPS without inspection
- For content inspection, use mitmproxy with trusted CA

### App bypasses proxy
- Some apps ignore system proxy settings
- Use environment variables method
- Check app-specific proxy settings

## Security Considerations

- This tool is for authorized security testing and monitoring
- Only use on systems and applications you own or have permission to test
- Be aware of privacy implications when logging request bodies
- Store logs securely; they may contain sensitive data

## License

MIT
