# Fixing Certificate Trust Issues

## The Problem

You're seeing this error:
```
Client TLS handshake failed. The client disconnected during the handshake.
If this happens consistently for api2.cursor.sh, this may indicate that 
the client does not trust the proxy's certificate.
```

This means the mitmproxy certificate is installed but **not trusted**.

## The Solution

### Option 1: Automatic Fix (Recommended)

```bash
./fix-mitmproxy-trust.sh
```

This will:
1. Remove any existing mitmproxy certificates
2. Reinstall with proper trust settings
3. Verify the certificate is trusted

Then:
1. **Completely quit Cursor** (Cmd+Q, not just close window)
2. **Relaunch Cursor**: `./launch-cursor-with-mitmproxy.sh`

### Option 2: Manual Fix

If the automatic fix doesn't work, do this manually:

#### Step 1: Open Keychain Access
- Press **Cmd+Space**, type "Keychain Access", press Enter

#### Step 2: Find the Certificate
- In the search box (top right), type: **mitmproxy**
- You should see a certificate named "mitmproxy"
- If you see multiple, work with the one in "System" keychain

#### Step 3: Trust the Certificate
1. **Double-click** the mitmproxy certificate
2. Click the **▶** arrow next to "Trust"
3. Find the dropdown "**When using this certificate:**"
4. Change from "Use System Defaults" to **"Always Trust"**
5. **Close the window** (click the red X or Cmd+W)
6. Enter your **password** when prompted
7. The certificate should now show a blue **"+"** icon

#### Step 4: Verify
```bash
# This should succeed now
security verify-cert -c ~/.mitmproxy/mitmproxy-ca-cert.pem
```

#### Step 5: Restart Cursor
1. **Completely quit Cursor**: Press **Cmd+Q** (or Cursor menu → Quit)
2. Wait a few seconds
3. **Relaunch with proxy**: `./launch-cursor-with-mitmproxy.sh`

## Visual Guide: Keychain Access

```
┌─────────────────────────────────────────────────────────────┐
│  Keychain Access                                      🔍 mitmproxy │
├─────────────────────────────────────────────────────────────┤
│  Keychains          │ Category: Certificates               │
│  ├─ login           │                                      │
│  └─ System          │ Name              Kind    Expires    │
│                     │ mitmproxy    certificate    --       │
│                     │                                      │
└─────────────────────────────────────────────────────────────┘

Double-click "mitmproxy" →

┌─────────────────────────────────────────────────────────────┐
│  mitmproxy                                              ✕   │
├─────────────────────────────────────────────────────────────┤
│  ▼ Trust                                                    │
│    When using this certificate: [Always Trust ▼]           │
│    ✓ Always trust "mitmproxy" when connecting to...        │
│                                                             │
│  ▶ Details                                                  │
│  ▶ Access Control                                           │
│                                                             │
│                                    [Cancel]  [Save Changes] │
└─────────────────────────────────────────────────────────────┘
```

## Still Not Working?

### Check Certificate is Trusted
```bash
# Should show no errors
security verify-cert -c ~/.mitmproxy/mitmproxy-ca-cert.pem

# Should show trust settings
security dump-trust-settings -d | grep -A 10 mitmproxy
```

### Check mitmproxy is Running
```bash
# Should show mitmproxy process
lsof -i :8889
```

### Test with curl
```bash
# This should work if certificate is trusted
curl -x http://localhost:8889 https://api2.cursor.sh
```

If curl works but Cursor doesn't:
- Cursor might have its own certificate store
- Try restarting your Mac (sometimes required for trust changes)
- Check if Cursor has proxy/certificate settings in its preferences

### Nuclear Option: Restart Mac

Sometimes macOS needs a full restart for trust settings to take effect:

```bash
sudo shutdown -r now
```

After restart:
1. Start mitmproxy: `./start-mitmproxy-analyzer.sh`
2. Launch Cursor: `./launch-cursor-with-mitmproxy.sh`

## Common Mistakes

❌ **Not quitting Cursor completely**
   - Must use **Cmd+Q**, not just close windows
   
❌ **Setting trust in wrong keychain**
   - Must be in **System** keychain, not login
   
❌ **Certificate installed but not trusted**
   - Must set "When using this certificate" to "Always Trust"
   
❌ **Launching Cursor without proxy settings**
   - Must use `./launch-cursor-with-mitmproxy.sh`, not normal launch

## Success Indicators

When it's working, you should see:

**In mitmproxy terminal:**
```
🔍 HTTPS Request to api2.cursor.sh
   Method: POST
   Path: /v1/chat/completions
   Body: {"model": "claude-3.5-sonnet", ...}
```

**NOT this:**
```
Client TLS handshake failed. The client disconnected during the handshake.
```

## Need More Help?

1. Check mitmproxy logs for other error messages
2. Check Cursor's console logs: `~/Library/Logs/Cursor/`
3. Try with a simpler app first (like curl or a browser)
4. Make sure you're running the latest version of mitmproxy




