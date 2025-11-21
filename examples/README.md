# Sensitive Data Examples

This directory contains example files that demonstrate the types of sensitive data the AI DLP Proxy is designed to detect.

## ⚠️ IMPORTANT: These are test examples only

All credentials, keys, and sensitive data in these files are **fake/example data** and should never be used in production systems.

## Files

### 1. `sensitive-data-blocked.json`
**Classification: BLOCKED** 🔴

Contains examples that would trigger immediate blocking (if `BLOCK_MODE=true`):

- **API Keys**: OpenAI, Stripe, AWS, GitHub tokens
- **Passwords**: Various password formats
- **JWT Tokens**: Bearer tokens and refresh tokens
- **Connection Strings**: MongoDB, PostgreSQL, MySQL, Redis with embedded credentials
- **SSH Keys**: RSA and Ed25519 private/public key pairs
- **Cloud Credentials**: AWS, Azure, GCP access keys

**Risk Level**: HIGH - These patterns indicate direct credential leakage

### 2. `sensitive-data-suspicious.js`
**Classification: SUSPICIOUS** 🟡

Contains examples that trigger suspicious classification:

- **Code Patterns**:
  - Function declarations and implementations
  - Class definitions with methods
  - Import/export statements
  - Python code blocks
  
- **Database Schemas**:
  - CREATE TABLE statements
  - ALTER TABLE statements
  - SELECT queries with JOINs
  - INSERT/UPDATE statements
  
- **File Paths**:
  - Unix/Linux paths (`/home/user/project/...`)
  - Windows paths (`C:\Users\...`)
  - Source file extensions (.js, .ts, .py, .go, etc.)
  
- **Environment Variables**:
  - `process.env.DATABASE_URL`
  - Environment variable patterns
  - Configuration references

- **Large Body Size**: Code blocks exceeding 5KB threshold

**Risk Level**: MEDIUM - Indicates potential intellectual property or architecture leakage

### 3. `sensitive-data-mixed.txt`
**Classification: BLOCKED + SUSPICIOUS** 🔴🟡

A realistic example of what might be accidentally shared with AI tools:

- User configuration files with embedded credentials
- Code snippets including auth middleware
- Database schema definitions
- SSH keys in config files
- Environment variable files (`.env` content)
- Project file structure
- AWS credentials file

**Risk Level**: VERY HIGH - Combines multiple risk factors

## Testing with curl

You can test these examples with your DLP proxy using curl:

```bash
# Start the proxy first
npm start

# Test with BLOCKED content
curl -x http://localhost:8888 http://httpbin.org/post \
  -X POST \
  -H "Content-Type: application/json" \
  -d @examples/sensitive-data-blocked.json

# Test with SUSPICIOUS content
curl -x http://localhost:8888 http://httpbin.org/post \
  -X POST \
  -H "Content-Type: application/javascript" \
  -d "$(cat examples/sensitive-data-suspicious.js)"

# Test with MIXED content
curl -x http://localhost:8888 http://httpbin.org/post \
  -X POST \
  -H "Content-Type: text/plain" \
  -d "$(cat examples/sensitive-data-mixed.txt)"
```

## Testing with Block Mode

Enable block mode to see requests get rejected:

```bash
BLOCK_MODE=true npm start

# This should get blocked
curl -x http://localhost:8888 http://httpbin.org/post \
  -X POST \
  -d "api_key: sk-proj-1234567890abcdefghijklmnopqrstuvwxyz"
```

## What You Should See

### SAFE Classification (Green)
```
✓ SAFE
No sensitive patterns detected
```

### SUSPICIOUS Classification (Yellow)
```
⚠ SUSPICIOUS
Findings:
  • Code patterns detected: 8 occurrences
  • File paths detected: 10 paths
  • Database schema pattern detected
```

### BLOCKED Classification (Red)
```
🛑 BLOCKED
Findings:
  • Credential pattern detected
  • SSH private key detected
Request blocked by DLP proxy
```

## Real-World Scenarios

These examples simulate common scenarios where sensitive data might leak:

1. **Asking AI for help with code** - Pasting authentication middleware with secrets
2. **Database migration help** - Sharing schema with connection strings
3. **Configuration issues** - Copying .env file contents
4. **SSH/deployment problems** - Including private keys
5. **API integration** - Exposing API keys in code snippets

## Best Practices

To avoid data leakage:

1. ✅ **Sanitize before sharing**: Remove credentials before pasting code
2. ✅ **Use placeholders**: Replace sensitive values with `YOUR_API_KEY`, `***`, etc.
3. ✅ **Share minimal code**: Only include relevant portions
4. ✅ **Check environment variables**: Never share actual `.env` contents
5. ✅ **Redact connection strings**: Remove usernames/passwords from URLs
6. ✅ **Use the DLP proxy**: Monitor what your AI tools are seeing

## Detection Patterns

The DLP proxy uses regex patterns to detect:

| Pattern Type | Example | Classification |
|-------------|---------|----------------|
| API Keys | `api_key: sk-...` | BLOCKED |
| Passwords | `password: "secret123"` | BLOCKED |
| JWT Tokens | `Bearer eyJ...` | BLOCKED |
| SSH Keys | `-----BEGIN PRIVATE KEY-----` | BLOCKED |
| Connection Strings | `postgresql://user:pass@...` | BLOCKED |
| Functions | `function myFunc() {` | SUSPICIOUS |
| SQL Statements | `CREATE TABLE users` | SUSPICIOUS |
| File Paths | `/src/components/Auth.tsx` | SUSPICIOUS |
| Env Variables | `process.env.API_KEY` | SUSPICIOUS |

## License

These examples are part of the AI DLP Proxy project and are provided for testing purposes only.



