#!/usr/bin/env python3
"""
mitmproxy script to analyze and detect sensitive data in Cursor traffic

Usage:
    mitmdump --listen-port 8889 -s mitmproxy-analyzer.py
"""

import re
from mitmproxy import http
from datetime import datetime

class Colors:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class SensitiveDataDetector:
    """Detect sensitive patterns in traffic"""
    
    # Patterns that should be BLOCKED
    CRITICAL_PATTERNS = {
        'api_key': re.compile(r'(api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})', re.IGNORECASE),
        'password': re.compile(r'password\s*[:=]\s*["\']([^"\']{3,})', re.IGNORECASE),
        'token': re.compile(r'(bearer|token)\s+([a-zA-Z0-9_-]{20,})', re.IGNORECASE),
        'ssh_key': re.compile(r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----'),
        'aws_key': re.compile(r'AKIA[0-9A-Z]{16}'),
        'jwt': re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'),
    }
    
    # Patterns that are SUSPICIOUS
    SUSPICIOUS_PATTERNS = {
        'function': re.compile(r'\b(function|def|const|let|var)\s+\w+\s*\('),
        'class': re.compile(r'\b(class|interface|struct)\s+\w+'),
        'import': re.compile(r'\b(import|require|from)\s+[\w.\'"\/]+'),
        'sql': re.compile(r'\b(SELECT|INSERT|UPDATE|DELETE|CREATE TABLE)\b', re.IGNORECASE),
        'file_path': re.compile(r'[/\\][\w/\\.-]{10,}'),
        'env_var': re.compile(r'process\.env\.|os\.environ|ENV\['),
    }
    
    def analyze(self, text):
        """Analyze text for sensitive patterns"""
        if not text:
            return {'critical': [], 'suspicious': [], 'safe': True}
        
        critical = []
        suspicious = []
        
        # Check critical patterns
        for name, pattern in self.CRITICAL_PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                critical.append(f"{name}: {len(matches)} occurrence(s)")
        
        # Check suspicious patterns
        for name, pattern in self.SUSPICIOUS_PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                suspicious.append(f"{name}: {len(matches)} occurrence(s)")
        
        return {
            'critical': critical,
            'suspicious': suspicious,
            'safe': len(critical) == 0 and len(suspicious) == 0
        }

detector = SensitiveDataDetector()

def format_header(text, color):
    """Format a header with color"""
    line = "=" * 80
    return f"{color}{Colors.BOLD}{line}\n{text}\n{line}{Colors.RESET}"

def request(flow: http.HTTPFlow) -> None:
    """Analyze outgoing requests"""
    
    # Only analyze Cursor traffic (or all if you want)
    if "api2.cursor.sh" not in flow.request.pretty_host:
        return
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Get request body
    body = flow.request.text or ""
    body_size = len(body)
    
    # Analyze for sensitive data
    findings = detector.analyze(body)
    
    # Determine classification
    if findings['critical']:
        classification = "BLOCKED"
        color = Colors.RED
    elif findings['suspicious']:
        classification = "SUSPICIOUS"
        color = Colors.YELLOW
    else:
        classification = "SAFE"
        color = Colors.GREEN
    
    # Print analysis
    print("\n" + format_header(f"[{classification}] REQUEST - {timestamp}", color))
    
    print(f"{Colors.BLUE}Request Details:{Colors.RESET}")
    print(f"  Method: {flow.request.method}")
    print(f"  URL: {flow.request.url}")
    print(f"  Host: {flow.request.pretty_host}")
    print(f"  Size: {body_size} bytes")
    
    if flow.request.headers:
        print(f"\n{Colors.BLUE}Headers:{Colors.RESET}")
        for key, value in flow.request.headers.items():
            # Redact authorization headers
            if key.lower() in ['authorization', 'cookie']:
                print(f"  {key}: {value[:20]}***")
            else:
                print(f"  {key}: {value}")
    
    # Show body preview
    if body:
        print(f"\n{Colors.BLUE}Body Preview:{Colors.RESET}")
        preview = body[:500]
        if len(body) > 500:
            preview += "..."
        print(f"  {preview}")
    
    # Show findings
    if findings['critical']:
        print(f"\n{Colors.RED}{Colors.BOLD}🚫 CRITICAL FINDINGS (SHOULD BLOCK):{Colors.RESET}")
        for finding in findings['critical']:
            print(f"  • {finding}")
    
    if findings['suspicious']:
        print(f"\n{Colors.YELLOW}{Colors.BOLD}⚠️  SUSPICIOUS FINDINGS:{Colors.RESET}")
        for finding in findings['suspicious']:
            print(f"  • {finding}")
    
    if findings['safe']:
        print(f"\n{Colors.GREEN}✅ No sensitive patterns detected{Colors.RESET}")
    
    print("=" * 80)

def response(flow: http.HTTPFlow) -> None:
    """Analyze incoming responses (optional)"""
    
    if "api2.cursor.sh" not in flow.request.pretty_host:
        return
    
    # Only log response summary
    print(f"\n{Colors.BLUE}📥 Response: {flow.response.status_code} - {len(flow.response.content)} bytes{Colors.RESET}")

# Example of blocking requests (if needed)
def request_block_example(flow: http.HTTPFlow) -> None:
    """Example of how to block requests with critical findings"""
    
    body = flow.request.text or ""
    findings = detector.analyze(body)
    
    if findings['critical']:
        # Block the request
        flow.response = http.Response.make(
            403,  # Forbidden
            b"Request blocked: Sensitive data detected by mitmproxy DLP",
            {"Content-Type": "text/plain"}
        )
        print(f"{Colors.RED}🚫 REQUEST BLOCKED!{Colors.RESET}")

