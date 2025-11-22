#!/usr/bin/env python3
"""
mitmproxy script to analyze and detect sensitive data in Cursor traffic

Usage:
    mitmdump --listen-port 8889 -s mitmproxy-analyzer.py
"""

import re
import json
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
        'private_key': re.compile(r'-----BEGIN [A-Z ]+ PRIVATE KEY-----'),
        'aws_key': re.compile(r'AKIA[0-9A-Z]{16}'),
        'aws_secret': re.compile(r'aws[_-]?secret[_-]?access[_-]?key', re.IGNORECASE),
        'jwt': re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'),
        'credit_card': re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b'),
        'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        'connection_string': re.compile(r'(?:mongodb|postgres|mysql|redis|mssql):\/\/[^\s]+', re.IGNORECASE),
        'github_token': re.compile(r'gh[pousr]_[A-Za-z0-9]{36}'),
        'slack_token': re.compile(r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[A-Za-z0-9]{24}'),
        'azure_key': re.compile(r'[a-zA-Z0-9/+]{86}==', re.IGNORECASE),
    }
    
    # Patterns that are SUSPICIOUS
    SUSPICIOUS_PATTERNS = {
        'function': re.compile(r'\b(function|def|const|let|var)\s+\w+\s*\('),
        'class': re.compile(r'\b(class|interface|struct|enum)\s+\w+'),
        'import': re.compile(r'\b(import|require|from)\s+[\w.\'"\/]+'),
        'sql': re.compile(r'\b(SELECT|INSERT|UPDATE|DELETE|CREATE TABLE|ALTER TABLE|DROP TABLE)\b', re.IGNORECASE),
        'file_path': re.compile(r'(?:[/\\][\w/\\.-]{10,}|\w+[/\\][\w/\\.-]+\.(js|ts|py|java|cpp|go|rs|rb|php))'),
        'env_var': re.compile(r'(process\.env\.|os\.environ|ENV\[|getenv\()'),
        'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        'ip_address': re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
        'url': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
        'base64': re.compile(r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'),
    }
    
    def parse_body(self, body):
        """Parse body content and extract text from various formats"""
        if not body:
            return ""
        
        text = body
        parsed_data = {}
        
        # Try to parse as JSON
        try:
            parsed_data = json.loads(body)
            # Convert JSON back to pretty-printed string for pattern matching
            text = json.dumps(parsed_data, indent=2)
        except (json.JSONDecodeError, ValueError):
            # Not JSON, use raw text
            pass
        
        return text, parsed_data
    
    def extract_json_values(self, obj, depth=0, max_depth=10):
        """Recursively extract all string values from JSON object"""
        if depth > max_depth:
            return []
        
        values = []
        
        if isinstance(obj, dict):
            for key, value in obj.items():
                # Check key names for sensitive indicators
                key_lower = key.lower()
                if any(sensitive in key_lower for sensitive in ['password', 'secret', 'token', 'key', 'credential']):
                    values.append(f"SENSITIVE_KEY:{key}={value}")
                
                if isinstance(value, (str, int, float, bool)):
                    values.append(str(value))
                elif isinstance(value, (dict, list)):
                    values.extend(self.extract_json_values(value, depth + 1, max_depth))
        
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (str, int, float, bool)):
                    values.append(str(item))
                elif isinstance(item, (dict, list)):
                    values.extend(self.extract_json_values(item, depth + 1, max_depth))
        
        return values
    
    def analyze(self, body):
        """Analyze body for sensitive patterns with enhanced parsing"""
        if not body:
            return {
                'critical': [],
                'suspicious': [],
                'critical_samples': {},
                'suspicious_samples': {},
                'safe': True,
                'body_type': 'empty'
            }
        
        critical = []
        suspicious = []
        critical_samples = {}
        suspicious_samples = {}
        
        # Parse the body
        text, parsed_data = self.parse_body(body)
        body_type = 'json' if parsed_data else 'text'
        
        # For JSON, also check individual values
        json_values = []
        if parsed_data:
            json_values = self.extract_json_values(parsed_data)
        
        # Check critical patterns in main text
        for name, pattern in self.CRITICAL_PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                critical.append(f"{name}: {len(matches)} occurrence(s)")
                # Store samples
                samples = []
                for match in matches[:3]:  # Max 3 samples
                    if isinstance(match, tuple):
                        match = ' '.join(str(m) for m in match if m)
                    samples.append(mask_sensitive(str(match)))
                critical_samples[name] = samples
                continue
            
            # Also check in individual JSON values
            for value in json_values:
                if pattern.search(str(value)):
                    critical.append(f"{name}: found in JSON value")
                    critical_samples[name] = [mask_sensitive(str(value))]
                    break
        
        # Check suspicious patterns
        for name, pattern in self.SUSPICIOUS_PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                # Filter out common false positives
                if name == 'url' and len(matches) < 3:
                    continue  # A few URLs are OK
                suspicious.append(f"{name}: {len(matches)} occurrence(s)")
                # Store samples
                samples = []
                for match in matches[:3]:  # Max 3 samples
                    if isinstance(match, tuple):
                        match = ' '.join(str(m) for m in match if m)
                    samples.append(mask_sensitive(str(match), show_length=10))
                suspicious_samples[name] = samples
        
        # Additional checks
        body_size = len(body)
        if body_size > 10000:
            suspicious.append(f"large_body: {body_size} bytes")
        
        return {
            'critical': critical,
            'suspicious': suspicious,
            'critical_samples': critical_samples,
            'suspicious_samples': suspicious_samples,
            'safe': len(critical) == 0 and len(suspicious) == 0,
            'body_type': body_type,
            'body_size': body_size
        }

detector = SensitiveDataDetector()

def mask_sensitive(text, show_length=4):
    """Mask sensitive text for display"""
    if len(text) <= show_length * 2:
        return "***"
    return f"{text[:show_length]}...{text[-show_length:]}"

def format_header(text, color):
    """Format a header with color"""
    line = "=" * 80
    return f"{color}{Colors.BOLD}{line}\n{text}\n{line}{Colors.RESET}"

def get_sample_matches(body, pattern, max_samples=3):
    """Get sample matches for a pattern"""
    if not body:
        return []
    matches = pattern.findall(body)
    if not matches:
        return []
    
    # Handle tuples from patterns with groups
    samples = []
    for match in matches[:max_samples]:
        if isinstance(match, tuple):
            match = ' '.join(str(m) for m in match if m)
        samples.append(mask_sensitive(str(match)))
    
    return samples

def request(flow: http.HTTPFlow) -> None:
    """Analyze outgoing requests"""

    # Only analyze Cursor traffic (or all if you want)
    if "api2.cursor.sh" not in flow.request.pretty_host:
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Get request body
    body = flow.request.text or ""
    body_size = len(body)

    # Analyze body for sensitive data (ignoring headers as per user request)
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
    print(f"  Body Type: {findings.get('body_type', 'unknown')}")
    print(f"  Body Size: {findings.get('body_size', body_size)} bytes")
    
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
        
        # Show samples
        if findings.get('critical_samples'):
            print(f"\n{Colors.RED}Sample matches (masked):{Colors.RESET}")
            for pattern_name, samples in findings['critical_samples'].items():
                print(f"  {pattern_name}:")
                for sample in samples:
                    print(f"    - {sample}")
    
    if findings['suspicious']:
        print(f"\n{Colors.YELLOW}{Colors.BOLD}⚠️  SUSPICIOUS FINDINGS:{Colors.RESET}")
        for finding in findings['suspicious']:
            print(f"  • {finding}")
        
        # Show samples
        if findings.get('suspicious_samples'):
            print(f"\n{Colors.YELLOW}Sample matches (masked):{Colors.RESET}")
            for pattern_name, samples in findings['suspicious_samples'].items():
                print(f"  {pattern_name}:")
                for sample in samples[:2]:  # Show max 2 samples for suspicious
                    print(f"    - {sample}")
    
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

