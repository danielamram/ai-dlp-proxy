#!/usr/bin/env python3
"""
mitmproxy script to analyze and detect sensitive data in Cursor traffic

Usage:
    mitmdump --listen-port 8889 -s mitmproxy-analyzer.py
"""

import re
import json
import gzip
import zlib
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
    
    def extract_strings_from_binary(self, data, min_length=4):
        """Extract readable ASCII/UTF-8 strings from binary data"""
        if isinstance(data, str):
            data = data.encode('utf-8', errors='ignore')

        strings = []
        current = []

        for byte in data:
            # Printable ASCII range (32-126) plus common whitespace
            if 32 <= byte <= 126 or byte in (9, 10, 13):
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []

        if len(current) >= min_length:
            strings.append(''.join(current))

        return strings

    def decompress_body(self, raw_body, content_encoding):
        """Decompress gzip/deflate body if needed"""
        if not raw_body:
            return raw_body

        try:
            if content_encoding == 'gzip':
                return gzip.decompress(raw_body)
            elif content_encoding == 'deflate':
                return zlib.decompress(raw_body)
        except Exception:
            pass

        return raw_body

    def parse_body(self, body, raw_body=None, content_encoding=None):
        """Parse body content and extract text from various formats including protobuf"""
        if not body and not raw_body:
            return "", {}

        text = body if body else ""
        parsed_data = {}
        extracted_strings = []

        # Handle binary/protobuf data
        if raw_body:
            # Decompress if needed
            decompressed = self.decompress_body(raw_body, content_encoding)

            # Extract readable strings from binary
            extracted_strings = self.extract_strings_from_binary(decompressed)

            # Join extracted strings for analysis
            if extracted_strings:
                text = '\n'.join(extracted_strings)

        # Try to parse as JSON (either from text or extracted strings)
        try:
            parsed_data = json.loads(body if body else text)
            text = json.dumps(parsed_data, indent=2)
        except (json.JSONDecodeError, ValueError, TypeError):
            pass

        # Also look for embedded JSON in extracted strings
        for s in extracted_strings:
            if s.startswith('{') or s.startswith('['):
                try:
                    embedded_json = json.loads(s)
                    text += '\n' + json.dumps(embedded_json, indent=2)
                except:
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

    def extract_user_prompt_and_files(self, parsed_data):
        """Extract user prompts and file attachments from Cursor request format"""
        result = {
            'user_prompts': [],
            'files': [],
            'model': None,
            'system_prompt': None
        }

        if not isinstance(parsed_data, dict):
            return result

        # Get model
        result['model'] = parsed_data.get('model', parsed_data.get('modelName'))

        # Extract messages - standard OpenAI/Anthropic format
        messages = parsed_data.get('messages', [])
        for msg in messages:
            if isinstance(msg, dict):
                role = msg.get('role', '')
                content = msg.get('content', '')

                if role == 'user':
                    # Handle content that can be string or array (for multimodal)
                    if isinstance(content, str):
                        result['user_prompts'].append(content)
                    elif isinstance(content, list):
                        for item in content:
                            if isinstance(item, dict):
                                if item.get('type') == 'text':
                                    result['user_prompts'].append(item.get('text', ''))
                                elif item.get('type') == 'image_url':
                                    result['files'].append(f"[Image: {item.get('image_url', {}).get('url', 'embedded')[:50]}...]")
                            elif isinstance(item, str):
                                result['user_prompts'].append(item)
                elif role == 'system':
                    if isinstance(content, str):
                        result['system_prompt'] = content

        # Extract file context - Cursor specific fields
        context = parsed_data.get('context', {})
        if isinstance(context, dict):
            # Files array
            files = context.get('files', [])
            for f in files:
                if isinstance(f, dict):
                    name = f.get('name', f.get('path', f.get('filename', 'unknown')))
                    result['files'].append(name)
                elif isinstance(f, str):
                    result['files'].append(f)

            # Code snippets
            code = context.get('code', context.get('codeContext', ''))
            if code:
                result['files'].append(f"[Code snippet: {len(code)} chars]")

        # Also check for documents/attachments (alternative formats)
        for key in ['documents', 'attachments', 'fileContents', 'codeBlocks']:
            items = parsed_data.get(key, [])
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        name = item.get('name', item.get('path', item.get('filename', '')))
                        if name:
                            result['files'].append(name)
                    elif isinstance(item, str):
                        result['files'].append(f"[{key}: {len(item)} chars]")

        # Check for inline file references in the prompt text
        for prompt in result['user_prompts']:
            # Look for @file patterns that Cursor uses
            at_mentions = re.findall(r'@([\w./\\-]+\.\w+)', prompt)
            for mention in at_mentions:
                if mention not in result['files']:
                    result['files'].append(f"@{mention}")

        return result
    
    def analyze(self, body, raw_body=None, content_encoding=None):
        """Analyze body for sensitive patterns with enhanced parsing"""
        if not body and not raw_body:
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

        # Parse the body (handles protobuf, gzip, JSON)
        text, parsed_data = self.parse_body(body, raw_body, content_encoding)
        body_type = 'protobuf' if raw_body and not parsed_data else ('json' if parsed_data else 'text')
        
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
        raw_size = len(raw_body) if raw_body else len(body)
        if raw_size > 10000:
            suspicious.append(f"large_body: {raw_size} bytes")

        # Extract user prompts and files
        prompt_info = self.extract_user_prompt_and_files(parsed_data)

        return {
            'critical': critical,
            'suspicious': suspicious,
            'critical_samples': critical_samples,
            'suspicious_samples': suspicious_samples,
            'safe': len(critical) == 0 and len(suspicious) == 0,
            'body_type': body_type,
            'body_size': raw_size,
            'extracted_text': text[:2000] if text else "",  # Return extracted text for preview
            'user_prompts': prompt_info['user_prompts'],
            'files': prompt_info['files'],
            'model': prompt_info['model'],
            'system_prompt': prompt_info['system_prompt']
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

    # Get request body (both text and raw for protobuf handling)
    body = flow.request.text or ""
    raw_body = flow.request.raw_content
    body_size = len(raw_body) if raw_body else len(body)
    content_encoding = flow.request.headers.get('content-encoding', '').lower()

    # Analyze body for sensitive data (handles protobuf, gzip, JSON)
    findings = detector.analyze(body, raw_body, content_encoding)
    
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
    if findings.get('model'):
        print(f"  Model: {findings['model']}")
    print(f"  Body Type: {findings.get('body_type', 'unknown')}")
    print(f"  Body Size: {findings.get('body_size', body_size)} bytes")

    # Display user prompts prominently
    user_prompts = findings.get('user_prompts', [])
    if user_prompts:
        print(f"\n{Colors.BLUE}{Colors.BOLD}📝 USER PROMPT:{Colors.RESET}")
        for i, prompt in enumerate(user_prompts):
            if len(user_prompts) > 1:
                print(f"  [{i+1}]")
            # Show full prompt (truncate if very long)
            if len(prompt) > 2000:
                print(f"  {prompt[:2000]}")
                print(f"  ... [truncated, {len(prompt)} total chars]")
            else:
                # Print each line with indentation
                for line in prompt.split('\n'):
                    print(f"  {line}")

    # Display attached files
    files = findings.get('files', [])
    if files:
        print(f"\n{Colors.BLUE}{Colors.BOLD}📎 ATTACHED FILES ({len(files)}):{Colors.RESET}")
        for f in files:
            print(f"  • {f}")
    
    if flow.request.headers:
        print(f"\n{Colors.BLUE}Headers:{Colors.RESET}")
        for key, value in flow.request.headers.items():
            # Redact authorization headers
            if key.lower() in ['authorization', 'cookie']:
                print(f"  {key}: {value[:20]}***")
            else:
                print(f"  {key}: {value}")
    
    # Show body preview (use extracted text for protobuf)
    extracted_text = findings.get('extracted_text', '')
    preview_text = extracted_text if extracted_text else body
    if preview_text:
        print(f"\n{Colors.BLUE}Extracted Content Preview:{Colors.RESET}")
        preview = preview_text[:1000]
        if len(preview_text) > 1000:
            preview += "..."
        # Show each line (for extracted strings)
        for line in preview.split('\n')[:20]:
            if line.strip():
                print(f"  {line[:100]}")
        if preview_text.count('\n') > 20:
            print(f"  ... ({preview_text.count(chr(10))} total lines)")
    
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

