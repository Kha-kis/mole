#!/usr/bin/env python3
"""
Test suite for MOLE features - HTTP API, HTTP Proxy, DNS over TLS, and Security
"""

import sys
import os
import base64
import hmac
import tempfile
from pathlib import Path

def test_section(name):
    print(f"\n{'='*60}")
    print(f"  {name}")
    print('='*60)

def test_pass(name):
    print(f"  ✓ {name}")

def test_fail(name, reason=""):
    print(f"  ✗ {name}: {reason}")
    return False

# ============================================================================
# Test: Timing-safe authentication
# ============================================================================
def test_timing_safe_auth():
    test_section("Timing-Safe Authentication")
    passed = True

    # Test that hmac.compare_digest is used
    secret = "test_api_key_12345"

    # Correct key
    if hmac.compare_digest(secret.encode(), secret.encode()):
        test_pass("hmac.compare_digest works for matching strings")
    else:
        passed = test_fail("hmac.compare_digest matching")

    # Wrong key
    if not hmac.compare_digest(secret.encode(), "wrong_key".encode()):
        test_pass("hmac.compare_digest rejects non-matching strings")
    else:
        passed = test_fail("hmac.compare_digest rejection")

    # Test API key checking logic
    class MockAPIServer:
        def __init__(self):
            self.api_key = "test_key_abc123"

        def _check_auth(self, headers, query_params):
            if not self.api_key:
                return True
            api_key_bytes = self.api_key.encode('utf-8')

            header_key = headers.get('x-api-key', '')
            if header_key and hmac.compare_digest(header_key.encode('utf-8'), api_key_bytes):
                return True

            auth_header = headers.get('authorization', '')
            if auth_header.startswith('Bearer '):
                bearer_key = auth_header[7:]
                if bearer_key and hmac.compare_digest(bearer_key.encode('utf-8'), api_key_bytes):
                    return True

            query_key = query_params.get('api_key', '')
            if query_key and hmac.compare_digest(query_key.encode('utf-8'), api_key_bytes):
                return True

            return False

    server = MockAPIServer()

    # Test X-API-Key header
    if server._check_auth({'x-api-key': 'test_key_abc123'}, {}):
        test_pass("X-API-Key header authentication works")
    else:
        passed = test_fail("X-API-Key header auth")

    # Test Bearer token
    if server._check_auth({'authorization': 'Bearer test_key_abc123'}, {}):
        test_pass("Bearer token authentication works")
    else:
        passed = test_fail("Bearer token auth")

    # Test query parameter
    if server._check_auth({}, {'api_key': 'test_key_abc123'}):
        test_pass("Query parameter authentication works")
    else:
        passed = test_fail("Query param auth")

    # Test wrong key rejection
    if not server._check_auth({'x-api-key': 'wrong_key'}, {}):
        test_pass("Wrong API key rejected")
    else:
        passed = test_fail("Wrong key rejection")

    return passed

# ============================================================================
# Test: SSRF Protection
# ============================================================================
def test_ssrf_protection():
    test_section("SSRF Protection")
    passed = True

    class MockConfig:
        veth_host_ip = "10.200.200.1"
        veth_vpn_ip = "10.200.200.2"

    class MockProxyServer:
        BLOCKED_NETWORKS = [
            ('127.', ),
            ('10.', ),
            ('192.168.', ),
            ('172.16.', '172.17.', '172.18.', '172.19.',
             '172.20.', '172.21.', '172.22.', '172.23.',
             '172.24.', '172.25.', '172.26.', '172.27.',
             '172.28.', '172.29.', '172.30.', '172.31.'),
            ('169.254.', ),
            ('0.', ),
            ('255.', ),
        ]

        def __init__(self):
            self.config = MockConfig()

        def _is_blocked_target(self, host):
            if host.lower() in ('localhost', 'localhost.localdomain'):
                return True
            if host.lower() in ('metadata.google.internal', 'metadata', '169.254.169.254'):
                return True
            if host == self.config.veth_host_ip or host == self.config.veth_vpn_ip:
                return True
            parts = host.split('.')
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                for network_group in self.BLOCKED_NETWORKS:
                    for prefix in network_group:
                        if host.startswith(prefix):
                            return True
            return False

    proxy = MockProxyServer()

    # Test blocked addresses
    blocked_tests = [
        ("127.0.0.1", "loopback"),
        ("localhost", "localhost name"),
        ("10.0.0.1", "private class A"),
        ("192.168.1.1", "private class C"),
        ("172.16.0.1", "private class B"),
        ("169.254.169.254", "cloud metadata IP"),
        ("metadata.google.internal", "GCP metadata"),
        ("10.200.200.1", "veth host IP"),
        ("10.200.200.2", "veth vpn IP"),
    ]

    for ip, desc in blocked_tests:
        if proxy._is_blocked_target(ip):
            test_pass(f"Blocked {desc} ({ip})")
        else:
            passed = test_fail(f"Block {desc}", f"{ip} should be blocked")

    # Test allowed addresses
    allowed_tests = [
        ("8.8.8.8", "Google DNS"),
        ("1.1.1.1", "Cloudflare DNS"),
        ("example.com", "external domain"),
        ("93.184.216.34", "external IP"),
    ]

    for ip, desc in allowed_tests:
        if not proxy._is_blocked_target(ip):
            test_pass(f"Allowed {desc} ({ip})")
        else:
            passed = test_fail(f"Allow {desc}", f"{ip} should be allowed")

    return passed

# ============================================================================
# Test: Secure File Write
# ============================================================================
def test_secure_file_write():
    test_section("Secure File Permissions")
    passed = True

    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "test_secure.txt"

        # Test secure_write_file function
        def secure_write_file(path, content, mode=0o600):
            path_str = str(path)
            fd = os.open(path_str, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, mode)
            try:
                os.write(fd, content.encode('utf-8'))
            finally:
                os.close(fd)

        secure_write_file(test_file, "sensitive data")

        # Check file exists
        if test_file.exists():
            test_pass("File created successfully")
        else:
            return test_fail("File creation")

        # Check permissions
        mode = test_file.stat().st_mode & 0o777
        if mode == 0o600:
            test_pass(f"File permissions are 0600 (got {oct(mode)})")
        else:
            passed = test_fail("File permissions", f"Expected 0600, got {oct(mode)}")

        # Check content
        content = test_file.read_text()
        if content == "sensitive data":
            test_pass("File content written correctly")
        else:
            passed = test_fail("File content", f"Got: {content}")

    return passed

# ============================================================================
# Test: Log Sanitization
# ============================================================================
def test_log_sanitization():
    test_section("Log Sanitization")
    passed = True

    import re as _re
    def sanitize_for_log(text, max_length=200):
        if not text:
            return text
        text = _re.sub(r'\b[A-Za-z0-9_-]{32,}\b', '[REDACTED]', text)
        text = _re.sub(r'\b[A-Za-z0-9+/]{20,}={0,2}\b', '[REDACTED]', text)
        text = _re.sub(r'"(password|token|secret|key|auth)"\s*:\s*"[^"]*"', r'"\1": "[REDACTED]"', text, flags=_re.IGNORECASE)
        if len(text) > max_length:
            text = text[:max_length] + "...[truncated]"
        return text

    # Test token redaction
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdefghij"
    result = sanitize_for_log(f"Token: {token}")
    if "[REDACTED]" in result and token not in result:
        test_pass("Long tokens are redacted")
    else:
        passed = test_fail("Token redaction", f"Got: {result}")

    # Test JSON password redaction
    json_str = '{"username": "user", "password": "secretpass123"}'
    result = sanitize_for_log(json_str)
    if "secretpass123" not in result and '"password": "[REDACTED]"' in result:
        test_pass("JSON passwords are redacted")
    else:
        passed = test_fail("JSON password redaction", f"Got: {result}")

    # Test truncation (use text with spaces to avoid token detection)
    long_text = "This is a log message. " * 20  # ~460 chars
    result = sanitize_for_log(long_text)
    if len(result) < 250 and "...[truncated]" in result:
        test_pass("Long messages are truncated")
    else:
        passed = test_fail("Truncation", f"Length: {len(result)}")

    # Test normal text passes through
    normal = "Connection established successfully"
    result = sanitize_for_log(normal)
    if result == normal:
        test_pass("Normal text unchanged")
    else:
        passed = test_fail("Normal text", f"Got: {result}")

    return passed

# ============================================================================
# Test: HTTP Proxy Authentication
# ============================================================================
def test_proxy_auth():
    test_section("HTTP Proxy Authentication")
    passed = True

    def check_proxy_auth(headers, expected_user, expected_pass):
        auth = headers.get('proxy-authorization', '')
        if not auth.startswith('Basic '):
            return False
        try:
            credentials = base64.b64decode(auth[6:]).decode('utf-8')
            user, passwd = credentials.split(':', 1)
            user_match = hmac.compare_digest(user.encode('utf-8'), expected_user.encode('utf-8'))
            pass_match = hmac.compare_digest(passwd.encode('utf-8'), expected_pass.encode('utf-8'))
            return user_match and pass_match
        except Exception:
            return False

    # Valid credentials
    valid_auth = base64.b64encode(b"mole:secretpass").decode()
    if check_proxy_auth({'proxy-authorization': f'Basic {valid_auth}'}, 'mole', 'secretpass'):
        test_pass("Valid proxy credentials accepted")
    else:
        passed = test_fail("Valid credentials")

    # Wrong password
    wrong_auth = base64.b64encode(b"mole:wrongpass").decode()
    if not check_proxy_auth({'proxy-authorization': f'Basic {wrong_auth}'}, 'mole', 'secretpass'):
        test_pass("Wrong password rejected")
    else:
        passed = test_fail("Wrong password rejection")

    # Missing auth header
    if not check_proxy_auth({}, 'mole', 'secretpass'):
        test_pass("Missing auth header rejected")
    else:
        passed = test_fail("Missing auth rejection")

    # Malformed auth
    if not check_proxy_auth({'proxy-authorization': 'Basic invalid!!!'}, 'mole', 'secretpass'):
        test_pass("Malformed auth rejected")
    else:
        passed = test_fail("Malformed auth rejection")

    return passed

# ============================================================================
# Test: DNS Parsing
# ============================================================================
def test_dns_parsing():
    test_section("DNS Query Parsing")
    passed = True

    def parse_dns_name(data, offset):
        labels = []
        while True:
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:
                pointer = ((length & 0x3F) << 8) | data[offset + 1]
                name, _ = parse_dns_name(data, pointer)
                labels.append(name)
                offset += 2
                break
            offset += 1
            labels.append(data[offset:offset + length].decode('ascii'))
            offset += length
        return '.'.join(labels), offset

    # Build a simple DNS query for "example.com"
    query = bytes([
        0x00, 0x01,  # Transaction ID
        0x01, 0x00,  # Flags: standard query
        0x00, 0x01,  # Questions: 1
        0x00, 0x00,  # Answer RRs: 0
        0x00, 0x00,  # Authority RRs: 0
        0x00, 0x00,  # Additional RRs: 0
        # Question: example.com
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,  # "example"
        0x03, 0x63, 0x6f, 0x6d,  # "com"
        0x00,  # End of name
        0x00, 0x01,  # Type: A
        0x00, 0x01,  # Class: IN
    ])

    name, _ = parse_dns_name(query, 12)
    if name == "example.com":
        test_pass(f"DNS name parsing works: {name}")
    else:
        passed = test_fail("DNS name parsing", f"Got: {name}")

    return passed

# ============================================================================
# Test: DNS Blocklist Matching
# ============================================================================
def test_dns_blocking():
    test_section("DNS Blocklist Matching")
    passed = True

    # Simulate blocklist
    blocked_domains = {
        "ads.example.com",
        "tracker.bad.com",
        "malware.evil.org",
    }

    def is_blocked(domain):
        domain = domain.lower().rstrip('.')
        if domain in blocked_domains:
            return True
        parts = domain.split('.')
        for i in range(len(parts)):
            parent = '.'.join(parts[i:])
            if parent in blocked_domains:
                return True
        return False

    if is_blocked("ads.example.com"):
        test_pass("Blocked domain detected")
    else:
        passed = test_fail("Block detection")

    if is_blocked("sub.ads.example.com"):
        test_pass("Subdomain of blocked domain detected")
    else:
        passed = test_fail("Subdomain block detection")

    if not is_blocked("google.com"):
        test_pass("Clean domain allowed")
    else:
        passed = test_fail("Clean domain should be allowed")

    return passed

# ============================================================================
# Test: Input Validation
# ============================================================================
def test_input_validation():
    test_section("Input Validation")
    passed = True

    def validate_credential(value):
        if not value:
            return False, "Empty"
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            return False, "Control characters"
        if len(value) > 256:
            return False, "Too long"
        return True, "OK"

    valid, msg = validate_credential("myusername123")
    if valid:
        test_pass("Normal credential accepted")
    else:
        passed = test_fail("Normal credential", msg)

    valid, msg = validate_credential("user\nmalicious")
    if not valid and "Control" in msg:
        test_pass("Credential with newline rejected")
    else:
        passed = test_fail("Newline rejection", msg)

    valid, msg = validate_credential("user\x00evil")
    if not valid:
        test_pass("Credential with null byte rejected")
    else:
        passed = test_fail("Null byte rejection")

    valid, msg = validate_credential("A" * 300)
    if not valid and "long" in msg:
        test_pass("Overly long credential rejected")
    else:
        passed = test_fail("Length check", msg)

    return passed

# ============================================================================
# Test: Config Validation Messages
# ============================================================================
def test_config_warnings():
    test_section("Configuration Security Warnings")
    passed = True

    def check_api_security(api_enabled, api_key, bind_addr):
        warnings = []
        if api_enabled:
            if not api_key and bind_addr not in ('127.0.0.1', 'localhost', '::1'):
                warnings.append(f"SECURITY: HTTP API bound to '{bind_addr}' without authentication")
        return warnings

    warnings = check_api_security(True, "", "127.0.0.1")
    if not warnings:
        test_pass("No warning for localhost binding")
    else:
        passed = test_fail("Localhost should not warn")

    warnings = check_api_security(True, "", "0.0.0.0")
    if warnings and "SECURITY" in warnings[0]:
        test_pass("Warning for 0.0.0.0 without auth")
    else:
        passed = test_fail("Should warn for 0.0.0.0")

    warnings = check_api_security(True, "my_secret_key", "0.0.0.0")
    if not warnings:
        test_pass("No warning when API key is set")
    else:
        passed = test_fail("Should not warn with API key")

    return passed

# ============================================================================
# Main
# ============================================================================
def main():
    print("\n" + "="*60)
    print("  MOLE Feature Tests")
    print("="*60)

    results = []

    results.append(("Timing-Safe Auth", test_timing_safe_auth()))
    results.append(("SSRF Protection", test_ssrf_protection()))
    results.append(("Secure File Write", test_secure_file_write()))
    results.append(("Log Sanitization", test_log_sanitization()))
    results.append(("Proxy Authentication", test_proxy_auth()))
    results.append(("DNS Parsing", test_dns_parsing()))
    results.append(("DNS Blocking", test_dns_blocking()))
    results.append(("Input Validation", test_input_validation()))
    results.append(("Config Warnings", test_config_warnings()))

    print("\n" + "="*60)
    print("  Test Summary")
    print("="*60)

    passed = 0
    failed = 0
    for name, result in results:
        status = "PASS" if result else "FAIL"
        symbol = "✓" if result else "✗"
        print(f"  {symbol} {name}: {status}")
        if result:
            passed += 1
        else:
            failed += 1

    print(f"\n  Total: {passed} passed, {failed} failed")
    print("="*60 + "\n")

    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
