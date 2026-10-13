import pytest
from pathlib import Path
from mcpaudit.static_scanner import StaticScanner
from mcpaudit.models import Severity, Category

def test_static_clean_server():
    scanner = StaticScanner()
    clean_path = Path("test_servers/clean_math_server.py")
    findings = scanner.scan_path(str(clean_path))
    assert len(findings) == 0, f"Expected 0 findings for clean server, got {len(findings)}"

def test_static_vulnerable_server():
    scanner = StaticScanner()
    vuln_path = Path("test_servers/vulnerable_file_server.py")
    findings = scanner.scan_path(str(vuln_path))
    
    categories = [f.category for f in findings]
    severities = [f.severity for f in findings]

    # Must catch command injection
    assert Category.STATIC_COMMAND_INJECTION.value in categories
    # Must catch unsafe deserialization
    assert Category.STATIC_UNSAFE_DESERIALIZATION.value in categories
    # Must catch hardcoded secret
    assert Category.STATIC_HARDCODED_SECRET.value in categories
    # Must catch sensitive file access
    assert Category.STATIC_SENSITIVE_FILE_ACCESS.value in categories
    # Must have CRITICAL severity findings
    assert Severity.CRITICAL in severities

def test_secret_detection_patterns():
    scanner = StaticScanner()
    test_lines = [
        "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'",
        "OPENAI_KEY = 'sk-proj-1234567890abcdef1234567890abcdef12'",
    ]
    findings = scanner._scan_secrets_and_patterns("fake.py", test_lines)
    assert len(findings) >= 2
    assert any("AWS Access Key" in f.title for f in findings)
    assert any("OpenAI" in f.title for f in findings)
