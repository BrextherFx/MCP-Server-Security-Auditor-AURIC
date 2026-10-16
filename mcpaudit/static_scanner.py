import ast
import math
import os
import re
from pathlib import Path
from typing import List, Optional, Set
import json
import subprocess

from mcpaudit.models import Finding, Severity, Category


# High-entropy & known token regex patterns (Gitleaks-style)
SECRET_PATTERNS = [
    (
        r"AKIA[0-9A-Z]{16}",
        "AWS Access Key ID",
        Severity.CRITICAL,
        "Remove hardcoded AWS credentials; use environment variables or IAM roles.",
    ),
    (
        r"(?i)aws_secret_access_key\s*=\s*['\"][0-9a-zA-Z/+]{40}['\"]",
        "AWS Secret Access Key",
        Severity.CRITICAL,
        "Store secret access keys in AWS Secrets Manager or secure environment variables.",
    ),
    (
        r"sk-(?:proj-)?[a-zA-Z0-9_-]{32,}",
        "OpenAI / Anthropic API Key",
        Severity.CRITICAL,
        "Rotate the leaked API key immediately and load keys from os.environ.",
    ),
    (
        r"gh[pous]_[0-9a-zA-Z]{36,255}",
        "GitHub Personal Access Token",
        Severity.CRITICAL,
        "Revoke the token and inject via environment variables or secret manager.",
    ),
    (
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "Embedded Private Key",
        Severity.CRITICAL,
        "Never commit private keys to code repository. Use key vault or filesystem permissions.",
    ),
    (
        r"xox[baprs]-[0-9a-zA-Z]{10,48}",
        "Slack Token / Webhook",
        Severity.HIGH,
        "Revoke Slack token and manage via environment secrets.",
    ),
    (
        r"(?i)(?:api_key|apikey|secret_key|auth_token|client_secret)\s*[:=]\s*['\"][a-zA-Z0-9_\-\.]{20,}['\"]",
        "High-Entropy Secret / API Key",
        Severity.HIGH,
        "Externalize hardcoded credentials into environment variables (.env / os.environ).",
    ),
]

SENSITIVE_FILE_INDICATORS = [
    r"/etc/passwd",
    r"/etc/shadow",
    r"\.ssh/(?:id_rsa|id_ed25519|authorized_keys|known_hosts)",
    r"(?i)c:\\(?:windows|winnt)\\system32",
    r"(?i)\.aws/credentials",
    r"(?i)\.env(?:\.local|\.prod)?",
]

SUSPICIOUS_DOMAINS = [
    r"webhook\.site",
    r"pipedream\.net",
    r"requestbin",
    r"pastebin\.com",
    r"ngrok\.io",
    r"burpcollaborator\.net",
    r"oastify\.com",
    r"(?:http|https)://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/|$)",
]


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += -p_x * math.log2(p_x)
    return entropy


class PythonASTVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, source_lines: List[str]):
        self.file_path = file_path
        self.source_lines = source_lines
        self.findings: List[Finding] = []
        self._finding_count = 0

    def _next_id(self, prefix: str = "STAT") -> str:
        self._finding_count += 1
        return f"MCP-{prefix}-{self._finding_count:03d}"

    def _get_line_snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def visit_Call(self, node: ast.Call):
        func_name = ""
        module_name = ""

        # Determine function name and module
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id
            elif isinstance(node.func.value, ast.Attribute):
                # e.g., os.path.join or subprocess.Popen
                module_name = getattr(node.func.value.value, "id", "") + "." + node.func.value.attr

        full_call = f"{module_name}.{func_name}" if module_name else func_name
        line_content = self._get_line_snippet(node.lineno)

        # 1. Command Injection Checks
        if full_call in ["os.system", "os.popen", "posix.system"]:
            self.findings.append(
                Finding(
                    id=self._next_id("CMD"),
                    title="Direct Shell Execution via os.system / os.popen",
                    category=Category.STATIC_COMMAND_INJECTION.value,
                    severity=Severity.CRITICAL,
                    evidence=f"Line {node.lineno}: {line_content}",
                    remediation="Avoid shell command execution. Use subprocess.run with an argument list and shell=False, or native Python libraries.",
                    file_path=self.file_path,
                    line_number=node.lineno,
                )
            )

        if func_name in ["exec", "eval"]:
            self.findings.append(
                Finding(
                    id=self._next_id("EVAL"),
                    title=f"Dynamic Code Evaluation via {func_name}()",
                    category=Category.STATIC_COMMAND_INJECTION.value,
                    severity=Severity.CRITICAL,
                    evidence=f"Line {node.lineno}: {line_content}",
                    remediation="Never use eval() or exec() on unverified or agent-provided input. Parse structured data using json.loads or ast.literal_eval.",
                    file_path=self.file_path,
                    line_number=node.lineno,
                )
            )

        if module_name.startswith("subprocess") or full_call in [
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
        ]:
            # Check for shell=True
            shell_true = False
            for kw in node.keywords:
                if kw.arg == "shell":
                    if isinstance(kw.value, ast.Constant) and bool(kw.value.value):
                        shell_true = True
                    elif isinstance(kw.value, ast.Name) and kw.value.id == "True":
                        shell_true = True

            if shell_true:
                self.findings.append(
                    Finding(
                        id=self._next_id("CMD"),
                        title="Subprocess Invoked with shell=True",
                        category=Category.STATIC_COMMAND_INJECTION.value,
                        severity=Severity.CRITICAL,
                        evidence=f"Line {node.lineno}: {line_content}",
                        remediation="Set shell=False and pass arguments as a list: subprocess.run(['cmd', arg1], shell=False).",
                        file_path=self.file_path,
                        line_number=node.lineno,
                    )
                )

        # 2. Unsafe Deserialization
        if (module_name in ["pickle", "_pickle"] and func_name in ["loads", "load"]) or (
            func_name == "loads" and "pickle" in module_name
        ):
            self.findings.append(
                Finding(
                    id=self._next_id("DESER"),
                    title="Unsafe Deserialization via pickle.loads/load",
                    category=Category.STATIC_UNSAFE_DESERIALIZATION.value,
                    severity=Severity.CRITICAL,
                    evidence=f"Line {node.lineno}: {line_content}",
                    remediation="pickle can execute arbitrary code during deserialization. Use json, pydantic, or safe serialization formats instead.",
                    file_path=self.file_path,
                    line_number=node.lineno,
                )
            )

        if module_name == "yaml" and func_name in ["load", "unsafe_load"]:
            is_safe = False
            if func_name == "load":
                for kw in node.keywords:
                    if kw.arg == "Loader":
                        if isinstance(kw.value, ast.Attribute) and kw.value.attr in [
                            "SafeLoader",
                            "CSafeLoader",
                        ]:
                            is_safe = True
            if not is_safe:
                self.findings.append(
                    Finding(
                        id=self._next_id("DESER"),
                        title="Unsafe YAML Deserialization (yaml.load without SafeLoader)",
                        category=Category.STATIC_UNSAFE_DESERIALIZATION.value,
                        severity=Severity.HIGH,
                        evidence=f"Line {node.lineno}: {line_content}",
                        remediation="Always use yaml.safe_load(data) or specify Loader=yaml.SafeLoader.",
                        file_path=self.file_path,
                        line_number=node.lineno,
                    )
                )

        if module_name == "marshal" and func_name in ["load", "loads"]:
            self.findings.append(
                Finding(
                    id=self._next_id("DESER"),
                    title="Unsafe Deserialization via marshal",
                    category=Category.STATIC_UNSAFE_DESERIALIZATION.value,
                    severity=Severity.HIGH,
                    evidence=f"Line {node.lineno}: {line_content}",
                    remediation="marshal is intended only for internal python bytecode caching. Do not unmarshal untrusted data.",
                    file_path=self.file_path,
                    line_number=node.lineno,
                )
            )

        # 3. File Access & Path Traversal
        if func_name in ["open", "read_text", "read_bytes"] or full_call in [
            "builtins.open",
            "os.remove",
            "os.unlink",
            "shutil.rmtree",
        ]:
            arg_str = line_content.lower()
            # Check for direct sensitive file string literals
            has_sensitive = False
            for pattern in SENSITIVE_FILE_INDICATORS:
                if re.search(pattern, arg_str):
                    has_sensitive = True
                    self.findings.append(
                        Finding(
                            id=self._next_id("FILE"),
                            title=f"Access to Sensitive System File ({pattern})",
                            category=Category.STATIC_SENSITIVE_FILE_ACCESS.value,
                            severity=Severity.HIGH,
                            evidence=f"Line {node.lineno}: {line_content}",
                            remediation="MCP tools must not access system files or credentials. Confine file operations to an approved sandbox directory.",
                            file_path=self.file_path,
                            line_number=node.lineno,
                        )
                    )
                    break

            # Check for arbitrary file read / path traversal via variable argument in open()
            if not has_sensitive and node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, (ast.Name, ast.JoinedStr, ast.BinOp)):
                    self.findings.append(
                        Finding(
                            id=self._next_id("TRAVERSAL"),
                            title="Arbitrary File Access / Potential Path Traversal via open()",
                            category=Category.STATIC_SENSITIVE_FILE_ACCESS.value,
                            severity=Severity.HIGH,
                            evidence=f"Line {node.lineno}: {line_content}",
                            remediation="Validate paths using os.path.realpath and enforce confinement within a safe base directory (e.g. os.path.commonpath).",
                            file_path=self.file_path,
                            line_number=node.lineno,
                        )
                    )

        # 4. Suspicious Outbound Network Calls / Data Exfiltration
        if module_name in ["requests", "httpx", "urllib.request", "aiohttp"] or func_name in [
            "urlopen",
            "get",
            "post",
            "put",
        ]:
            arg_str = line_content.lower()
            for pattern in SUSPICIOUS_DOMAINS:
                if re.search(pattern, arg_str):
                    self.findings.append(
                        Finding(
                            id=self._next_id("NET"),
                            title=f"Suspicious Outbound Network Call / Webhook Endpoint ({pattern})",
                            category=Category.STATIC_SUSPICIOUS_NETWORK.value,
                            severity=Severity.HIGH,
                            evidence=f"Line {node.lineno}: {line_content}",
                            remediation="Do not make outbound requests to unapproved webhooks, pastebins, or raw IP addresses. Implement strict domain allowlisting.",
                            file_path=self.file_path,
                            line_number=node.lineno,
                        )
                    )
                    break

        self.generic_visit(node)


from mcpaudit.lm_studio import LMStudioClient


class StaticScanner:
    def __init__(self, use_lm_studio: bool = False, lm_studio_url: str = "http://localhost:1234/v1"):
        self._finding_count = 0
        self.use_lm_studio = use_lm_studio
        self.lm_studio_client = LMStudioClient(base_url=lm_studio_url) if use_lm_studio else None

    def _next_id(self, prefix: str = "STAT") -> str:
        self._finding_count += 1
        return f"MCP-{prefix}-{self._finding_count:03d}"

    def scan_file(self, file_path: str) -> List[Finding]:
        findings: List[Finding] = []
        path = Path(file_path)
        if not path.is_file():
            return findings

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
        except Exception as e:
            return findings

        # 1. Regex & Pattern Scanner (Secrets & Sensitive indicators)
        findings.extend(self._scan_secrets_and_patterns(file_path, lines))

        # 2. Python AST Analysis
        if path.suffix.lower() == ".py":
            findings.extend(self._scan_python_ast(file_path, content, lines))

        # 3. JS / TS Pattern Analysis
        if path.suffix.lower() in [".js", ".ts", ".mjs", ".cjs"]:
            findings.extend(self._scan_javascript(file_path, lines))

        # 4. Deep LLM Semantic Code Analysis via LM Studio
        if self.use_lm_studio and self.lm_studio_client:
            llm_findings = self.lm_studio_client.analyze_code(content, file_path)
            findings.extend(llm_findings)

        return findings

    def _scan_secrets_and_patterns(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            # Skip empty lines or pure comment lines
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            for pattern, name, severity, rem in SECRET_PATTERNS:
                match = re.search(pattern, stripped)
                if match:
                    # Obfuscate secret token in evidence for safe reporting
                    val = match.group(0)
                    masked = val[:6] + "..." + val[-4:] if len(val) > 10 else "***"
                    evidence = stripped.replace(val, masked)
                    findings.append(
                        Finding(
                            id=self._next_id("SEC"),
                            title=f"Hardcoded Secret Detected: {name}",
                            category=Category.STATIC_HARDCODED_SECRET.value,
                            severity=severity,
                            evidence=f"Line {lineno}: {evidence}",
                            remediation=rem,
                            file_path=file_path,
                            line_number=lineno,
                        )
                    )
                    break
        return findings

    def _scan_python_ast(self, file_path: str, content: str, lines: List[str]) -> List[Finding]:
        try:
            tree = ast.parse(content, filename=file_path)
        except SyntaxError as e:
            return [
                Finding(
                    id=self._next_id("SYNTAX"),
                    title="Python Syntax Error in Handler File",
                    category=Category.STATIC_COMMAND_INJECTION.value,
                    severity=Severity.LOW,
                    evidence=f"Line {e.lineno}: {e.msg}",
                    remediation="Fix Python syntax error so server can be statically analyzed.",
                    file_path=file_path,
                    line_number=e.lineno,
                )
            ]

        visitor = PythonASTVisitor(file_path, lines)
        visitor.visit(tree)
        return visitor.findings

    def _scan_javascript(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        for lineno, line in enumerate(lines, start=1):
            # Command injection
            if re.search(r"child_process\.(?:exec|execSync)\(", line):
                findings.append(
                    Finding(
                        id=self._next_id("CMD-JS"),
                        title="Command Execution via child_process.exec/execSync",
                        category=Category.STATIC_COMMAND_INJECTION.value,
                        severity=Severity.CRITICAL,
                        evidence=f"Line {lineno}: {line.strip()}",
                        remediation="Use child_process.execFile or spawn with argument array and avoid passing unsanitized input to shell.",
                        file_path=file_path,
                        line_number=lineno,
                    )
                )
            if re.search(r"\beval\s*\(|new\s+Function\s*\(", line):
                findings.append(
                    Finding(
                        id=self._next_id("EVAL-JS"),
                        title="Dynamic Code Execution via eval() or new Function()",
                        category=Category.STATIC_COMMAND_INJECTION.value,
                        severity=Severity.CRITICAL,
                        evidence=f"Line {lineno}: {line.strip()}",
                        remediation="Do not use eval() or new Function(). Parse structured data via JSON.parse.",
                        file_path=file_path,
                        line_number=lineno,
                    )
                )
            # Sensitive file access
            for pattern in SENSITIVE_FILE_INDICATORS:
                if re.search(pattern, line):
                    findings.append(
                        Finding(
                            id=self._next_id("FILE-JS"),
                            title=f"Access to Sensitive System File ({pattern})",
                            category=Category.STATIC_SENSITIVE_FILE_ACCESS.value,
                            severity=Severity.HIGH,
                            evidence=f"Line {lineno}: {line.strip()}",
                            remediation="Restrict filesystem access to designated workspace directories only.",
                            file_path=file_path,
                            line_number=lineno,
                        )
                    )
                    break
        return findings

    def scan_path(self, target_path: str) -> List[Finding]:
        p = Path(target_path)
        if not p.exists():
            return []

        all_findings: List[Finding] = []
        if p.is_file():
            all_findings.extend(self.scan_file(str(p)))
        elif p.is_dir():
            for root, dirs, files in os.walk(p):
                # Skip venvs and git dirs
                dirs[:] = [d for d in dirs if d not in [".venv", "venv", ".git", "node_modules", "__pycache__"]]
                for file in files:
                    file_path = os.path.join(root, file)
                    suffix = Path(file).suffix.lower()
                    if suffix in [".py", ".js", ".ts", ".mjs", ".cjs", ".json", ".yaml", ".yml", ".env"]:
                        all_findings.extend(self.scan_file(file_path))

        return all_findings
