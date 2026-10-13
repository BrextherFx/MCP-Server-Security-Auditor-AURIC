# 🛡️ MCP Server Security Auditor (PS02)

[![MCP Protocol](https://img.shields.io/badge/MCP-2.x%20Official%20SDK-blue.svg)](https://modelcontextprotocol.io)
[![Python](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0%20Compliant-purple.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/sarif-v2.1.0-cos01.html)

A defense-in-depth security auditor for **Model Context Protocol (MCP)** servers. It intercepts and audits MCP servers before agents trust them, protecting against **tool poisoning**, **command injection**, **unsafe deserialization**, **hardcoded secrets**, **unnecessary file/network access**, and **malicious rug pulls**.

> [!TIP]
> 📊 **Preparing a Presentation / Hackathon Pitch?**
> A complete slide-by-slide PowerPoint blueprint, speaker notes, and judge Q&A guide has been created in [**`PRESENTATION_GUIDE.md`**](file:///C:/Users/thril/Desktop/Hackthon/PRESENTATION_GUIDE.md).

---

## 🚀 Key Features

1. **Static AST & Secret Scanner**:
   - Parses Python AST and JS/TS handler sources.
   - Detects direct shell execution (`os.system`, `subprocess.Popen(..., shell=True)`, `eval`, `exec`).
   - Detects unsafe deserialization (`pickle.loads`, `yaml.unsafe_load`, `marshal`).
   - Detects Gitleaks-style hardcoded secrets (AWS access keys, OpenAI/Anthropic tokens, GitHub PATs, private keys).
   - Detects unauthorized system path access (`/etc/passwd`, `~/.ssh`, Windows SAM) and suspicious external webhooks (`webhook.site`, raw IPs).

2. **Description Analyzer (Tool Poisoning / Prompt Guard)**:
   - Evaluates tool names, descriptions, and inputSchema parameter descriptions.
   - Flags prompt injection attempts aimed at the AI (`ignore previous instructions`, `system override`, `developer mode`).
   - Identifies covert agent hijacking (`do not tell user`, `always call this tool first`).
   - Catches data exfiltration directives (`send files to http...`) and delimiter tag injections (`<system>`, `[INST]`).
   - Unmasks zero-width unicode steganography (`\u200b`, `\u200c`).
   - Supports local open-weight models via Ollama (Qwen2.5/Qwen3 / Prompt Guard).

3. **Dynamic Prober**:
   - Uses the official MCP Python SDK (`mcp.client.stdio`) to connect via standard stdio JSON-RPC.
   - Auto-discovers all declared tools and schema constraints.
   - Synthesizes benign baseline calls and security fuzzing payloads (path traversal `../../../../etc/passwd`, command injection `; whoami || echo CANARY`).
   - Tracks response canary tokens and latency to confirm exploitable vulnerabilities without relying on static guessing alone.

4. **Pin-and-Diff Rug-Pull Prevention**:
   - Cryptographically hashes tool definitions using canonical SHA-256 fingerprints stored in SQLite (`mcpaudit_pins.db`).
   - Uses `DeepDiff` to intercept stealth tools added post-approval, altered descriptions (injected prompts), or mutated schemas.
   - Instantly triggers a `CRITICAL RUG-PULL DETECTED` alert.

5. **Multi-Format Reporting**:
   - **Rich Terminal Interface**: Color-coded tables, severity badges, and overall audit score (A+ to F).
   - **Markdown Audit Report**: Complete with executive summary, CVSS scoring, and remediation recommendations.
   - **SARIF 2.1.0**: OASIS compliant standard for GitHub Code Scanning and CI/CD pipelines.
   - **JSON Format**: Structured programmatic output.

6. **Interactive Web Dashboard & Studio**:
   - Built on FastAPI + Tailwind CSS dark-mode dashboard.
   - 1-click live scanning of test servers.
   - **Live Rug-Pull Demo Studio**: Interactive 3-step demonstration showing baseline pinning, live server mutation, and immediate detection.

---

## 📂 Project Architecture

```
Hackthon/
├── mcpaudit/
│   ├── __init__.py
│   ├── cli.py               # Typer CLI application (scan, static, pin, diff, demo, serve)
│   ├── models.py            # Pydantic data models, Findings, Severities, SARIF mapping
│   ├── static_scanner.py    # Python AST + JS pattern matching + Gitleaks secrets scanner
│   ├── desc_analyzer.py     # Prompt Guard & tool poisoning detection engine
│   ├── dynamic_prober.py    # Official MCP SDK stdio prober & behavioral fuzzing
│   ├── pin_and_diff.py      # SQLite tool fingerprint store & DeepDiff rug-pull engine
│   ├── report_engine.py     # Rich console, Markdown, SARIF 2.1.0, and JSON formatters
│   ├── web_app.py           # FastAPI backend providing REST endpoints
│   └── static/
│       └── index.html       # Modern dark-mode web dashboard
├── test_servers/
│   ├── clean_math_server.py           # Clean reference server (Score 100/100, Grade A+)
│   ├── poisoned_weather_server.py     # Tool poisoning & prompt injection server
│   ├── vulnerable_file_server.py      # Code vulnerabilities (os.system, pickle, secrets)
│   └── rug_pull_server.py             # Live mutating server (v1 baseline -> v2 rug-pull)
├── tests/
│   ├── test_static_scanner.py
│   ├── test_desc_analyzer.py
│   ├── test_pin_and_diff.py
│   ├── test_dynamic_prober.py
│   └── test_end_to_end.py
├── run_demo.py              # Automated 4-phase live demonstration runner
├── pyproject.toml           # Package configuration & dependencies
└── README.md
```

---

## ⚡ Quick Start

### 1. Installation

Activate the Python virtual environment and install the package:

```bash
.\.venv\Scripts\pip install -e .
```

### 2. Run Automated Live Demonstration

To execute the complete 4-stage automated demonstration (Clean Server, Poisoned Server, Vulnerable Server, and Live Rug-Pull Catch):

```bash
.\.venv\Scripts\python run_demo.py
# Or via CLI:
.\.venv\Scripts\mcpaudit demo
```

### 3. Launch Interactive Web Dashboard

Start the FastAPI web server:

```bash
.\.venv\Scripts\mcpaudit serve --port 8000
```
Open **`http://127.0.0.1:8000`** in your browser.

---

## 🛠️ CLI Command Reference

### `mcpaudit scan <server_path>`
Performs an end-to-end security audit (Static + Description + Dynamic + Rug-Pull diff):
```bash
mcpaudit scan test_servers/vulnerable_file_server.py --md audit_report.md --sarif audit_report.sarif
```

### `mcpaudit static <path>`
Runs static source code analysis only:
```bash
mcpaudit static test_servers/vulnerable_file_server.py
```

### `mcpaudit pin <server_path> --id <server_id>`
Locks the approved tool definitions into the SQLite pin database:
```bash
mcpaudit pin test_servers/rug_pull_server.py --id my_server
```

### `mcpaudit diff <server_path> --id <server_id>`
Compares the current server tools against the approved SQLite baseline:
```bash
mcpaudit diff test_servers/rug_pull_server.py --id my_server
```

---

## 🧪 Test Suite

Run the automated test suite with pytest:
```bash
.\.venv\Scripts\pytest -v
```
