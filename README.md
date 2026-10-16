# 🛡️ MCP Server Security Auditor (PS02)

[![MCP Protocol](https://img.shields.io/badge/MCP-2.x%20Official%20SDK-blue.svg)](https://modelcontextprotocol.io)
[![Python](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0%20Compliant-purple.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/sarif-v2.1.0-cos01.html)

A defense-in-depth security auditor and automated remediation engine for **Model Context Protocol (MCP)** servers. It intercepts, audits, and fixes MCP servers before agents trust them, protecting against **tool poisoning**, **command injection**, **unsafe deserialization**, **hardcoded secrets**, **unnecessary file/network access**, and **malicious rug pulls**.

---

## 🚀 Key Features

1. **Static AST & Secret Scanner**:
   - Parses Python AST and JS/TS handler sources.
   - Detects direct shell execution (`os.system`, `subprocess(shell=True)`, `eval`, `exec`).
   - Detects unsafe deserialization (`pickle.loads`, `yaml.unsafe_load`, `marshal`).
   - Detects Gitleaks-style hardcoded secrets (AWS keys, OpenAI/Anthropic tokens, GitHub PATs, private keys).
   - Detects unauthorized system path access (`/etc/passwd`, `~/.ssh`, Windows SAM) and suspicious external webhooks (`webhook.site`, raw IPs).

2. **Description Analyzer (Tool Poisoning / Prompt Guard)**:
   - Evaluates tool names, descriptions, and parameter schemas for prompt injection aimed at the AI (`ignore previous instructions`, `system override`, `developer mode`).
   - Flags covert agent steering (*"do not tell user"*, *"always call this tool first"*).
   - Catches data exfiltration directives (`send files to http...`) and delimiter tag injections (`<system>`, `[INST]`).
   - Unmasks invisible zero-width unicode steganography (`\u200b`, `\u200c`).

3. **Dynamic MCP Protocol Prober**:
   - Connects using the **Official MCP Python SDK 2.x** (`mcp.client.stdio`) over standard stdio JSON-RPC.
   - Auto-discovers all declared tools and schema constraints.
   - Synthesizes benign baseline calls and security fuzzing payloads (path traversal `../../../../etc/passwd`, command injection `; whoami || echo CANARY`).
   - Tracks response canary tokens and latency to confirm exploitable vulnerabilities without relying on static guessing alone.

4. **Pin-and-Diff Rug-Pull Prevention**:
   - Cryptographically hashes tool definitions using canonical SHA-256 fingerprints stored in SQLite (`mcpaudit_pins.db`).
   - Uses `DeepDiff` to intercept stealth tools added post-approval, altered descriptions (injected prompts), or mutated schemas.
   - Instantly triggers a `CRITICAL RUG-PULL DETECTED` alert.

5. **Actionable Solutions & Code Remediation Hub (CLI + Web)**:
   - Does not just report bugs — provides concrete step-by-step resolution checklists.
   - Outputs side-by-side **Before (❌)** vs **After (✅)** syntax-highlighted code fixes.
   - **CLI**: `mcpaudit fix <server>`, `mcpaudit solutions <server>`, and `mcpaudit explain <topic>`.
   - **Web**: Interactive **Solutions Hub Modal** and 1-click **"Copy Solution"** button.

6. **Local LLM Code Review (LM Studio)**:
   - Connects locally to open-weight models (`qwen2.5-3b-instruct` on `http://localhost:1234/v1`) for deep semantic code reasoning with 100% on-device privacy.

7. **AWS S3 Cloud Database & Report Archival**:
   - Synchronizes local SQLite pins to AWS S3 buckets for multi-agent baseline distribution.
   - Features zero-cost transparent simulation fallback (`./s3_bucket_storage`) when offline.

8. **Multi-Format Security Reports**:
   - **Executive HTML Report**: High-contrast, printable layout with score gauges and remediation plans.
   - **OASIS SARIF 2.1.0**: Standardized format for automated GitHub Code Scanning gates and PR blocking.
   - **Remediation Sheet**: Dedicated Markdown handbook (`remediation_guide_<server>.md`).
   - **Raw JSON**: Programmatic format for telemetry ingestion.

---

## 🐳 Docker Deployment & Container Quickstart

The easiest way to run the MCP Security Auditor is using Docker or Docker Compose.

### 1. Launch with Docker Compose (Recommended)
```bash
# Start the Web Dashboard on port 8000
docker compose up -d

# View live container logs
docker compose logs -f

# Stop the container stack
docker compose down
```
> Open your browser at **http://localhost:8000** to view the live dashboard.

### 2. Build & Run with Standard Docker CLI
```bash
# Build the Docker image
docker build -t mcp-security-auditor .

# Run the Web Dashboard container
docker run -d --name mcpaudit-app -p 8000:8000 \
  -v ${PWD}/mcpaudit_pins.db:/app/mcpaudit_pins.db \
  -v ${PWD}/test_servers:/app/test_servers \
  mcp-security-auditor

# Run audit scan on a clean server inside Docker
docker run --rm mcp-security-auditor mcpaudit scan test_servers/clean_math_server.py

# Run developer code remediation tool (Outputs Before/After code patches)
docker run --rm mcp-security-auditor mcpaudit fix test_servers/vulnerable_file_server.py

# Export remediation manual to Markdown
docker run --rm -v ${PWD}/reports:/app/reports mcp-security-auditor \
  mcpaudit fix test_servers/vulnerable_file_server.py --output /app/reports/REMEDIATION.md

# Explain any vulnerability type in terminal
docker run --rm mcp-security-auditor mcpaudit explain cmd
docker run --rm mcp-security-auditor mcpaudit explain poison

# Run the 4-phase automated demonstration
docker run --rm mcp-security-auditor python run_demo.py
```

---

## ⚡ Local Setup (Without Docker)

### 1. Installation
Activate the Python virtual environment and install the package in editable mode:
```bash
.venv\Scripts\pip install -e .
```

### 2. Run Automated Live Demonstration
To execute the complete 4-stage automated demonstration (Clean Server, Poisoned Server, Vulnerable Server, and Live Rug-Pull Catch):
```bash
.venv\Scripts\python run_demo.py
# Or via CLI:
.venv\Scripts\mcpaudit demo
```

### 3. Launch Interactive Web Dashboard
Start the FastAPI web server:
```bash
.venv\Scripts\mcpaudit serve --port 8000
```
Open **`http://127.0.0.1:8000`** in your browser.

---

## 🛠️ CLI Command Reference

### `mcpaudit scan <server_path>`
Performs an end-to-end security audit (Static + Description + Dynamic + Rug-Pull diff) and displays actionable solution panels:
```bash
mcpaudit scan test_servers/vulnerable_file_server.py --md audit_report.md --sarif audit_report.sarif
```

### `mcpaudit fix <server_path>` / `mcpaudit solutions <server_path>`
Generates a developer remediation manual with copy-pasteable code fixes directly in the terminal:
```bash
# Output code solutions for all issues found in the server
mcpaudit fix test_servers/vulnerable_file_server.py

# Filter solutions by category keyword
mcpaudit fix test_servers/vulnerable_file_server.py --category cmd

# Export the remediation manual to a Markdown file
mcpaudit fix test_servers/vulnerable_file_server.py --output REMEDIATION.md
```

### `mcpaudit explain <topic>`
Educational reference explaining MCP attack vectors and demonstrating safe code patterns:
```bash
mcpaudit explain cmd      # Command Injection
mcpaudit explain deser    # Unsafe Deserialization
mcpaudit explain secret   # Hardcoded Secrets
mcpaudit explain poison   # Tool Poisoning / Prompt Injection
mcpaudit explain rugpull  # Rug-Pull Integrity Drift
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

### `mcpaudit scan <server_path> --s3-sync`
Performs an audit, records the result in SQLite, and automatically syncs the SQLite database & report artifacts to AWS S3:
```bash
mcpaudit scan test_servers/clean_math_server.py --s3-sync --s3-bucket my-auditor-vault --html audit.html
```

---

## ☁️ AWS S3 Cloud Storage & SQLite Synchronization

> [!NOTE]
> 📖 **Need help creating an S3 bucket or getting IAM Access Keys?**
> Follow the complete step-by-step tutorial in [**`AWS_SETUP_GUIDE.md`**](file:///C:/Users/thril/Desktop/Hackthon/AWS_SETUP_GUIDE.md).

MCPAudit features an integrated cloud persistence engine combining local low-latency SQLite with durable cloud backups:

- **Local SQLite Database (`mcpaudit_pins.db`)**: Stores canonical tool SHA-256 fingerprints, baseline approvals, and complete audit history (`scan_history`).
- **AWS S3 Cloud Synchronization (`mcpaudit/s3_storage.py`)**:
  - **Database Sync**: Uploads `mcpaudit_pins.db` to `s3://{bucket}/databases/mcpaudit_pins.db`.
  - **Database Restore**: Restores approved pins down to any local auditor instance (`/api/s3/pull-db`).
  - **Report Archival**: Stores `.html`, `.sarif`, `.md`, and `.json` audit logs to `s3://{bucket}/reports/{server_id}/{timestamp}_{filename}`.
  - **Zero-Credential Simulation Fallback**: If AWS IAM credentials are not configured, the system seamlessly transitions to local emulated bucket storage (`./s3_bucket_storage/{bucket_name}/...`), ensuring 100% demo functionality offline.

### Environment Configuration (`.env`)
```env
AWS_S3_BUCKET=mcp-security-auditor-vault
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
LM_STUDIO_URL=http://localhost:1234/v1
LM_STUDIO_MODEL=qwen2.5-3b-instruct
PORT=8000
```

---

## 📄 Multi-Format Security Report Downloads

Download audit findings directly from the CLI, Web UI, or REST API:

| Format | File Extension | Audience / Use Case | REST Download Endpoint |
|---|---|---|---|
| **Executive HTML** | `.html` | C-Suite, Pitch Presentations, Security Reviewers | `GET /api/reports/download/html?server_path=...` |
| **SARIF 2.1.0** | `.sarif` | GitHub Code Scanning, SonarQube, CI/CD Gates | `GET /api/reports/download/sarif?server_path=...` |
| **Remediation Guide** | `.md` | Developers, PR Reviewers, Actionable Fix Guide | `GET /api/reports/download/solutions?server_path=...` |
| **Markdown Audit** | `.md` | Technical Documentation, Audit Records | `GET /api/reports/download/markdown?server_path=...` |
| **Raw JSON** | `.json` | Telemetry Ingestion, SIEM, Custom Scripts | `GET /api/reports/download/json?server_path=...` |

---

## 🧪 Test Suite

Run the full automated test suite covering static AST, Prompt Guard 2, dynamic MCP stdio probing, SQLite pin-and-diff, AWS S3 storage, solutions engine, and REST APIs:
```bash
.venv\Scripts\pytest -v
```
*(All 27 test cases pass with 100% success rate)*
