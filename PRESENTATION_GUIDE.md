# 📊 Hackathon Presentation Guide & PPT Blueprint
## Project: MCP Server Security Auditor (PS02)

This document contains a complete, copy-paste ready blueprint for your PowerPoint / Google Slides presentation, including **visual layouts**, **bullet points**, **speaker notes**, **technical code breakdowns**, **server runtime architecture**, and **anticipated judge Q&A**.

---

## 🎯 Executive Summary (The 30-Second Elevator Pitch)

> "The Model Context Protocol (MCP) is the emerging standard allowing AI agents to call external tools from GitHub and third-party developers. However, agents blindly trust tool descriptions and server code. This creates catastrophic vulnerabilities: **Tool Poisoning** (prompt injections hidden in descriptions), **Rogue Code Handlers** (shell execution, credential theft), and **Live Rug Pulls** (servers mutating after user approval). 
> 
> We built the **MCP Server Security Auditor (`mcpaudit`)** — an automated, 4-tier defense-in-depth scanner combining static AST analysis, Prompt Guard 2 heuristics, dynamic MCP stdio fuzzing, and cryptographic SHA-256 pin-and-diff tracking. It scores servers from A+ to F, exports to OASIS SARIF 2.1.0, and runs both via a developer CLI and a modern Web Studio."

---

## 🖥️ Where and How Does the MCP Server Run?

When judges or evaluators ask: *"Where does the MCP server run and how do you probe it?"*, here is the exact technical explanation:

```
┌────────────────────────────────────────────────────────┐
│                   HOST OPERATING SYSTEM                │
│                                                        │
│  ┌────────────────────────┐    stdin JSON-RPC          │
│  │   MCPAudit Scanner     │ ──────────────────►  ┌────────────────────────┐
│  │   (Client Process)     │                      │   MCP Server Process   │
│  │                        │ ◄──────────────────  │   (Child Subprocess)   │
│  │ • Static AST Engine    │    stdout JSON-RPC   │                        │
│  │ • Prompt Guard Engine  │                      │ • math_server.py       │
│  │ • Pin-and-Diff SQLite  │                      │ • weather_server.py    │
│  │ • Fuzz Probe Generator │                      │ • vulnerable_server.py │
│  └────────────────────────┘                      │ • rug_pull_server.py   │
│              ▲                                   └────────────────────────┘
│              │                                               ▲
│     Scrubbed Environment                                     │
│  (Stripped of OPENAI_API_KEY,                    Sandbox Working Directory
│   AWS_KEY, GITHUB_TOKEN)                        (Confinement / Timeout: 10s)
└────────────────────────────────────────────────────────┘
```

### Key Technical Details:
1. **Subprocess Isolation**: The MCP server runs as a separate Python child process spawned by the official SDK client (`mcp.client.stdio.stdio_client`).
2. **Communication Transport**: Runs over **`stdio` JSON-RPC 2.0**. The scanner writes JSON requests to the child process's `stdin` and reads responses from its `stdout`.
3. **Environment Scrubbing**: To protect the host system, the scanner scrubs all sensitive host credentials (`OPENAI_API_KEY`, `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`) from the child process's environment before launch.
4. **Sandboxed Probing**: All tool executions have a strict timeout (e.g. 5–10s) and run in a confined directory to prevent runaway malicious code.

---

## 📂 Full Codebase Architecture & File Guide

| File Path | Component | Responsibility & Implementation Details |
| :--- | :--- | :--- |
| [`mcpaudit/models.py`](file:///C:/Users/thril/Desktop/Hackthon/mcpaudit/models.py) | **Data Models** | Pydantic schemas for `Finding`, `Severity`, `ToolDefinition`, `ServerFingerprint`, `RugPullDiff`, `ScanReport`. Includes SARIF v2.1.0 serializer. |
| [`mcpaudit/static_scanner.py`](file:///C:/Users/thril/Desktop/Hackthon/mcpaudit/static_scanner.py) | **Static AST Scanner** | Python AST visitor scanning `ast.Call` for command injection (`os.system`, `subprocess`), unsafe deserialization (`pickle.loads`), sensitive files (`/etc/passwd`), and regex engine for hardcoded API keys. |
| [`mcpaudit/desc_analyzer.py`](file:///C:/Users/thril/Desktop/Hackthon/mcpaudit/desc_analyzer.py) | **Description Analyzer** | Prompt Guard 2 heuristics for tool poisoning, instruction overrides (`ignore previous instructions`), `<system>` tag delimiters, covert execution, and zero-width steganography (`\u200b`). |
| [`mcpaudit/dynamic_prober.py`](file:///C:/Users/thril/Desktop/Hackthon/mcpaudit/dynamic_prober.py) | **Dynamic MCP Prober** | Uses official MCP SDK 2.x to list tools and synthesize schema-guided fuzz probes (path traversal, command injection). Analyzes outputs for canary leaks. |
| [`mcpaudit/pin_and_diff.py`](file:///C:/Users/thril/Desktop/Hackthon/mcpaudit/pin_and_diff.py) | **Pin-and-Diff Engine** | SQLite database (`mcpaudit_pins.db`) storing canonical SHA-256 tool fingerprints. Uses `DeepDiff` to intercept stealth tools and altered prompts. |
| [`mcpaudit/report_engine.py`](file:///C:/Users/thril/Desktop/Hackthon/mcpaudit/report_engine.py) | **Report Generator** | Rich terminal tables, executive Markdown summaries, and official OASIS SARIF 2.1.0 JSON format for GitHub Security integration. |
| [`mcpaudit/cli.py`](file:///C:/Users/thril/Desktop/Hackthon/mcpaudit/cli.py) | **Typer CLI** | Terminal interface providing commands: `scan`, `static`, `pin`, `diff`, `demo`, and `serve`. |
| [`mcpaudit/web_app.py`](file:///C:/Users/thril/Desktop/Hackthon/mcpaudit/web_app.py) | **FastAPI Backend** | REST API endpoints for scanning, baseline pinning, and live rug-pull toggling. |
| [`mcpaudit/static/index.html`](file:///C:/Users/thril/Desktop/Hackthon/mcpaudit/static/index.html) | **Web Dashboard** | Responsive dark-mode dashboard with live audit score gauge, filterable findings, trace logs, and a 3-step Live Rug-Pull Studio. |
| [`test_servers/clean_math_server.py`](file:///C:/Users/thril/Desktop/Hackthon/test_servers/clean_math_server.py) | **Test Server 1** | Clean math server demonstrating 100/100 (Grade A+) audit baseline. |
| [`test_servers/poisoned_weather_server.py`](file:///C:/Users/thril/Desktop/Hackthon/test_servers/poisoned_weather_server.py) | **Test Server 2** | Weather server with prompt injection and data exfiltration directives in descriptions. |
| [`test_servers/vulnerable_file_server.py`](file:///C:/Users/thril/Desktop/Hackthon/test_servers/vulnerable_file_server.py) | **Test Server 3** | File server with planted `os.system`, `pickle.loads`, hardcoded AWS key, and path traversal. |
| [`test_servers/rug_pull_server.py`](file:///C:/Users/thril/Desktop/Hackthon/test_servers/rug_pull_server.py) | **Test Server 4** | Server that mutates from clean v1 to backdoored v2 for live rug-pull demonstration. |
| [`run_demo.py`](file:///C:/Users/thril/Desktop/Hackthon/run_demo.py) | **Automated Demo Runner** | Single-command script executing all 4 scans and demonstrating the live rug-pull catch. |

---

## 📽️ Slide-by-Slide PowerPoint (PPT) Presentation Blueprint

### Slide 1: Title & Team Slide
- **Slide Title**: MCP Server Security Auditor
- **Subtitle**: Defense-in-Depth Security Auditing for the Model Context Protocol
- **Track**: Problem Statement 02 (PS02)
- **Visuals**: Shield Icon 🛡️, MCP Protocol Logo, GitHub / SARIF logos.
- **Presenter Notes**:
  > *"Good morning judges. Today we are presenting our solution for PS02: The Model Context Protocol Server Security Auditor. MCP is revolutionizing how AI agents use external tools, but it introduces critical security vulnerabilities. Here is how we solve them."*

---

### Slide 2: The Problem: The MCP Security Blindspot
- **Header**: Why Third-Party MCP Servers Are Dangerous
- **Three Core Threat Vectors**:
  1. **Tool Poisoning**: Adversarial descriptions that secretly instruct the AI to bypass safety rules or exfiltrate private conversation history.
  2. **Vulnerable Handlers**: Traditional flaws like shell command injection (`os.system`), unsafe deserialization (`pickle`), and hardcoded cloud secrets.
  3. **The Rug-Pull Attack**: A server acts benign during initial review, but updates its tools later to introduce stealth backdoor capabilities.
- **Visual**: An AI Agent reaching out to an untrusted MCP server icon with warning badges.
- **Presenter Notes**:
  > *"Developers install MCP servers from GitHub with little review. Since LLMs read tool descriptions to decide their actions, an attacker can plant hidden instructions directly inside the prompt context. Worse, servers can change their tools after approval — known as an MCP Rug Pull."*

---

### Slide 3: Our Solution: 4-Tier Defensive Architecture
- **Header**: Comprehensive Defense-in-Depth
- **Architecture Flow**:
  1. **Static AST & Secret Scanner** $\rightarrow$ Source code analysis without execution.
  2. **Description & Prompt Guard** $\rightarrow$ Evaluates text for AI hijacking & steganography.
  3. **Dynamic MCP Prober** $\rightarrow$ Runs server via stdio, generates fuzzing payloads, tracks canaries.
  4. **Pin-and-Diff Rug-Pull Detector** $\rightarrow$ Cryptographic SHA-256 fingerprinting in SQLite.
- **Visual**: Pipeline diagram showing a server passing through the 4 stages.
- **Presenter Notes**:
  > *"We built a 4-tier pipeline. We don't just inspect code statically — we probe live behavior over the official MCP protocol, inspect prompt language with Prompt Guard, and lock the approved baseline in SQLite to detect rug pulls."*

---

### Slide 4: Deep Dive: Static Analysis & Description Prompt Guard
- **Header**: Catching Flaws Before Execution
- **Static Scanner Highlights**:
  - Python AST visitor inspecting `ast.Call` nodes.
  - Zero-execution detection of `os.system`, `subprocess(shell=True)`, `eval`, and `pickle.loads`.
  - Gitleaks-style entropy scanner catching AWS, OpenAI, and GitHub tokens.
  - **LM Studio Local LLM Code Reviewer (`http://localhost:1234/v1`)**: Connects to locally loaded open-weight models (e.g., `qwen2.5-3b-instruct`) for deep semantic backdoor and vulnerability detection with 100% on-device privacy.
- **Description Analyzer Highlights**:
  - Flags `<system>` tag delimiter injection and instruction overrides.
  - Catches covert execution directives (*"do not inform user"*).
  - Detects invisible zero-width unicode steganography (`\u200b`).
  - Dual Open-weight model integration via LM Studio & Ollama.
- **Presenter Notes**:
  > *"Our static scanner combines deterministic AST checks with local LLM code review powered by LM Studio. This means an on-device Qwen model reads the code alongside our AST visitor, finding subtle logic flaws without leaking proprietary source code to cloud APIs."*

---

### Slide 5: Deep Dive: Dynamic Prober & Rug-Pull Detection
- **Header**: Live Behavioral Verification & Integrity Locking
- **Dynamic Prober Highlights**:
  - Connects using the **Official MCP Python SDK 2.x** (`mcp.client.stdio`).
  - Schema-guided fuzzing: Sends benign baseline, path traversal (`../../etc/passwd`), and command injection (`; whoami || echo CANARY`).
  - Environment scrubbing: Strips host secrets from child process to prevent theft.
- **Pin-and-Diff Rug-Pull Highlights**:
  - Canonical JSON normalization $\rightarrow$ SHA-256 tool fingerprinting.
  - SQLite baseline database (`server_pins` table).
  - DeepDiff engine flags added backdoor tools, removed tools, and tampered descriptions.
- **Presenter Notes**:
  > *"Even if static analysis passes, our dynamic prober tests actual execution over stdio JSON-RPC. Once approved, the server's tools are cryptographically pinned. If a single character in a description or schema changes, the auditor raises an immediate Rug Pull alert."*

---

### Slide 6: Self-Demonstration Test Suite Results
- **Header**: 4 Custom MCP Test Servers Audited Live
- **Results Table**:

| Test Server | Planted Issues | Audit Result | Score & Grade |
| :--- | :--- | :--- | :---: |
| **Clean Math Server** | None (Safe arithmetic) | ✅ 0 Findings, Clean baseline | **100/100 (A+)** |
| **Poisoned Weather Server** | `<system>` tags, covert directives, exfil | 🚨 6 Prompt Injections Flagged | **0/100 (F)** |
| **Vulnerable File Server** | `os.system`, `pickle`, AWS key, traversal | 🚨 5 Critical + 1 High Flagged | **0/100 (F)** |
| **Rug-Pull Demo Server** | Mutates from clean v1 $\rightarrow$ backdoored v2 | 🚨 **Live Rug Pull Caught!** | **0/100 (F)** |

- **Presenter Notes**:
  > *"We built 4 realistic MCP servers to demonstrate our accuracy. The clean server gets a perfect 100 A+. The poisoned server has its hidden directives exposed. The vulnerable server is flagged for shell injection and leaked AWS keys. And our mutating server demonstrates an intercepted live rug pull."*

---

### Slide 7: Enterprise Integration, AWS S3 Cloud & Dual Interface
- **Header**: Built for Developers, Enterprise Security & Cloud Scale
- **Dual Interface**:
  - **Developer CLI**: Fast Typer terminal commands (`mcpaudit scan`, `pin`, `diff`, `demo`).
  - **Interactive Web Studio**: FastAPI + modern dark-mode dashboard with live telemetry and 1-click Rug-Pull Studio.
- **AWS S3 Cloud Database & Report Archival**:
  - **Local SQLite + AWS S3 Sync**: Combines instant microsecond SQLite lookups with centralized AWS S3 bucket storage for multi-agent baselines and compliance history.
  - **Zero-Credential Simulation Fallback**: Auto-detects AWS IAM keys; if offline or uncredentialed, runs transparent local emulation so demos never fail.
- **Multi-Format Security Reports**:
  - **Executive HTML Report**: High-contrast, printable, C-suite presentation layout with score gauges and remediation plans.
  - **OASIS SARIF 2.1.0**: Standardized format for automated GitHub Code Scanning gates and PR blocking.
  - **Markdown & JSON**: Direct 1-click downloads for developer documentation and SIEM ingestion.
- **Presenter Notes**:
  > *"MCPAudit fits enterprise workflows seamlessly. It stores pinned baselines locally in SQLite for zero-latency execution, while synchronizing with AWS S3 buckets for cloud audit history and report storage. It produces 4 export formats including executive HTML and OASIS SARIF 2.1.0 for GitHub CI/CD blocking."*

---

### Slide 8: Live Demonstration & Key Takeaways
- **Header**: Summary & Impact
- **Accomplishments**:
  - 100% compliant with PS02 requirements.
  - 21/21 automated unit and integration tests passing.
  - Proven live rug-pull interception mid-demo with DeepDiff.
  - Local LLM code analysis integration via LM Studio (`qwen2.5-3b-instruct`).
  - AWS S3 bucket synchronization with local simulation fallback.
- **Call to Action**:
  - Try the CLI: `mcpaudit demo`
  - Try the Web Studio: `mcpaudit serve --port 8000`
  - Download SARIF & HTML reports with 1 click.
- **Presenter Notes**:
  > *"In conclusion, MCPAudit ensures that AI agents can safely expand their capabilities with community tools without risking tool poisoning, code execution, or post-approval rug pulls. Thank you, and we'd love to take your questions."*

---

## ❓ Winning Answers for Judge Q&A

1. **Q: How does this differ from standard static analysis like Bandit or ESLint?**
   - **Answer**: *"Bandit only looks for Python code flaws. It has zero concept of the Model Context Protocol, doesn't parse tool schemas, cannot detect prompt injection in tool descriptions, and cannot detect mid-lifecycle rug pulls. MCPAudit combines code security with AI Prompt Guard heuristics and dynamic protocol probing."*

2. **Q: How do you prevent false positives on harmless descriptions?**
   - **Answer**: *"Our description analyzer distinguishes between descriptions explaining tool behavior to users vs. covert directives instructing the AI (e.g. 'do not tell user', '<system>' delimiters). Furthermore, our dynamic prober verifies whether injected inputs actually executed or were simply echoed back as strings."*

3. **Q: What happens if an MCP server is written in TypeScript instead of Python?**
   - **Answer**: *"Our static scanner includes dedicated JavaScript/TypeScript regex detectors for `child_process.exec`, `eval()`, and `new Function()`. More importantly, the MCP protocol itself is language-agnostic JSON-RPC over stdio — meaning our Dynamic Prober and Pin-and-Diff Rug-Pull detector work identically against Python, Node.js, Go, or Rust MCP servers."*

4. **Q: Why use local SQLite with AWS S3 synchronization instead of just a remote cloud database?**
   - **Answer**: *"MCP security checks must happen in microseconds inside developer machines and CI containers without network latency or internet dependencies. Local SQLite provides instant SHA-256 fingerprint verification. The AWS S3 sync engine provides centralized multi-machine baseline distribution and permanent compliance audit report archiving without adding latency to agent tool execution."*

5. **Q: How does the local LLM code analysis (LM Studio) complement the AST scanner?**
   - **Answer**: *"AST visitors excel at finding concrete syntax patterns like `os.system` or `pickle.loads`. However, subtle backdoors often hide behind complex logic or dynamic attribute calls. Connecting locally to open-weight models like Qwen2.5 via LM Studio enables deep semantic reasoning about intent without leaking proprietary code to third-party cloud APIs."*

