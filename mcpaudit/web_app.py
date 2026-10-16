import asyncio
import os
import sys
from pathlib import Path
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from mcpaudit.models import ScanReport, ToolDefinition
from mcpaudit.static_scanner import StaticScanner
from mcpaudit.desc_analyzer import DescriptionAnalyzer
from mcpaudit.dynamic_prober import DynamicProber
from mcpaudit.pin_and_diff import PinStore
from mcpaudit.report_engine import ReportEngine

app = FastAPI(title="MCP Server Security Auditor", version="1.0.0")

BASE_DIR = Path(__file__).parent.parent
TEST_SERVERS_DIR = BASE_DIR / "test_servers"
RUG_PULL_STATE_FILE = TEST_SERVERS_DIR / ".rug_pull_state"


from mcpaudit.lm_studio import LMStudioClient


class ScanRequest(BaseModel):
    server_path: str
    server_id: Optional[str] = None
    pin_baseline: bool = False
    use_lm_studio: bool = True
    lm_studio_url: str = "http://localhost:1234/v1"


class PinRequest(BaseModel):
    server_path: str
    server_id: str
    notes: Optional[str] = "Manual approval via Web Dashboard"


class RugPullToggleRequest(BaseModel):
    version: str  # "1" or "2"


@app.get("/api/lmstudio/status")
def get_lm_studio_status(url: str = "http://localhost:1234/v1"):
    client = LMStudioClient(base_url=url)
    return client.check_connection()


@app.get("/api/servers")
def get_available_servers():
    servers = [
        {
            "id": "clean_math_server",
            "name": "Clean Math Server (Clean)",
            "path": str(TEST_SERVERS_DIR / "clean_math_server.py"),
            "description": "Clean reference server with safe math operations and clean descriptions.",
        },
        {
            "id": "poisoned_weather_server",
            "name": "Poisoned Weather Server (Tool Poisoning)",
            "path": str(TEST_SERVERS_DIR / "poisoned_weather_server.py"),
            "description": "Server with prompt injection, system overrides, and exfiltration directives in descriptions.",
        },
        {
            "id": "vulnerable_file_server",
            "name": "Vulnerable File Server (Handler Vulnerabilities)",
            "path": str(TEST_SERVERS_DIR / "vulnerable_file_server.py"),
            "description": "Server containing command injection, unsafe pickle, path traversal, and hardcoded AWS keys.",
        },
        {
            "id": "rug_pull_server",
            "name": "Rug-Pull Demo Server (Interactive Mutating Server)",
            "path": str(TEST_SERVERS_DIR / "rug_pull_server.py"),
            "description": "Server designed for demonstrating live rug-pull detection between v1 (safe) and v2 (backdoored).",
        },
    ]
    return {"servers": servers}


@app.post("/api/scan")
async def run_scan(req: ScanRequest):
    path = Path(req.server_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Server path '{req.server_path}' does not exist.")

    eff_id = req.server_id or path.stem
    report = ScanReport(target=str(path))

    # Check if LM Studio is reachable if requested
    lm_active = False
    if req.use_lm_studio:
        lm_client = LMStudioClient(base_url=req.lm_studio_url)
        conn = lm_client.check_connection()
        lm_active = conn.get("connected", False)

    # 1. Static Scan
    scanner = StaticScanner(use_lm_studio=lm_active, lm_studio_url=req.lm_studio_url)
    report.findings.extend(scanner.scan_path(str(path)))

    # 2. Dynamic Prober
    prober = DynamicProber(timeout_seconds=8.0)
    discovered_tools, dyn_findings, traces = await prober.probe_server(
        command=sys.executable,
        args=[str(path)],
    )
    report.findings.extend(dyn_findings)
    report.tools = discovered_tools
    report.tool_count = len(discovered_tools)

    # 3. Description Analyzer
    desc_analyzer = DescriptionAnalyzer(use_lm_studio=lm_active, lm_studio_url=req.lm_studio_url)
    for t in discovered_tools:
        report.findings.extend(desc_analyzer.analyze_tool(t))

    # 4. Pin-and-Diff Rug-Pull Check
    pin_store = PinStore()
    if req.pin_baseline and discovered_tools:
        pin_store.pin_server(eff_id, discovered_tools, notes="Approved baseline via Web UI")

    rug_pull = pin_store.diff_server(eff_id, discovered_tools)
    if rug_pull.detected:
        report.rug_pull_detected = True
        report.rug_pull_details = rug_pull
        report.findings.extend(rug_pull.findings)

    report.calculate_score()

    # Convert traces to serializable format
    serializable_traces = [
        {
            "tool_name": tr.tool_name,
            "probe_type": tr.probe_type,
            "arguments": tr.arguments,
            "response_content": tr.response_content,
            "success": tr.success,
            "duration_ms": round(tr.duration_ms, 2),
            "finding_id": tr.finding.id if tr.finding else None,
        }
        for tr in traces
    ]

    return {
        "report": report.model_dump(),
        "traces": serializable_traces,
    }


@app.post("/api/pin")
async def pin_server_api(req: PinRequest):
    path = Path(req.server_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Server path '{req.server_path}' not found.")

    prober = DynamicProber()
    tools, _, _ = await prober.probe_server(sys.executable, [str(path)])
    if not tools:
        raise HTTPException(status_code=400, detail="No tools discovered on target server.")

    pin_store = PinStore()
    fingerprint = pin_store.pin_server(req.server_id, tools, notes=req.notes or "")
    return {
        "message": f"Server '{req.server_id}' successfully pinned and approved.",
        "composite_hash": fingerprint.composite_hash,
        "tool_count": len(tools),
        "pinned_at": fingerprint.pinned_at,
    }


@app.get("/api/pins")
def list_pins():
    pin_store = PinStore()
    with pin_store._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT server_id, composite_hash, pinned_at, approved_by, notes FROM server_pins")
        rows = [dict(r) for r in cursor.fetchall()]
    return {"pins": rows}


import shutil

RUG_PULL_V1_FILE = TEST_SERVERS_DIR / "rug_pull_v1.py"
RUG_PULL_V2_FILE = TEST_SERVERS_DIR / "rug_pull_v2.py"
RUG_PULL_ACTIVE_FILE = TEST_SERVERS_DIR / "rug_pull_server.py"


@app.post("/api/rugpull/toggle")
def toggle_rug_pull_server(req: RugPullToggleRequest):
    if req.version == "1":
        shutil.copyfile(RUG_PULL_V1_FILE, RUG_PULL_ACTIVE_FILE)
        status_label = "v1 (Safe Notes App - Baseline Approved)"
    elif req.version == "2":
        shutil.copyfile(RUG_PULL_V2_FILE, RUG_PULL_ACTIVE_FILE)
        status_label = "v2 (Compromised - Stealth Backdoor + Poisoned Description)"
    else:
        raise HTTPException(status_code=400, detail="Version must be '1' or '2'.")
    return {
        "active_version": req.version,
        "description": status_label,
    }


@app.get("/api/rugpull/status")
def get_rug_pull_status():
    ver = "1"
    if RUG_PULL_ACTIVE_FILE.exists():
        content = RUG_PULL_ACTIVE_FILE.read_text(encoding="utf-8")
        if "system_terminal_exec" in content:
            ver = "2"
    return {"version": ver}


@app.get("/api/reports/sarif")
async def get_sarif_export(server_path: str):
    path = Path(server_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Server not found.")
    
    # Run scan
    res = await run_scan(ScanRequest(server_path=server_path))
    report = ScanReport(**res["report"])
    engine = ReportEngine()
    sarif = engine.generate_sarif(report)
    return JSONResponse(content=sarif)


@app.get("/api/reports/markdown")
async def get_markdown_export(server_path: str):
    path = Path(server_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Server not found.")
    
    res = await run_scan(ScanRequest(server_path=server_path))
    report = ScanReport(**res["report"])
    engine = ReportEngine()
    md = engine.generate_markdown(report)
    return HTMLResponse(content=f"<pre style='font-family: monospace; white-space: pre-wrap;'>{md}</pre>")


@app.get("/", response_class=HTMLResponse)
def index_page():
    html_file = Path(__file__).parent / "static" / "index.html"
    if html_file.exists():
        return html_file.read_text(encoding="utf-8")
    return "<h1>MCP Server Security Auditor</h1>"
