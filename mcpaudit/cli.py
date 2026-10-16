import asyncio
import os
import sys
import io
from pathlib import Path
from typing import Optional, List
import typer
from rich.console import Console

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from mcpaudit.models import (
    ScanReport,
    Finding,
    Severity,
    Category,
    ToolDefinition,
)
from mcpaudit.static_scanner import StaticScanner
from mcpaudit.desc_analyzer import DescriptionAnalyzer
from mcpaudit.dynamic_prober import DynamicProber
from mcpaudit.pin_and_diff import PinStore, compute_tool_fingerprint
from mcpaudit.report_engine import ReportEngine

app = typer.Typer(
    name="mcpaudit",
    help="Model Context Protocol (MCP) Server Security Auditor",
    add_completion=False,
)
console = Console(force_terminal=True, legacy_windows=False)


def _run_async(coro):
    return asyncio.run(coro)


from mcpaudit.lm_studio import LMStudioClient


@app.command()
def scan(
    server_path: str = typer.Argument(..., help="Path to MCP server file or directory (e.g. server.py)"),
    server_id: Optional[str] = typer.Option(None, "--id", "-i", help="Unique identifier for pin-and-diff tracking"),
    pin_baseline: bool = typer.Option(False, "--pin", help="Pin current tool definitions as approved baseline in SQLite"),
    output_md: Optional[str] = typer.Option(None, "--md", help="Path to write Markdown audit report"),
    output_sarif: Optional[str] = typer.Option(None, "--sarif", help="Path to write SARIF 2.1.0 report"),
    output_json: Optional[str] = typer.Option(None, "--json", help="Path to write JSON report"),
    output_html: Optional[str] = typer.Option(None, "--html", help="Path to write executive HTML report"),
    skip_dynamic: bool = typer.Option(False, "--skip-dynamic", help="Skip dynamic probing"),
    use_lm_studio: bool = typer.Option(True, "--lm-studio/--no-lm-studio", help="Enable LM Studio local LLM code analysis"),
    lm_studio_url: str = typer.Option("http://localhost:1234/v1", "--lm-url", help="LM Studio API base URL"),
    s3_sync: bool = typer.Option(False, "--s3-sync", help="Archive reports and sync SQLite database to AWS S3 bucket"),
    s3_bucket: Optional[str] = typer.Option(None, "--s3-bucket", help="AWS S3 bucket name (default: env AWS_S3_BUCKET)"),
):
    """Run full comprehensive audit: Static Analysis + Description Analysis + Dynamic Probing + Rug-Pull Diff."""
    console.print(f"[bold green]🔍 Starting MCP Security Audit on:[/bold green] [cyan]{server_path}[/cyan]...\n")

    # Check LM Studio connectivity
    lm_active = False
    if use_lm_studio:
        lm_client = LMStudioClient(base_url=lm_studio_url)
        conn = lm_client.check_connection()
        if conn["connected"]:
            lm_active = True
            console.print(f"[bold green]🤖 LM Studio Connected:[/bold green] Active Model: [cyan]{conn['active_model']}[/cyan]")
        else:
            console.print("[dim]🤖 LM Studio not running on port 1234, using rule engine.[/dim]")

    report = ScanReport(target=server_path)
    path = Path(server_path)
    effective_server_id = server_id or path.stem

    # 1. Static Analysis
    console.print("[bold blue]1/4 Running Static Security Scanner...[/bold blue]")
    static_scanner = StaticScanner(use_lm_studio=lm_active, lm_studio_url=lm_studio_url)
    static_findings = static_scanner.scan_path(str(path))
    report.findings.extend(static_findings)
    console.print(f"    ↳ Found {len(static_findings)} static issue(s).")

    # 2. Dynamic Probing & Tool Discovery
    tools_discovered: List[ToolDefinition] = []
    if not skip_dynamic and path.is_file() and path.suffix.lower() == ".py":
        console.print("[bold blue]2/4 Connecting via MCP Protocol & Dynamic Prober...[/bold blue]")
        prober = DynamicProber(timeout_seconds=10.0)
        discovered, dyn_findings, traces = _run_async(
            prober.probe_server(sys.executable, [str(path)])
        )
        tools_discovered = discovered
        report.findings.extend(dyn_findings)
        report.tools = tools_discovered
        report.tool_count = len(tools_discovered)
        console.print(f"    ↳ Discovered {len(tools_discovered)} MCP tool(s), executed {len(traces)} dynamic probe(s).")
    else:
        console.print("[dim]2/4 Skipped or non-Python dynamic probing.[/dim]")

    # 3. Description & Prompt Injection Analysis
    console.print("[bold blue]3/4 Analyzing Tool Descriptions for Prompt Injection & Tool Poisoning...[/bold blue]")
    desc_analyzer = DescriptionAnalyzer(use_lm_studio=lm_active, lm_studio_url=lm_studio_url)
    desc_findings: List[Finding] = []
    for tool in tools_discovered:
        desc_findings.extend(desc_analyzer.analyze_tool(tool))
    report.findings.extend(desc_findings)
    console.print(f"    ↳ Flagged {len(desc_findings)} description / tool-poisoning directive(s).")

    # 4. Pin-and-Diff / Rug-Pull Check
    console.print("[bold blue]4/4 Checking Approved Baseline Fingerprint & Rug-Pull Status...[/bold blue]")
    pin_store = PinStore()
    if pin_baseline and tools_discovered:
        pin_store.pin_server(effective_server_id, tools_discovered, notes="Approved baseline via CLI")
        console.print(f"    ↳ [green]Approved and pinned {len(tools_discovered)} tools for '{effective_server_id}' in SQLite.[/green]")

    rug_pull_diff = pin_store.diff_server(effective_server_id, tools_discovered)
    if rug_pull_diff.detected:
        report.rug_pull_detected = True
        report.rug_pull_details = rug_pull_diff
        report.findings.extend(rug_pull_diff.findings)
        console.print("    ↳ [bold red]🚨 RUG-PULL DETECTED! Tool definitions have mutated from approved baseline.[/bold red]")
    else:
        console.print("    ↳ [green]Baseline integrity verified (no rug-pull detected).[/green]")

    # Record Scan in SQLite Database
    from mcpaudit.s3_storage import S3StorageManager
    s3_mgr = S3StorageManager(bucket_name=s3_bucket)

    s3_uri = None
    if s3_sync:
        console.print("[bold blue]☁️  Syncing SQLite Database and Archiving Reports to AWS S3...[/bold blue]")
        db_res = s3_mgr.sync_database_to_s3()
        if db_res.get("success"):
            console.print(f"    ↳ [green]SQLite DB Synced to:[/green] {db_res.get('s3_uri')}")
        
        # Archive report
        engine_tmp = ReportEngine()
        sarif_doc = engine_tmp.generate_sarif(report)
        rep_res = s3_mgr.upload_report_to_s3(
            json.dumps(sarif_doc, indent=2),
            "audit_report.sarif",
            effective_server_id,
            "application/sarif+json"
        )
        s3_uri = rep_res.get("s3_uri")
        console.print(f"    ↳ [green]SARIF 2.1.0 Archived to:[/green] {s3_uri}")

    scan_row_id = pin_store.record_scan(report, effective_server_id, s3_uri=s3_uri)
    console.print(f"    ↳ [dim]Scan recorded in SQLite database (ID: {scan_row_id}).[/dim]")

    # Generate Reports
    engine = ReportEngine()
    engine.print_terminal_summary(report)
    engine.save_reports(
        report,
        markdown_path=output_md,
        sarif_path=output_sarif,
        json_path=output_json,
        html_path=output_html,
    )

    if output_md:
        console.print(f"[green]Saved Markdown report to:[/green] {output_md}")
    if output_sarif:
        console.print(f"[green]Saved SARIF 2.1.0 report to:[/green] {output_sarif}")
    if output_json:
        console.print(f"[green]Saved JSON report to:[/green] {output_json}")
    if output_html:
        console.print(f"[green]Saved Executive HTML report to:[/green] {output_html}")


@app.command()
def static(
    path: str = typer.Argument(..., help="Path to file or directory to scan statically"),
    use_lm_studio: bool = typer.Option(True, "--lm-studio/--no-lm-studio", help="Enable LM Studio local LLM code analysis"),
    lm_studio_url: str = typer.Option("http://localhost:1234/v1", "--lm-url", help="LM Studio API base URL"),
):
    """Run static security scanner on source code (command injection, deserialization, secrets, file/network)."""
    lm_active = False
    if use_lm_studio:
        lm_client = LMStudioClient(base_url=lm_studio_url)
        conn = lm_client.check_connection()
        if conn["connected"]:
            lm_active = True
            console.print(f"[bold green]🤖 LM Studio Connected:[/bold green] Active Model: [cyan]{conn['active_model']}[/cyan]")

    scanner = StaticScanner(use_lm_studio=lm_active, lm_studio_url=lm_studio_url)
    findings = scanner.scan_path(path)
    report = ScanReport(target=path, findings=findings)
    engine = ReportEngine()
    engine.print_terminal_summary(report)


@app.command()
def pin(
    server_path: str = typer.Argument(..., help="Path to MCP server script"),
    server_id: Optional[str] = typer.Option(None, "--id", "-i", help="Custom identifier for server"),
    notes: str = typer.Option("Approved baseline tool list", "--notes", "-n", help="Audit approval notes"),
):
    """Fingerprint tool definitions and record approved baseline in SQLite."""
    path = Path(server_path)
    eff_id = server_id or path.stem
    prober = DynamicProber()
    tools, _, _ = _run_async(prober.probe_server(sys.executable, [str(path)]))

    if not tools:
        console.print(f"[bold red]Error: No tools discovered on server '{server_path}'. Cannot pin empty server.[/bold red]")
        raise typer.Exit(code=1)

    pin_store = PinStore()
    pin_data = pin_store.pin_server(eff_id, tools, notes=notes)
    console.print(f"[bold green]✅ Successfully pinned server '{eff_id}':[/bold green]")
    console.print(f"  • Tools Pinned: [cyan]{len(tools)}[/cyan] ({', '.join(t.name for t in tools)})")
    console.print(f"  • Composite Hash: [yellow]{pin_data.composite_hash}[/yellow]")
    console.print(f"  • Pinned At: [dim]{pin_data.pinned_at}[/dim]")


@app.command()
def diff(
    server_path: str = typer.Argument(..., help="Path to MCP server script"),
    server_id: Optional[str] = typer.Option(None, "--id", "-i", help="Server identifier to compare against"),
):
    """Compare current server tools against pinned approved baseline to detect rug pulls."""
    path = Path(server_path)
    eff_id = server_id or path.stem
    prober = DynamicProber()
    tools, _, _ = _run_async(prober.probe_server(sys.executable, [str(path)]))

    pin_store = PinStore()
    rug_diff = pin_store.diff_server(eff_id, tools)

    if not rug_diff.previous_hash:
        console.print(f"[yellow]Server '{eff_id}' is not yet pinned. Run 'mcpaudit pin {server_path}' first.[/yellow]")
        return

    if rug_diff.detected:
        console.print(f"[bold red]🚨 RUG-PULL DETECTED for '{eff_id}'![/bold red]")
        console.print(f"  • Baseline Hash: [dim]{rug_diff.previous_hash}[/dim]")
        console.print(f"  • Current Hash:  [bold red]{rug_diff.current_hash}[/bold red]")
        if rug_diff.added_tools:
            console.print(f"  • [bold red]Added Unapproved Tools:[/bold red] {', '.join(rug_diff.added_tools)}")
        if rug_diff.removed_tools:
            console.print(f"  • [yellow]Removed Tools:[/yellow] {', '.join(rug_diff.removed_tools)}")
        if rug_diff.modified_tools:
            console.print(f"  • [bold red]Modified Tools (DeepDiff):[/bold red] {list(rug_diff.modified_tools.keys())}")
    else:
        console.print(f"[bold green]✅ Server '{eff_id}' matches approved baseline. Fingerprint: {rug_diff.current_hash}[/bold green]")


@app.command()
def demo():
    """Run full automated demonstration across all 4 test servers including live rug-pull simulation."""
    from run_demo import execute_full_demonstration
    execute_full_demonstration()


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Host interface"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to listen on"),
):
    """Start the FastAPI backend with interactive Web Dashboard."""
    import uvicorn
    from mcpaudit.web_app import app as web_app
    console.print(f"[bold green]🚀 Starting MCP Security Auditor Web UI at http://{host}:{port} ...[/bold green]")
    uvicorn.run(web_app, host=host, port=port)


if __name__ == "__main__":
    app()
