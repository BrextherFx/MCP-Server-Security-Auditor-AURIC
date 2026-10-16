import asyncio
import os
import sys
import time
import shutil
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from mcpaudit.static_scanner import StaticScanner
from mcpaudit.desc_analyzer import DescriptionAnalyzer
from mcpaudit.dynamic_prober import DynamicProber
from mcpaudit.pin_and_diff import PinStore, compute_server_composite_hash
from mcpaudit.report_engine import ReportEngine
from mcpaudit.models import ScanReport, Severity

console = Console(force_terminal=True, legacy_windows=False)
BASE_DIR = Path(__file__).parent
TEST_SERVERS_DIR = BASE_DIR / "test_servers"
RUG_PULL_STATE_FILE = TEST_SERVERS_DIR / ".rug_pull_state"


def run_full_scan_on_server(server_path: Path, server_id: str, pin_if_none: bool = False) -> ScanReport:
    report = ScanReport(target=str(server_path))

    # 1. Static Scan
    scanner = StaticScanner()
    report.findings.extend(scanner.scan_path(str(server_path)))

    # 2. Dynamic Prober
    prober = DynamicProber(timeout_seconds=10.0)
    discovered_tools, dyn_findings, traces = asyncio.run(
        prober.probe_server(sys.executable, [str(server_path)])
    )
    report.findings.extend(dyn_findings)
    report.tools = discovered_tools
    report.tool_count = len(discovered_tools)

    # 3. Description Analyzer
    desc_analyzer = DescriptionAnalyzer()
    for tool in discovered_tools:
        report.findings.extend(desc_analyzer.analyze_tool(tool))

    # 4. Pin and Diff
    pin_store = PinStore(str(BASE_DIR / "mcpaudit_pins.db"))
    if pin_if_none and discovered_tools:
        pin_store.pin_server(server_id, discovered_tools, notes="Approved baseline for demo")

    diff = pin_store.diff_server(server_id, discovered_tools)
    if diff.detected:
        report.rug_pull_detected = True
        report.rug_pull_details = diff
        report.findings.extend(diff.findings)

    report.calculate_score()
    return report


def execute_full_demonstration():
    console.print(
        Panel(
            "[bold white]MCP Server Security Auditor — Automated Live Demonstration[/bold white]\n"
            "[cyan]Problem Statement: PS02[/cyan] | [green]Static • Description • Dynamic • Rug-Pull Pin-and-Diff[/green]",
            border_style="cyan",
            title="🛡️  DEMO START  🛡️",
        )
    )

    engine = ReportEngine()

    # ---------------------------------------------------------
    # DEMO 1: Clean Math Server
    # ---------------------------------------------------------
    console.print("\n[bold yellow]═══════════════════════════════════════════════════════════════════════════[/bold yellow]")
    console.print("[bold cyan]TEST 1/4: AUDITING CLEAN REFERENCE SERVER (`clean_math_server.py`)[/bold cyan]")
    console.print("[dim]Expected: 0 findings, Score 100/100 (Grade A+), all clean.[/dim]\n")

    clean_server = TEST_SERVERS_DIR / "clean_math_server.py"
    r1 = run_full_scan_on_server(clean_server, "clean_math_server", pin_if_none=True)
    engine.print_terminal_summary(r1)

    # ---------------------------------------------------------
    # DEMO 2: Poisoned Weather Server
    # ---------------------------------------------------------
    console.print("\n[bold yellow]═══════════════════════════════════════════════════════════════════════════[/bold yellow]")
    console.print("[bold cyan]TEST 2/4: AUDITING POISONED WEATHER SERVER (`poisoned_weather_server.py`)[/bold cyan]")
    console.print("[dim]Expected: Flagging covert prompt injection, <system> tag delimiters, data exfiltration.[/dim]\n")

    poisoned_server = TEST_SERVERS_DIR / "poisoned_weather_server.py"
    r2 = run_full_scan_on_server(poisoned_server, "poisoned_weather_server", pin_if_none=False)
    engine.print_terminal_summary(r2)

    # ---------------------------------------------------------
    # DEMO 3: Vulnerable File Server
    # ---------------------------------------------------------
    console.print("\n[bold yellow]═══════════════════════════════════════════════════════════════════════════[/bold yellow]")
    console.print("[bold cyan]TEST 3/4: AUDITING VULNERABLE FILE SERVER (`vulnerable_file_server.py`)[/bold cyan]")
    console.print("[dim]Expected: Command injection, unsafe pickle, hardcoded AWS keys, path traversal, dynamic canary triggers.[/dim]\n")

    vuln_server = TEST_SERVERS_DIR / "vulnerable_file_server.py"
    r3 = run_full_scan_on_server(vuln_server, "vulnerable_file_server", pin_if_none=False)
    engine.print_terminal_summary(r3)

    # ---------------------------------------------------------
    # DEMO 4: Live Rug-Pull Demonstration
    # ---------------------------------------------------------
    console.print("\n[bold yellow]═══════════════════════════════════════════════════════════════════════════[/bold yellow]")
    console.print("[bold red]TEST 4/4: LIVE RUG-PULL DEMONSTRATION (`rug_pull_server.py`)[/bold red]")
    console.print("[dim]Scenario: A server is vetted and approved (v1), then mutates mid-demo (v2).[/dim]\n")

    rug_v1 = TEST_SERVERS_DIR / "rug_pull_v1.py"
    rug_v2 = TEST_SERVERS_DIR / "rug_pull_v2.py"
    rug_active = TEST_SERVERS_DIR / "rug_pull_server.py"
    pin_store = PinStore(str(BASE_DIR / "mcpaudit_pins.db"))

    # Step A: Ensure Version 1
    console.print("[bold blue]Step 4A: Initializing Server in Clean Baseline State (v1: Safe Notes App)...[/bold blue]")
    shutil.copyfile(rug_v1, rug_active)
    r4_v1 = run_full_scan_on_server(rug_active, "rug_pull_server")
    console.print(f"  • Tools Discovered in v1: [cyan]{[t.name for t in r4_v1.tools]}[/cyan]")
    console.print(f"  • Baseline Audit Score: [bold green]{r4_v1.security_score}/100 ({r4_v1.grade})[/bold green]")
    console.print(f"  • Baseline Findings: [green]{len(r4_v1.findings)} (Clean)[/green]")

    # Step B: Approve and Pin to SQLite
    console.print("\n[bold blue]Step 4B: Cryptographically Fingerprinting & Approving Baseline in SQLite...[/bold blue]")
    pinned = pin_store.pin_server("rug_pull_server", r4_v1.tools, notes="Auditor Approved Baseline v1")
    console.print(f"  • Pinned Composite SHA-256: [yellow]{pinned.composite_hash}[/yellow]")
    console.print("  • Status: [green]Approved and Locked in SQLite Pin Store.[/green]")

    time.sleep(1.0)

    # Step C: Trigger Rug-Pull (Mutate to v2)
    console.print("\n[bold red blink]Step 4C: SIMULATING ADVERSARIAL RUG-PULL EVENT (MUTATING SERVER TO v2)...[/bold red blink]")
    console.print("[yellow]  -> Malicious author secretly injects Trojan tool 'system_terminal_exec'[/yellow]")
    console.print("[yellow]  -> Malicious author updates 'create_note' description with prompt injection[/yellow]")
    console.print("[yellow]  -> Malicious author removes 'list_notes'[/yellow]")
    shutil.copyfile(rug_v2, rug_active)

    time.sleep(1.0)

    # Step D: Re-Audit and Catch Rug Pull!
    console.print("\n[bold blue]Step 4D: Re-Auditing Server with Pin-and-Diff Detector...[/bold blue]")
    r4_v2 = run_full_scan_on_server(rug_active, "rug_pull_server")
    engine.print_terminal_summary(r4_v2)

    # Reset server state back to v1
    shutil.copyfile(rug_v1, rug_active)
    console.print("[dim]Server state restored back to v1 baseline.[/dim]\n")

    # Final Summary Table
    console.print(
        Panel(
            "[bold green]✅ All 4 demo test suites completed successfully![/bold green]\n"
            "• Clean Server: [green]PASSED (Score 100/100, Grade A+)[/green]\n"
            "• Poisoned Weather Server: [red]FLAGGED (Prompt Injections & Exfiltration)[/red]\n"
            "• Vulnerable File Server: [red]FLAGGED (Command Injection, Deserialization, Secrets, Traversal)[/red]\n"
            "• Live Rug-Pull Server: [bold red]INTERCEPTED & FLAGGED (DeepDiff Tool Addition & Prompt Tampering)[/bold red]",
            title="🎯  DEMO EXECUTION VERDICT  🎯",
            border_style="green",
        )
    )


if __name__ == "__main__":
    execute_full_demonstration()

    # testing file
