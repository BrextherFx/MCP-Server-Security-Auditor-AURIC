import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from mcpaudit.models import ScanReport, Finding, Severity

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


class ReportEngine:
    def __init__(self):
        self.console = Console(force_terminal=True, legacy_windows=False)

    def print_terminal_summary(self, report: ScanReport):
        report.calculate_score()

        # Grade color
        grade_colors = {
            "A+": "bold green",
            "A": "green",
            "B": "cyan",
            "C": "yellow",
            "D": "magenta",
            "F": "bold red",
        }
        grade_style = grade_colors.get(report.grade, "white")

        # Summary Header Panel
        rug_pull_msg = ""
        if report.rug_pull_detected:
            rug_pull_msg = "\n[bold red blink]🚨 CRITICAL ALERT: RUG-PULL DETECTED! Tool definitions mutated since baseline approval! 🚨[/bold red blink]"

        header_content = (
            f"[bold cyan]Target:[/bold cyan] {report.target}\n"
            f"[bold cyan]Timestamp:[/bold cyan] {report.scanned_at}\n"
            f"[bold cyan]Tools Scanned:[/bold cyan] {report.tool_count}\n"
            f"[bold cyan]Security Score:[/bold cyan] [{grade_style}]{report.security_score}/100 (Grade: {report.grade})[/{grade_style}]\n"
            f"[bold cyan]Findings Summary:[/bold cyan] "
            f"[bold red]CRITICAL: {report.summary.get('CRITICAL', 0)}[/bold red] | "
            f"[bold orange3]HIGH: {report.summary.get('HIGH', 0)}[/bold orange3] | "
            f"[yellow]MEDIUM: {report.summary.get('MEDIUM', 0)}[/yellow] | "
            f"[blue]LOW: {report.summary.get('LOW', 0)}[/blue] | "
            f"[white]INFO: {report.summary.get('INFO', 0)}[/white]"
            f"{rug_pull_msg}"
        )

        self.console.print(
            Panel(
                header_content,
                title="🛡️  [bold green]MCP Server Security Auditor Report[/bold green]  🛡️",
                border_style="green",
            )
        )

        if not report.findings:
            self.console.print("[bold green]✅ No security findings identified! Server is clean.[/bold green]\n")
            return

        # Findings Table
        table = Table(title="Security Findings & Vulnerability Evidence", expand=True)
        table.add_column("ID", style="bold cyan", width=14)
        table.add_column("Severity", width=10)
        table.add_column("Category", width=22)
        table.add_column("Location / Tool", width=20)
        table.add_column("Evidence & Recommended Fix", style="dim")

        severity_colors = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "orange3",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "dim white",
        }

        # Sort findings: CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO
        severity_order = {s: i for i, s in enumerate(Severity)}
        sorted_findings = sorted(report.findings, key=lambda f: severity_order.get(f.severity, 99))

        for f in sorted_findings:
            sev_style = severity_colors.get(f.severity, "white")
            sev_badge = f"[{sev_style}]{f.severity.value}[/{sev_style}]"

            loc = f.file_path or f.tool_name or "Global"
            if f.line_number:
                loc += f":{f.line_number}"

            evidence_text = f"[bold white]{f.title}[/bold white]\n[yellow]Evidence:[/yellow] {f.evidence[:250]}\n[green]Fix:[/green] {f.remediation}"

            table.add_row(
                f.id,
                sev_badge,
                f.category,
                loc,
                evidence_text,
            )

        self.console.print(table)
        self.console.print()

    def generate_markdown(self, report: ScanReport) -> str:
        report.calculate_score()

        md = []
        md.append(f"# 🛡️ MCP Server Security Audit Report")
        md.append("")
        md.append(f"- **Target:** `{report.target}`")
        md.append(f"- **Audit Date:** `{report.scanned_at}`")
        md.append(f"- **Tools Audited:** `{report.tool_count}`")
        md.append(f"- **Security Score:** `{report.security_score}/100` (**Grade: {report.grade}**)")
        md.append("")

        if report.rug_pull_detected:
            md.append("> [!CAUTION]")
            md.append("> **CRITICAL INTEGRITY BREACH: RUG PULL DETECTED!**")
            md.append("> This MCP server has mutated since its approved baseline. Unapproved tools or modified descriptions/schemas were detected.")
            md.append("")

        md.append("## Executive Summary")
        md.append("")
        md.append("| Severity | Count |")
        md.append("| :--- | :--- |")
        for sev in Severity:
            count = report.summary.get(sev.value, 0)
            md.append(f"| **{sev.value}** | {count} |")
        md.append("")

        if report.rug_pull_details and report.rug_pull_details.detected:
            md.append("## 🚨 Rug-Pull Analysis Details")
            md.append("")
            md.append(f"- **Server ID:** `{report.rug_pull_details.server_id}`")
            md.append(f"- **Baseline Hash:** `{report.rug_pull_details.previous_hash}`")
            md.append(f"- **Current Hash:** `{report.rug_pull_details.current_hash}`")
            if report.rug_pull_details.added_tools:
                md.append(f"- **Added Tools (Unvetted):** {', '.join(f'`{t}`' for t in report.rug_pull_details.added_tools)}")
            if report.rug_pull_details.removed_tools:
                md.append(f"- **Removed Tools:** {', '.join(f'`{t}`' for t in report.rug_pull_details.removed_tools)}")
            if report.rug_pull_details.modified_tools:
                md.append(f"- **Modified Tools:** {', '.join(f'`{t}`' for t in report.rug_pull_details.modified_tools.keys())}")
            md.append("")

        md.append("## Detailed Findings")
        md.append("")
        if not report.findings:
            md.append("✅ **No vulnerabilities or security warnings found. The MCP server passed all audit checks.**")
            md.append("")
        else:
            for idx, f in enumerate(report.findings, start=1):
                md.append(f"### {idx}. [{f.severity.value}] {f.title} (`{f.id}`)")
                md.append(f"- **Category:** {f.category}")
                if f.tool_name:
                    md.append(f"- **Tool:** `{f.tool_name}`")
                if f.file_path:
                    loc = f"`{f.file_path}`" + (f" (Line {f.line_number})" if f.line_number else "")
                    md.append(f"- **Location:** {loc}")
                md.append(f"- **Evidence:**")
                md.append("```")
                md.append(f.evidence)
                md.append("```")
                md.append(f"- **Remediation / Fix:** {f.remediation}")
                md.append("")

        md.append("---")
        md.append("*Generated by MCP Server Security Auditor (PS02)*")
        return "\n".join(md)

    def generate_sarif(self, report: ScanReport) -> Dict[str, Any]:
        """Generates standard OASIS SARIF v2.1.0 output."""
        rules_dict: Dict[str, Any] = {}
        results: List[Dict[str, Any]] = []

        for f in report.findings:
            if f.id not in rules_dict:
                rules_dict[f.id] = {
                    "id": f.id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f"{f.title} - Category: {f.category}"},
                    "defaultConfiguration": {
                        "level": {
                            Severity.CRITICAL: "error",
                            Severity.HIGH: "error",
                            Severity.MEDIUM: "warning",
                            Severity.LOW: "note",
                            Severity.INFO: "none",
                        }.get(f.severity, "warning")
                    },
                    "help": {
                        "text": f"Remediation: {f.remediation}",
                        "markdown": f"**Remediation:** {f.remediation}",
                    },
                }
            results.append(f.to_sarif_result())

        sarif_doc = {
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos01/schemas/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "MCPServerSecurityAuditor",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/mcpaudit",
                            "rules": list(rules_dict.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }
        return sarif_doc

    def save_reports(
        self,
        report: ScanReport,
        markdown_path: Optional[str] = None,
        sarif_path: Optional[str] = None,
        json_path: Optional[str] = None,
    ):
        if markdown_path:
            Path(markdown_path).write_text(self.generate_markdown(report), encoding="utf-8")
        if sarif_path:
            sarif = self.generate_sarif(report)
            Path(sarif_path).write_text(json.dumps(sarif, indent=2), encoding="utf-8")
        if json_path:
            Path(json_path).write_text(report.model_dump_json(indent=2), encoding="utf-8")
