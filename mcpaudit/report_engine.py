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

        # Dedicated Actionable Solutions and Code Patches Panel
        if show_solutions and sorted_findings:
            self.console.print(
                Panel(
                    "[bold green]💡 ACTIONABLE REMEDIATION & SECURITY CODE PATCHES[/bold green]\n"
                    "[dim]Step-by-step developer implementation guide and safe code replacement patterns:[/dim]",
                    border_style="green",
                    padding=(0, 2),
                )
            )
            for f in sorted_findings:
                sev_style = severity_colors.get(f.severity, "white")
                loc = f.file_path or f.tool_name or "Global"
                if f.line_number:
                    loc += f":{f.line_number}"

                steps_str = ""
                if f.solution_steps:
                    steps_str = "\n".join(f"  [cyan]{i+1}.[/cyan] {s}" for i, s in enumerate(f.solution_steps))

                content_parts = [
                    f"[bold]Category:[/bold] {f.category}  |  [bold]Target:[/bold] [cyan]{loc}[/cyan]",
                    f"[bold green]Remediation Strategy:[/bold green] {f.solution_summary or f.remediation}",
                ]
                if steps_str:
                    content_parts.append(f"[bold yellow]Actionable Resolution Steps:[/bold yellow]\n{steps_str}")

                if f.code_fix_before and f.code_fix_after:
                    content_parts.append(
                        f"[bold red]❌ Vulnerable Implementation Pattern:[/bold red]\n{f.code_fix_before}\n\n"
                        f"[bold green]✅ Recommended Safe Code Fix:[/bold green]\n{f.code_fix_after}"
                    )

                border_color = "red" if f.severity == Severity.CRITICAL else ("orange3" if f.severity == Severity.HIGH else ("yellow" if f.severity == Severity.MEDIUM else "blue"))
                self.console.print(
                    Panel(
                        "\n\n".join(content_parts),
                        title=f"[{sev_style}][{f.severity.value}][/{sev_style}] [bold cyan]{f.id}[/bold cyan] — [white]{f.title}[/white]",
                        border_style=border_color,
                        padding=(1, 2),
                    )
                )
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

        md.append("## Detailed Findings & Actionable Solutions")
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
                md.append(f"- **Remediation Strategy:** {f.solution_summary or f.remediation}")
                if f.solution_steps:
                    md.append("- **Actionable Fix Steps:**")
                    for s_idx, step in enumerate(f.solution_steps, 1):
                        md.append(f"  {s_idx}. {step}")
                if f.code_fix_before and f.code_fix_after:
                    md.append("- **Code Solution (Before vs After):**")
                    md.append("```python")
                    md.append(f.code_fix_before)
                    md.append("")
                    md.append(f.code_fix_after)
                    md.append("```")
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

    def generate_html(self, report: ScanReport) -> str:
        """Generates an executive, printable HTML security report."""
        report.calculate_score()
        summary = report.summary or {}

        findings_html = ""
        if not report.findings:
            findings_html = '<div style="background:#052e16;border:1px solid #16a34a;padding:20px;border-radius:8px;color:#4ade80;"><strong>✅ Clean Server:</strong> Zero security vulnerabilities identified.</div>'
        else:
            for idx, f in enumerate(report.findings, 1):
                sev_color = {
                    Severity.CRITICAL: "#ef4444",
                    Severity.HIGH: "#f97316",
                    Severity.MEDIUM: "#eab308",
                    Severity.LOW: "#3b82f6",
                    Severity.INFO: "#64748b",
                }.get(f.severity, "#94a3b8")

                loc = f.file_path or f.tool_name or "Global"
                if f.line_number:
                    loc += f" (Line {f.line_number})"

                steps_html = ""
                if f.solution_steps:
                    steps_html = "<ol style='margin:4px 0 8px 18px;padding:0;color:#cbd5e1;font-size:12px;'>" + "".join(f"<li>{s}</li>" for s in f.solution_steps) + "</ol>"

                code_box = ""
                if f.code_fix_before and f.code_fix_after:
                    code_box = f"""
                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:8px;">
                        <div style="background:#450a0a;border:1px solid #7f1d1d;border-radius:4px;padding:8px;font-family:monospace;font-size:11px;color:#fca5a5;white-space:pre-wrap;"><strong>❌ Vulnerable:</strong><br>{f.code_fix_before}</div>
                        <div style="background:#064e3b;border:1px solid #047857;border-radius:4px;padding:8px;font-family:monospace;font-size:11px;color:#a7f3d0;white-space:pre-wrap;"><strong>✅ Secure Fix:</strong><br>{f.code_fix_after}</div>
                    </div>
                    """

                findings_html += f"""
                <div style="background:#1e293b;border:1px solid #334155;border-left:4px solid {sev_color};padding:16px;margin-bottom:14px;border-radius:6px;">
                    <div style="display:flex;justify-content:space-between;margin-bottom:8px;">
                        <div>
                            <span style="background:{sev_color};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold;">{f.severity.value}</span>
                            <span style="color:#38bdf8;font-family:monospace;font-size:12px;margin-left:8px;">{f.id}</span>
                            <span style="font-weight:bold;color:#f8fafc;margin-left:8px;">{f.title}</span>
                        </div>
                        <span style="color:#94a3b8;font-size:11px;font-family:monospace;">{loc}</span>
                    </div>
                    <div style="background:#0f172a;border:1px solid #1e293b;padding:10px;border-radius:4px;font-family:monospace;font-size:12px;color:#cbd5e1;white-space:pre-wrap;margin-bottom:8px;">{f.evidence}</div>
                    <div style="background:#0f172a;border:1px solid #10b981;border-radius:6px;padding:10px;margin-top:8px;">
                        <div style="color:#34d399;font-size:12px;font-weight:bold;margin-bottom:4px;">💡 Actionable Solution &amp; Remediation:</div>
                        <div style="color:#e2e8f0;font-size:12px;margin-bottom:6px;">{f.solution_summary or f.remediation}</div>
                        {steps_html}
                        {code_box}
                    </div>
                </div>
                """

        rug_pull_alert = ""
        if report.rug_pull_detected:
            rug_pull_alert = """
            <div style="background:#450a0a;border:2px solid #ef4444;padding:16px;border-radius:8px;margin-bottom:20px;color:#fecaca;">
                <h3 style="margin:0 0 6px 0;color:#f87171;">🚨 CRITICAL INTEGRITY BREACH: RUG PULL DETECTED!</h3>
                <p style="margin:0;font-size:13px;">This server mutated after baseline approval. Stealth tools, modified tool descriptions, or parameter schema changes were intercepted.</p>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>MCP Security Audit - {report.target}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0b1120; color: #f8fafc; margin: 0; padding: 40px; }}
        .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 24px; margin-bottom: 24px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid #334155; font-size: 13px; }}
        th {{ background: #0f172a; color: #94a3b8; }}
        @media print {{
            body {{ background: #fff; color: #000; padding: 10px; }}
            .card {{ border: 1px solid #ccc; background: #fff; color: #000; }}
        }}
    </style>
</head>
<body>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;border-bottom:1px solid #334155;padding-bottom:16px;">
        <div>
            <h1 style="margin:0;font-size:24px;color:#fff;">🛡️ MCP Server Security Audit Report</h1>
            <p style="margin:4px 0 0 0;font-size:13px;color:#94a3b8;">Target: <code>{report.target}</code> | Audited: {report.scanned_at}</p>
        </div>
        <div style="text-align:right;">
            <div style="font-size:28px;font-weight:bold;color:#4ade80;">{report.security_score}<span style="font-size:14px;color:#94a3b8;">/100</span></div>
            <div style="font-size:12px;color:#94a3b8;">Security Grade: <strong style="color:#4ade80;">{report.grade}</strong></div>
        </div>
    </div>

    {rug_pull_alert}

    <div class="card">
        <h2 style="margin-top:0;font-size:16px;color:#f8fafc;">Executive Summary</h2>
        <table>
            <tr><th>Metric</th><th>Value</th><th>Metric</th><th>Value</th></tr>
            <tr>
                <td><strong>Critical Vulnerabilities</strong></td><td style="color:#ef4444;font-weight:bold;">{summary.get('CRITICAL', 0)}</td>
                <td><strong>Total Tools Discovered</strong></td><td>{report.tool_count}</td>
            </tr>
            <tr>
                <td><strong>High Risk Flaws</strong></td><td style="color:#f97316;font-weight:bold;">{summary.get('HIGH', 0)}</td>
                <td><strong>Integrity Status</strong></td><td>{'🚨 Compromised (Rug Pull)' if report.rug_pull_detected else '✅ Verified (Clean)'}</td>
            </tr>
            <tr>
                <td><strong>Medium Warnings</strong></td><td style="color:#eab308;font-weight:bold;">{summary.get('MEDIUM', 0)}</td>
                <td><strong>Low / Info Findings</strong></td><td>{summary.get('LOW', 0) + summary.get('INFO', 0)}</td>
            </tr>
        </table>
    </div>

    <div class="card">
        <h2 style="margin-top:0;font-size:16px;color:#f8fafc;">Detailed Security Findings ({len(report.findings)})</h2>
        {findings_html}
    </div>

    <div style="text-align:center;font-size:11px;color:#64748b;margin-top:40px;">
        Generated by MCP Server Security Auditor (PS02) • Confidential Security Audit Report
    </div>
</body>
</html>"""
        return html

    def save_reports(
        self,
        report: ScanReport,
        markdown_path: Optional[str] = None,
        sarif_path: Optional[str] = None,
        json_path: Optional[str] = None,
        html_path: Optional[str] = None,
    ):
        if markdown_path:
            Path(markdown_path).write_text(self.generate_markdown(report), encoding="utf-8")
        if sarif_path:
            sarif = self.generate_sarif(report)
            Path(sarif_path).write_text(json.dumps(sarif, indent=2), encoding="utf-8")
        if json_path:
            Path(json_path).write_text(report.model_dump_json(indent=2), encoding="utf-8")
        if html_path:
            Path(html_path).write_text(self.generate_html(report), encoding="utf-8")

    def generate_solutions_guide_markdown(self, report: ScanReport) -> str:
        """Generates a developer-first Markdown remediation handbook with copyable code patches."""
        report.calculate_score()
        md = []
        md.append(f"# 💡 MCP Server Security Remediation & Code Patch Guide")
        md.append(f"**Target:** `{report.target}` | **Audit Date:** `{report.scanned_at}` | **Score:** `{report.security_score}/100` (Grade: **{report.grade}**)\n")
        md.append("> This manual contains concrete, step-by-step developer remediation instructions and copyable code solutions to resolve all detected vulnerabilities in this MCP server.\n")

        if not report.findings:
            md.append("✅ **Clean Server:** Zero vulnerabilities detected. No fixes required.")
            return "\n".join(md)

        for i, f in enumerate(report.findings, 1):
            md.append(f"## {i}. [{f.severity.value}] {f.title} (`{f.id}`)")
            md.append(f"- **Category:** {f.category}")
            loc = f.file_path or f.tool_name or "Global"
            if f.line_number:
                loc += f" (Line {f.line_number})"
            md.append(f"- **Location / Target:** `{loc}`")
            md.append(f"- **Remediation Strategy:** {f.solution_summary or f.remediation}")
            
            if f.solution_steps:
                md.append("\n### 🛠️ Implementation Steps:")
                for si, step in enumerate(f.solution_steps, 1):
                    md.append(f"{si}. {step}")
            
            if f.code_fix_before and f.code_fix_after:
                md.append("\n### 💻 Concrete Code Solution (Before vs After):")
                md.append("```python")
                md.append(f.code_fix_before)
                md.append("")
                md.append(f.code_fix_after)
                md.append("```")
            md.append("\n---\n")

        md.append("*Generated by MCP Server Security Auditor (PS02) Remediation Engine*")
        return "\n".join(md)

    def print_solutions_guide(self, report: ScanReport, category_filter: Optional[str] = None):
        """Prints a rich, formatted remediation guide directly in the CLI terminal."""
        report.calculate_score()
        findings = report.findings
        if category_filter:
            c_low = category_filter.lower()
            findings = [f for f in findings if c_low in f.category.lower() or c_low in f.id.lower() or c_low in f.title.lower()]

        self.console.print(
            Panel(
                f"[bold green]💡 MCP SECURITY REMEDIATION GUIDE & CODE SOLUTIONS[/bold green]\n"
                f"[dim]Target: {report.target} | Findings with Actionable Patches: {len(findings)}[/dim]",
                border_style="green",
                padding=(0, 2),
            )
        )

        if not findings:
            self.console.print("[bold green]✅ No matching security issues found for remediation.[/bold green]\n")
            return

        severity_colors = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "orange3",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "dim white",
        }

        for idx, f in enumerate(findings, 1):
            sev_style = severity_colors.get(f.severity, "white")
            loc = f.file_path or f.tool_name or "Global"
            if f.line_number:
                loc += f":{f.line_number}"

            steps_str = ""
            if f.solution_steps:
                steps_str = "\n".join(f"  [cyan]{i+1}.[/cyan] {s}" for i, s in enumerate(f.solution_steps))

            content_parts = [
                f"[bold]Category:[/bold] {f.category}  |  [bold]Location:[/bold] [cyan]{loc}[/cyan]",
                f"[bold green]Strategy:[/bold green] {f.solution_summary or f.remediation}",
            ]
            if steps_str:
                content_parts.append(f"[bold yellow]Step-by-Step Resolution:[/bold yellow]\n{steps_str}")

            if f.code_fix_before and f.code_fix_after:
                content_parts.append(
                    f"[bold red]❌ Vulnerable Code Pattern:[/bold red]\n{f.code_fix_before}\n\n"
                    f"[bold green]✅ Secure Replacement Fix:[/bold green]\n{f.code_fix_after}"
                )

            border_color = "red" if f.severity == Severity.CRITICAL else ("orange3" if f.severity == Severity.HIGH else ("yellow" if f.severity == Severity.MEDIUM else "blue"))
            self.console.print(
                Panel(
                    "\n\n".join(content_parts),
                    title=f"[{sev_style}][{f.severity.value}][/{sev_style}] [bold cyan]{f.id}[/bold cyan] ({idx}/{len(findings)}) — [white]{f.title}[/white]",
                    border_style=border_color,
                    padding=(1, 2),
                )
            )
        self.console.print()

