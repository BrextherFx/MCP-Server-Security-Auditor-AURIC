import pytest
import os
import sys
import json
import asyncio
from pathlib import Path
from mcpaudit.static_scanner import StaticScanner
from mcpaudit.desc_analyzer import DescriptionAnalyzer
from mcpaudit.dynamic_prober import DynamicProber
from mcpaudit.pin_and_diff import PinStore
from mcpaudit.report_engine import ReportEngine
from mcpaudit.models import ScanReport, Severity

def test_end_to_end_audit_flow(tmp_path):
    async def run():
        # 1. Clean Server Scan
        clean_path = Path("test_servers/clean_math_server.py")
        report1 = ScanReport(target=str(clean_path))
        
        scanner = StaticScanner()
        report1.findings.extend(scanner.scan_path(str(clean_path)))
        
        prober = DynamicProber(timeout_seconds=8.0)
        tools, dyn_findings, _ = await prober.probe_server(sys.executable, [str(clean_path)])
        report1.findings.extend(dyn_findings)
        report1.tools = tools
        report1.tool_count = len(tools)
        
        desc_analyzer = DescriptionAnalyzer()
        for t in tools:
            report1.findings.extend(desc_analyzer.analyze_tool(t))
            
        report1.calculate_score()
        return report1

    report1 = asyncio.run(run())
    assert report1.security_score == 100
    assert report1.grade == "A+"
    assert len(report1.findings) == 0

    # 2. Report Generation Verification
    engine = ReportEngine()
    md = engine.generate_markdown(report1)
    sarif = engine.generate_sarif(report1)
    
    assert "MCP Server Security Audit Report" in md
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "MCPServerSecurityAuditor"

    # Save to temp files
    md_file = tmp_path / "report.md"
    sarif_file = tmp_path / "report.sarif"
    json_file = tmp_path / "report.json"
    engine.save_reports(report1, markdown_path=str(md_file), sarif_path=str(sarif_file), json_path=str(json_file))
    
    assert md_file.exists()
    assert sarif_file.exists()
    assert json_file.exists()
