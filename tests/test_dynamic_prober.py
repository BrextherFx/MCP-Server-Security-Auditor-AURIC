import pytest
import sys
import asyncio
from pathlib import Path
from mcpaudit.dynamic_prober import DynamicProber
from mcpaudit.models import ToolDefinition

def test_probe_input_generation():
    prober = DynamicProber()
    tool = ToolDefinition(
        name="test_tool",
        description="A tool that takes a string and number",
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
                "limit": {"type": "integer"}
            },
            "required": ["file_path"]
        }
    )
    probes = prober.generate_probes_for_tool(tool)
    probe_names = [p[0] for p in probes]
    assert "benign_baseline" in probe_names
    assert "path_traversal_probe" in probe_names
    assert "command_injection_probe" in probe_names

def test_dynamic_probe_clean_server():
    async def run():
        prober = DynamicProber(timeout_seconds=8.0)
        server_path = Path("test_servers/clean_math_server.py")
        tools, findings, traces = await prober.probe_server(sys.executable, [str(server_path)])
        return tools, findings, traces

    tools, findings, traces = asyncio.run(run())
    assert len(tools) == 3
    tool_names = [t.name for t in tools]
    assert "add" in tool_names
    assert "multiply" in tool_names
    assert len(findings) == 0

def test_dynamic_probe_vulnerable_server():
    async def run():
        prober = DynamicProber(timeout_seconds=8.0)
        server_path = Path("test_servers/vulnerable_file_server.py")
        tools, findings, traces = await prober.probe_server(sys.executable, [str(server_path)])
        return tools, findings, traces

    tools, findings, traces = asyncio.run(run())
    assert len(tools) >= 3
    assert len(traces) > 0
