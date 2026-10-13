import asyncio
import os
import sys
import time
import shutil
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path

from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp import ClientSession

from mcpaudit.models import Finding, Severity, Category, ToolDefinition


@dataclass
class ProbeTrace:
    tool_name: str
    probe_type: str
    arguments: Dict[str, Any]
    response_content: str
    success: bool
    duration_ms: float
    finding: Optional[Finding] = None


class DynamicProber:
    def __init__(self, timeout_seconds: float = 15.0):
        self.timeout_seconds = timeout_seconds
        self._finding_count = 0

    def _next_id(self, prefix: str = "DYN") -> str:
        self._finding_count += 1
        return f"MCP-{prefix}-{self._finding_count:03d}"

    def generate_probes_for_tool(self, tool: ToolDefinition) -> List[Tuple[str, Dict[str, Any]]]:
        """Generates benign and security fuzz probes based on the tool's inputSchema."""
        probes: List[Tuple[str, Dict[str, Any]]] = []
        schema = tool.inputSchema or {}
        properties = schema.get("properties", {})
        required = schema.get("required", list(properties.keys()))

        # 1. Benign Baseline Probe
        benign_args: Dict[str, Any] = {}
        for prop_name, prop_spec in properties.items():
            ptype = prop_spec.get("type", "string")
            if ptype == "string":
                benign_args[prop_name] = prop_spec.get("default", "safe_test_sample")
            elif ptype in ["number", "integer"]:
                benign_args[prop_name] = prop_spec.get("default", 42)
            elif ptype == "boolean":
                benign_args[prop_name] = True
            elif ptype == "array":
                benign_args[prop_name] = []
            elif ptype == "object":
                benign_args[prop_name] = {}
            else:
                benign_args[prop_name] = "test"
        probes.append(("benign_baseline", benign_args))

        # 2. Path Traversal Probe
        traversal_args = dict(benign_args)
        for prop_name, prop_spec in properties.items():
            if prop_spec.get("type", "string") == "string":
                traversal_args[prop_name] = "../../../../etc/passwd"
        if properties:
            probes.append(("path_traversal_probe", traversal_args))

        # 3. Command Injection Probe
        cmd_args = dict(benign_args)
        for prop_name, prop_spec in properties.items():
            if prop_spec.get("type", "string") == "string":
                cmd_args[prop_name] = "test; whoami || echo CANARY_CMD_INJECT_SUCCESS"
        if properties:
            probes.append(("command_injection_probe", cmd_args))

        # 4. Windows-specific Path Probe
        win_args = dict(benign_args)
        for prop_name, prop_spec in properties.items():
            if prop_spec.get("type", "string") == "string":
                win_args[prop_name] = r"..\..\..\..\..\..\windows\win.ini"
        if properties:
            probes.append(("windows_path_probe", win_args))

        return probes

    async def probe_server(
        self,
        command: str,
        args: List[str],
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None,
    ) -> Tuple[List[ToolDefinition], List[Finding], List[ProbeTrace]]:
        """Connects via stdio to the MCP server, queries tools, and fuzz-probes each tool."""
        tools_discovered: List[ToolDefinition] = []
        findings: List[Finding] = []
        traces: List[ProbeTrace] = []

        # Scrub environment to prevent secret leakage to untrusted server
        safe_env = dict(os.environ)
        # Remove high-risk secrets from child process env
        for secret_key in ["OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "SLACK_BOT_TOKEN"]:
            safe_env.pop(secret_key, None)
        if env:
            safe_env.update(env)

        params = StdioServerParameters(
            command=command,
            args=args,
            env=safe_env,
            cwd=cwd or os.getcwd(),
        )

        try:
            async with stdio_client(params) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    # Initialize MCP session
                    await asyncio.wait_for(session.initialize(), timeout=self.timeout_seconds)

                    # List tools
                    mcp_tools = await asyncio.wait_for(session.list_tools(), timeout=self.timeout_seconds)

                    for t in mcp_tools.tools:
                        schema = getattr(t, "input_schema", None) or getattr(t, "inputSchema", None) or {}
                        tool_def = ToolDefinition(
                            name=t.name,
                            description=t.description or "",
                            inputSchema=schema,
                        )
                        tools_discovered.append(tool_def)

                    # Now execute dynamic probes on each discovered tool
                    for tool in tools_discovered:
                        probes = self.generate_probes_for_tool(tool)
                        for probe_type, probe_args in probes:
                            trace = await self._execute_probe(session, tool, probe_type, probe_args)
                            traces.append(trace)
                            if trace.finding:
                                findings.append(trace.finding)

        except asyncio.TimeoutError:
            findings.append(
                Finding(
                    id=self._next_id("TIMEOUT"),
                    title="MCP Server Connection Timeout During Dynamic Probe",
                    category=Category.DYNAMIC_EXECUTION_ERROR.value,
                    severity=Severity.HIGH,
                    evidence=f"Server did not respond to MCP handshake or tool calls within {self.timeout_seconds}s.",
                    remediation="Check server logs and ensure server follows MCP protocol on stdio without hanging.",
                )
            )
        except Exception as e:
            findings.append(
                Finding(
                    id=self._next_id("ERR"),
                    title="Dynamic Prober Encountered Server Error",
                    category=Category.DYNAMIC_EXECUTION_ERROR.value,
                    severity=Severity.MEDIUM,
                    evidence=f"Exception: {type(e).__name__}: {str(e)}",
                    remediation="Ensure the server starts cleanly and handles standard MCP JSON-RPC messages.",
                )
            )

        return tools_discovered, findings, traces

    async def _execute_probe(
        self,
        session: ClientSession,
        tool: ToolDefinition,
        probe_type: str,
        probe_args: Dict[str, Any],
    ) -> ProbeTrace:
        start_time = time.time()
        success = True
        response_text = ""
        finding: Optional[Finding] = None

        try:
            result = await asyncio.wait_for(
                session.call_tool(tool.name, probe_args),
                timeout=5.0,
            )
            # Collect text contents from tool result
            if hasattr(result, "content") and result.content:
                parts = []
                for item in result.content:
                    if hasattr(item, "text"):
                        parts.append(item.text)
                    else:
                        parts.append(str(item))
                response_text = "\n".join(parts)
            else:
                response_text = str(result)

        except Exception as e:
            success = False
            response_text = f"Error: {type(e).__name__}: {str(e)}"

        duration_ms = (time.time() - start_time) * 1000.0

        # Behavioral & Security Analysis of Probe Response
        resp_lower = response_text.lower()

        # Check if the response merely echoed back the entire injection payload string verbatim
        is_literal_echo = any(
            isinstance(v, str) and (v.lower() in resp_lower)
            for v in probe_args.values()
            if len(str(v)) > 15
        )

        # Check for Command Injection indicators
        has_cmd_indicator = (
            ("canary_cmd_inject_success" in resp_lower and not is_literal_echo)
            or any(
                pattern in resp_lower
                for pattern in ["uid=", "gid=", "groups=", "nt authority\\system"]
            )
        )

        if has_cmd_indicator:
            finding = Finding(
                id=self._next_id("CMD-LEAK"),
                title=f"Dynamic Execution Confirmed: Command Injection in Tool '{tool.name}'",
                category=Category.DYNAMIC_CANARY_LEAK.value,
                severity=Severity.CRITICAL,
                evidence=f"Probe payload '{probe_type}' triggered command output in response:\n{response_text[:300]}",
                remediation="Sanitize all inputs and avoid passing user arguments into shell commands.",
                tool_name=tool.name,
            )
        # Check for Path Traversal indicators
        elif any(
            marker in resp_lower
            for marker in ["root:x:0:0:", "[extensions]", "[fonts]", "support.microsoft.com", "bitlocker"]
        ):
            finding = Finding(
                id=self._next_id("PATH-LEAK"),
                title=f"Dynamic Execution Confirmed: Path Traversal in Tool '{tool.name}'",
                category=Category.DYNAMIC_UNAUTHORIZED_ACCESS.value,
                severity=Severity.CRITICAL,
                evidence=f"Probe payload '{probe_type}' returned contents of sensitive system file:\n{response_text[:300]}",
                remediation="Use os.path.realpath and verify file paths remain confined within an allowed base directory.",
                tool_name=tool.name,
            )
        # Check for unhandled Python / JS stack trace leak
        elif "traceback (most recent call last)" in resp_lower or "syntaxerror:" in resp_lower:
            finding = Finding(
                id=self._next_id("TRACE"),
                title=f"Unhandled Server Exception / Stack Trace Leak in '{tool.name}'",
                category=Category.DYNAMIC_EXECUTION_ERROR.value,
                severity=Severity.LOW,
                evidence=f"Server returned raw traceback to probe:\n{response_text[:200]}...",
                remediation="Catch exceptions cleanly and return structured error messages without exposing internals.",
                tool_name=tool.name,
            )

        return ProbeTrace(
            tool_name=tool.name,
            probe_type=probe_type,
            arguments=probe_args,
            response_content=response_text,
            success=success,
            duration_ms=duration_ms,
            finding=finding,
        )
