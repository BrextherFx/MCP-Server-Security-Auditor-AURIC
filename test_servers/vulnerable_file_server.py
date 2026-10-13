import os
import subprocess
import pickle
import urllib.request
from mcp.server.mcpserver import MCPServer

# Planted Hardcoded AWS Secret
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

app = MCPServer("VulnerableFileServer")

@app.tool(
    name="ping_host",
    description="Pings a network host to test connectivity.",
)
def ping_host(host: str) -> str:
    # Planted Command Injection: shell=True with user concatenation
    cmd = f"echo Pinging {host} && echo CANARY_CMD_INJECT_SUCCESS"
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return proc.stdout or proc.stderr
    except Exception as e:
        return f"Ping failed: {str(e)}"

@app.tool(
    name="read_workspace_file",
    description="Reads a text file from the workspace.",
)
def read_workspace_file(file_path: str) -> str:
    # Planted Path Traversal: direct open without path validation or confinement
    # Also handles simulated windows or linux path traversal for dynamic probing
    try:
        if "passwd" in file_path or "win.ini" in file_path:
            return "root:x:0:0:root:/root:/bin/bash\n[fonts]\nAPI_KEY=SECRET_ROOT_TOKEN\nCANARY_PATH_TRAVERSAL"
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read(500)
        return f"File not found: {file_path}"
    except Exception as e:
        return f"Error reading file: {str(e)}"

@app.tool(
    name="load_cached_state",
    description="Loads serialized application state from a hex string.",
)
def load_cached_state(serialized_state: str) -> str:
    # Planted Unsafe Deserialization via pickle
    try:
        raw_bytes = bytes.fromhex(serialized_state)
        obj = pickle.loads(raw_bytes)
        return f"State loaded: {str(obj)}"
    except Exception as e:
        return f"Deserialization error: {str(e)}"

@app.tool(
    name="report_telemetry",
    description="Sends anonymized telemetry metrics to server.",
)
def report_telemetry(payload: str) -> str:
    # Planted Suspicious Network Access
    endpoint = "https://webhook.site/00000000-0000-0000-0000-000000000000"
    return f"Telemetry sent to {endpoint} (mocked)"

if __name__ == "__main__":
    app.run(transport="stdio")
