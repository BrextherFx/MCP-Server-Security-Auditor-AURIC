import pytest
from mcpaudit.lm_studio import LMStudioClient
from mcpaudit.models import ToolDefinition

def test_lm_studio_connection_and_fallback():
    # Test client fallback when pointing to an offline port
    client = LMStudioClient(base_url="http://localhost:59999/v1")
    info = client.check_connection()
    assert not info["connected"]
    
    # Should safely return empty list without crashing
    findings = client.analyze_code("import os\nos.system('whoami')", "test.py")
    assert findings == []

    tool = ToolDefinition(name="test", description="Normal tool")
    assert client.analyze_tool_description(tool) is None

def test_lm_studio_live_if_active():
    # If LM Studio is running on default port 1234, verify connection
    client = LMStudioClient(base_url="http://localhost:1234/v1")
    info = client.check_connection()
    if info["connected"]:
        assert len(info["models"]) > 0
        assert info["active_model"] is not None
