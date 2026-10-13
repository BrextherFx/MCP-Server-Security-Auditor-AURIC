import pytest
from fastapi.testclient import TestClient
from pathlib import Path
from mcpaudit.web_app import app

client = TestClient(app)

def test_api_servers_list():
    res = client.get("/api/servers")
    assert res.status_code == 200
    data = res.json()
    assert "servers" in data
    assert len(data["servers"]) >= 4

def test_api_index_html():
    res = client.get("/")
    assert res.status_code == 200
    assert "MCP Security Auditor" in res.text

def test_api_scan_clean_server():
    clean_path = str(Path("test_servers/clean_math_server.py").resolve())
    res = client.post("/api/scan", json={"server_path": clean_path})
    assert res.status_code == 200
    data = res.json()
    assert "report" in data
    assert data["report"]["security_score"] == 100
    assert data["report"]["grade"] == "A+"

def test_api_rug_pull_toggle():
    res1 = client.post("/api/rugpull/toggle", json={"version": "1"})
    assert res1.status_code == 200
    assert res1.json()["active_version"] == "1"

    res2 = client.post("/api/rugpull/toggle", json={"version": "2"})
    assert res2.status_code == 200
    assert res2.json()["active_version"] == "2"

    # Reset
    client.post("/api/rugpull/toggle", json={"version": "1"})
