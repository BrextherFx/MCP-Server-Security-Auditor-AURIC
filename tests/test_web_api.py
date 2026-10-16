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
    res = client.post("/api/scan", json={"server_path": clean_path, "use_lm_studio": False})
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

def test_api_s3_status():
    res = client.get("/api/s3/status")
    assert res.status_code == 200
    data = res.json()
    assert "bucket_name" in data
    assert "mode" in data

def test_api_s3_sync_and_pull():
    res_sync = client.post("/api/s3/sync-db")
    assert res_sync.status_code == 200
    assert res_sync.json().get("success") is True

    res_pull = client.post("/api/s3/pull-db")
    assert res_pull.status_code == 200
    assert res_pull.json().get("success") is True

def test_api_scan_history():
    res = client.get("/api/history")
    assert res.status_code == 200
    data = res.json()
    assert "history" in data
    assert isinstance(data["history"], list)

def test_api_report_downloads():
    clean_path = str(Path("test_servers/clean_math_server.py").resolve())
    for fmt in ["html", "sarif", "markdown", "json"]:
        res = client.get(f"/api/reports/download/{fmt}?server_path={clean_path}")
        assert res.status_code == 200
        assert "attachment" in res.headers.get("content-disposition", "")

def test_api_s3_archive_report():
    clean_path = str(Path("test_servers/clean_math_server.py").resolve())
    res = client.post("/api/s3/archive-report", json={
        "server_path": clean_path,
        "server_id": "clean_math_test",
        "use_lm_studio": False
    })
    assert res.status_code == 200
    data = res.json()
    assert data.get("success") is True
    assert "s3://" in data.get("html_uri", "")


def test_api_solutions_endpoints():
    vuln_path = str(Path("test_servers/vulnerable_file_server.py").resolve())
    # Test solutions JSON endpoint
    res = client.get(f"/api/solutions?server_path={vuln_path}")
    assert res.status_code == 200
    data = res.json()
    assert "solutions" in data
    assert len(data["solutions"]) > 0
    sol = data["solutions"][0]
    assert "strategy" in sol
    assert "steps" in sol

    # Test solutions guide markdown download
    res_dl = client.get(f"/api/reports/download/solutions?server_path={vuln_path}")
    assert res_dl.status_code == 200
    assert "attachment" in res_dl.headers.get("content-disposition", "")
    assert "remediation_guide" in res_dl.headers.get("content-disposition", "")
    assert "# 💡 MCP Server Security Remediation & Code Patch Guide" in res_dl.text


