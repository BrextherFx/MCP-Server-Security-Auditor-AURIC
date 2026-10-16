import pytest
import os
import sqlite3
from pathlib import Path
from mcpaudit.s3_storage import S3StorageManager
from mcpaudit.pin_and_diff import PinStore
from mcpaudit.models import Finding, Severity, Category, ScanReport, ToolDefinition

@pytest.fixture
def temp_s3_dir(tmp_path):
    storage_dir = tmp_path / "mock_s3"
    return storage_dir

def test_s3_manager_initialization(temp_s3_dir):
    mgr = S3StorageManager(bucket_name="test-mcp-bucket", local_mock_dir=str(temp_s3_dir))
    status = mgr.get_status()
    assert status["bucket_name"] == "test-mcp-bucket"
    assert status["mode"] == "Local S3 Bucket Simulation"
    assert status["is_live_aws"] is False

def test_s3_sync_and_restore_sqlite(temp_s3_dir, tmp_path):
    db_file = tmp_path / "test_pins.db"
    store = PinStore(db_path=str(db_file))
    
    # Insert a dummy pin
    tool = ToolDefinition(
        name="test_tool",
        description="A test tool",
        inputSchema={"type": "object"},
    )
    store.pin_server("srv_1", [tool], notes="Approved unit test")
    
    mgr = S3StorageManager(
        bucket_name="test-mcp-bucket",
        local_mock_dir=str(temp_s3_dir),
    )
    
    # Sync to S3
    sync_res = mgr.sync_database_to_s3(local_db_path=str(db_file))
    assert sync_res["success"] is True
    assert "s3_uri" in sync_res
    assert "s3://test-mcp-bucket/databases/" in sync_res["s3_uri"]
    
    # Modify local DB or remove it
    db_file.unlink()
    assert not db_file.exists()
    
    # Restore from S3
    restore_res = mgr.restore_database_from_s3(local_db_path=str(db_file))
    assert restore_res["success"] is True
    assert db_file.exists()
    
    # Verify contents restored
    restored_store = PinStore(db_path=str(db_file))
    pinned = restored_store.get_pin("srv_1")
    assert pinned is not None
    assert "test_tool" in pinned.tools
    assert pinned.tools["test_tool"].name == "test_tool"

def test_s3_report_archival(temp_s3_dir):
    mgr = S3StorageManager(
        bucket_name="test-reports-bucket",
        local_mock_dir=str(temp_s3_dir),
    )
    
    sample_md = "# MCP Security Audit Report\nScore: 95/100"
    up_res = mgr.upload_report_to_s3(
        content=sample_md,
        filename="audit_report.md",
        server_id="clean_math_server",
        content_type="text/markdown",
    )
    
    assert up_res["success"] is True
    assert "s3://test-reports-bucket/reports/clean_math_server/" in up_res["s3_uri"]
    
    reports = mgr.list_archived_reports()
    assert len(reports) >= 1
    assert any("clean_math_server" in r["key"] for r in reports)

def test_pin_store_scan_history(tmp_path):
    db_file = tmp_path / "test_history.db"
    store = PinStore(db_path=str(db_file))
    
    report = ScanReport(
        target="server.py",
        tool_count=3,
        findings=[
            Finding(
                id="SEC-001",
                title="Command Injection",
                severity=Severity.CRITICAL,
                category=Category.STATIC_COMMAND_INJECTION.value,
                evidence="os.system()",
                remediation="Use subprocess.run without shell=True",
            )
        ],
        rug_pull_detected=True,
    )
    report.calculate_score()
    
    scan_id = store.record_scan(report=report, server_id="test_server", s3_uri="s3://test-bucket/reports/audit.json")
    assert scan_id > 0
    
    history = store.get_scan_history(limit=10)
    assert len(history) == 1
    assert history[0]["server_id"] == "test_server"
    assert history[0]["target_path"] == "server.py"
    assert history[0]["critical_count"] == 1
    assert history[0]["rug_pull_detected"] == 1
    assert history[0]["s3_uri"] == "s3://test-bucket/reports/audit.json"
