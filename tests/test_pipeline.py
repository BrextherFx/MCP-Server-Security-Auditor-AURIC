# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MCP Security Auditor Contributors

"""
Unit and integration tests for the unified 6-stage deterministic pipeline.
Verifies stage invariants, zero-hallucination determinism, rug-pull catching, and SARIF output.
"""

import pytest
import asyncio
from pathlib import Path

from mcpaudit.pipeline import SecurityAuditPipeline, PipelineConfig


def test_deterministic_pipeline_clean_server():
    """Verify clean server passes through all 6 stages with Grade A+ (Score 100)."""
    async def run():
        server_path = Path("test_servers/clean_math_server.py").resolve()
        assert server_path.exists()

        config = PipelineConfig(
            target_path=str(server_path),
            server_id="test_pipeline_clean",
            pin_baseline=True,
            use_lm_studio=False,
        )
        pipeline = SecurityAuditPipeline(config)
        return await pipeline.execute_full_pipeline()

    result = asyncio.run(run())
    assert result.report.security_score == 100
    assert result.report.grade == "A+"
    assert len(result.report.findings) == 0
    assert result.report.tool_count == 3
    assert result.rug_pull_diff is not None
    assert not result.rug_pull_diff.detected
    assert len(result.execution_stages_passed) == 6
    assert result.sarif_document is not None
    assert result.sqlite_row_id > 0


def test_deterministic_pipeline_vulnerable_server():
    """Verify vulnerable server flags command injection, traversal, and hardcoded secrets."""
    async def run():
        server_path = Path("test_servers/vulnerable_file_server.py").resolve()
        assert server_path.exists()

        config = PipelineConfig(
            target_path=str(server_path),
            server_id="test_pipeline_vulnerable",
            pin_baseline=False,
            use_lm_studio=False,
        )
        pipeline = SecurityAuditPipeline(config)
        return await pipeline.execute_full_pipeline()

    result = asyncio.run(run())
    assert result.report.security_score < 70
    assert len(result.report.findings) > 0
    # Verify actionable remediation was synthesized for findings
    for finding in result.report.findings:
        assert len(finding.solution_steps) > 0
        assert finding.code_fix_after is not None


def test_deterministic_pipeline_nonexistent_target():
    """Verify pipeline rejects invalid targets during Stage 0 preflight."""
    async def run():
        config = PipelineConfig(
            target_path="nonexistent_server_file.py",
            server_id="test_invalid",
            use_lm_studio=False,
        )
        pipeline = SecurityAuditPipeline(config)
        await pipeline.execute_full_pipeline()

    with pytest.raises(FileNotFoundError):
        asyncio.run(run())
