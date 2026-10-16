# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MCP Security Auditor Contributors

"""
Deterministic Multi-Stage Pipeline Engine for MCP Server Security Auditing.
Implements the 6-stage linear pipeline architecture:
  Stage 1: Ingestion & Syntax Extraction (AST parsing, schema extraction)
  Stage 2: Deterministic Static Rule Filtering (Shell, Deserialization, Secrets, Steganography)
  Stage 3: Subprocess Stdio Isolation & Dynamic Canary Probing (Native MCP JSON-RPC 2.0)
  Stage 4: Cryptographic Merkle Pinning & DeepDiff (Rug-pull mutation detection)
  Stage 5: Remediation Synthesis & CVSS Scoring (Before/After code patches, grade calculation)
  Stage 6: Serialization & Egress (SARIF 2.1.0, HTML, Markdown, JSON, SQLite, AWS S3)
"""

import sys
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field

from mcpaudit.models import (
    ScanReport,
    Finding,
    ToolDefinition,
    Severity,
    Category,
)
from mcpaudit.static_scanner import StaticScanner
from mcpaudit.desc_analyzer import DescriptionAnalyzer
from mcpaudit.dynamic_prober import DynamicProber, ProbeTrace
from mcpaudit.pin_and_diff import PinStore, RugPullDiff
from mcpaudit.report_engine import ReportEngine
from mcpaudit.s3_storage import S3StorageManager
from mcpaudit.lm_studio import LMStudioClient


@dataclass
class PipelineConfig:
    """Configuration parameters for the 6-stage deterministic pipeline."""
    target_path: str
    server_id: Optional[str] = None
    pin_baseline: bool = False
    skip_dynamic: bool = False
    probe_timeout_seconds: float = 8.0
    use_lm_studio: bool = True
    lm_studio_url: str = "http://localhost:1234/v1"
    s3_sync: bool = False
    s3_bucket: Optional[str] = None


@dataclass
class PipelineResult:
    """Consolidated immutable output of the 6-stage deterministic pipeline."""
    report: ScanReport
    traces: List[ProbeTrace] = field(default_factory=list)
    rug_pull_diff: Optional[RugPullDiff] = None
    sqlite_row_id: int = 0
    s3_uri: Optional[str] = None
    sarif_document: Optional[Dict[str, Any]] = None
    execution_stages_passed: List[str] = field(default_factory=list)


class SecurityAuditPipeline:
    """
    Unified 6-Stage Deterministic Pipeline Engine.
    Executes sequentially without vector search, probabilistic RAG, or external database bloat.
    """

    def __init__(self, config: PipelineConfig):
        self.config = config
        self.target_path = Path(config.target_path).resolve()
        self.effective_server_id = config.server_id or self.target_path.stem
        self.report = ScanReport(target=str(self.target_path))
        self.traces: List[ProbeTrace] = []
        self.rug_pull_diff: Optional[RugPullDiff] = None
        self.sqlite_row_id: int = 0
        self.s3_uri: Optional[str] = None
        self.sarif_doc: Optional[Dict[str, Any]] = None
        self.stages_completed: List[str] = []
        self.lm_active = False

    def stage_0_preflight(self) -> None:
        """Preflight connectivity checks and validation."""
        if not self.target_path.exists():
            raise FileNotFoundError(f"Target server path does not exist: {self.target_path}")

        if self.config.use_lm_studio:
            client = LMStudioClient(base_url=self.config.lm_studio_url)
            conn = client.check_connection()
            self.lm_active = conn.get("connected", False)

        self.stages_completed.append("Stage 0: Preflight & Environment Verification")

    def stage_1_and_2_static_scan(self) -> List[Finding]:
        """
        Stage 1 & 2: Ingestion, AST Syntax Traversal, and Deterministic Static Filtering.
        Detects shell execution sinks, unsafe deserialization, hardcoded secrets, and steganography.
        """
        scanner = StaticScanner(
            use_lm_studio=self.lm_active,
            lm_studio_url=self.config.lm_studio_url,
        )
        static_findings = scanner.scan_path(str(self.target_path))
        self.report.findings.extend(static_findings)
        self.stages_completed.append("Stage 1 & 2: AST Extraction & Deterministic Rule Filtering")
        return static_findings

    async def stage_3_dynamic_probing(self) -> List[ToolDefinition]:
        """
        Stage 3: Subprocess Stdio Isolation, MCP Protocol Handshake, and Dynamic Boundary Fuzzing.
        Queries active tools over stdio and executes schema-synthesized boundary payloads.
        """
        discovered_tools: List[ToolDefinition] = []
        if not self.config.skip_dynamic and self.target_path.is_file() and self.target_path.suffix.lower() == ".py":
            prober = DynamicProber(timeout_seconds=self.config.probe_timeout_seconds)
            tools, dyn_findings, traces = await prober.probe_server(
                command=sys.executable,
                args=[str(self.target_path)],
            )
            discovered_tools = tools
            self.traces = traces
            self.report.findings.extend(dyn_findings)
            self.report.tools = discovered_tools
            self.report.tool_count = len(discovered_tools)

            # Analyze tool descriptions for prompt injection and tool poisoning
            desc_analyzer = DescriptionAnalyzer(
                use_lm_studio=self.lm_active,
                lm_studio_url=self.config.lm_studio_url,
            )
            for tool in discovered_tools:
                self.report.findings.extend(desc_analyzer.analyze_tool(tool))

        self.stages_completed.append("Stage 3: Subprocess Protocol Handshake & Dynamic Canary Probing")
        return discovered_tools

    def stage_4_merkle_pin_and_diff(self, tools: List[ToolDefinition]) -> Optional[RugPullDiff]:
        """
        Stage 4: Cryptographic Merkle Pinning and DeepDiff Semantic Differencing.
        Guarantees supply-chain integrity against post-approval rug-pull mutations.
        """
        pin_store = PinStore()
        if self.config.pin_baseline and tools:
            pin_store.pin_server(
                self.effective_server_id,
                tools,
                approved_by="PipelineAdministrator",
                notes="Approved baseline via Deterministic Pipeline",
            )

        diff = pin_store.diff_server(self.effective_server_id, tools)
        self.rug_pull_diff = diff
        if diff.detected:
            self.report.rug_pull_detected = True
            self.report.rug_pull_details = diff
            self.report.findings.extend(diff.findings)

        self.stages_completed.append("Stage 4: Merkle Cryptographic Pinning & DeepDiff")
        return diff

    def stage_5_remediation_and_scoring(self) -> None:
        """
        Stage 5: Remediation Blueprint Mapping, CVSS Penalty Synthesis, and Grade Computation.
        """
        self.report.calculate_score()
        self.stages_completed.append("Stage 5: Remediation Synthesis & CVSS Scoring")

    def stage_6_serialization_and_egress(self) -> None:
        """
        Stage 6: Serialization to OASIS SARIF 2.1.0, SQLite Telemetry Ledger, and AWS S3 Sync.
        """
        pin_store = PinStore()
        engine = ReportEngine()
        self.sarif_doc = engine.generate_sarif(self.report)

        if self.config.s3_sync:
            s3_mgr = S3StorageManager(bucket_name=self.config.s3_bucket)
            s3_mgr.sync_database_to_s3()
            rep_res = s3_mgr.upload_report_to_s3(
                json.dumps(self.sarif_doc, indent=2),
                f"{self.effective_server_id}_audit.sarif",
                self.effective_server_id,
                "application/sarif+json",
            )
            self.s3_uri = rep_res.get("s3_uri")

        self.sqlite_row_id = pin_store.record_scan(
            self.report,
            self.effective_server_id,
            s3_uri=self.s3_uri,
        )
        self.stages_completed.append("Stage 6: Multi-Format Serialization & Cloud Egress")

    async def execute_full_pipeline(self) -> PipelineResult:
        """Executes the complete 6-stage deterministic pipeline sequentially."""
        self.stage_0_preflight()
        self.stage_1_and_2_static_scan()
        tools = await self.stage_3_dynamic_probing()
        self.stage_4_merkle_pin_and_diff(tools)
        self.stage_5_remediation_and_scoring()
        self.stage_6_serialization_and_egress()

        return PipelineResult(
            report=self.report,
            traces=self.traces,
            rug_pull_diff=self.rug_pull_diff,
            sqlite_row_id=self.sqlite_row_id,
            s3_uri=self.s3_uri,
            sarif_document=self.sarif_doc,
            execution_stages_passed=self.stages_completed,
        )
