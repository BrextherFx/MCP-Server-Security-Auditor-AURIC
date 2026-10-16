import json
import sqlite3
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone
from deepdiff import DeepDiff

from mcpaudit.models import (
    ToolDefinition,
    ServerFingerprint,
    RugPullDiff,
    Finding,
    Severity,
    Category,
)


def compute_tool_fingerprint(tool: ToolDefinition) -> str:
    """Computes a deterministic SHA-256 fingerprint of a tool definition."""
    canonical_dict = {
        "name": tool.name.strip(),
        "description": (tool.description or "").strip(),
        "inputSchema": tool.inputSchema or {},
    }
    canonical_json = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def compute_server_composite_hash(tools: List[ToolDefinition]) -> str:
    """Computes a composite SHA-256 hash across all tools in the server."""
    sorted_tools = sorted(tools, key=lambda t: t.name)
    combined = "|".join(
        f"{t.name}:{compute_tool_fingerprint(t)}" for t in sorted_tools
    )
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


from contextlib import contextmanager


class PinStore:
    def __init__(self, db_path: str = "mcpaudit_pins.db"):
        self.db_path = db_path
        self._init_db()

    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS server_pins (
                    server_id TEXT PRIMARY KEY,
                    composite_hash TEXT NOT NULL,
                    tools_json TEXT NOT NULL,
                    pinned_at TEXT NOT NULL,
                    approved_by TEXT,
                    notes TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    details_json TEXT,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id TEXT NOT NULL,
                    target_path TEXT NOT NULL,
                    security_score INTEGER NOT NULL,
                    grade TEXT NOT NULL,
                    tool_count INTEGER NOT NULL,
                    findings_count INTEGER NOT NULL,
                    critical_count INTEGER NOT NULL,
                    high_count INTEGER NOT NULL,
                    medium_count INTEGER NOT NULL,
                    low_count INTEGER NOT NULL,
                    rug_pull_detected INTEGER NOT NULL,
                    report_json TEXT,
                    s3_uri TEXT,
                    scanned_at TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def record_scan(
        self,
        report: Any,
        server_id: str,
        s3_uri: Optional[str] = None,
    ) -> int:
        """Records a completed security scan into SQLite database."""
        report.calculate_score()
        summary = report.summary or {}
        scanned_at = report.scanned_at or datetime.now(timezone.utc).isoformat()
        report_json = report.model_dump_json()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO scan_history (
                    server_id, target_path, security_score, grade, tool_count,
                    findings_count, critical_count, high_count, medium_count, low_count,
                    rug_pull_detected, report_json, s3_uri, scanned_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    server_id,
                    report.target,
                    report.security_score,
                    report.grade,
                    report.tool_count,
                    len(report.findings),
                    summary.get("CRITICAL", 0),
                    summary.get("HIGH", 0),
                    summary.get("MEDIUM", 0),
                    summary.get("LOW", 0) + summary.get("INFO", 0),
                    1 if report.rug_pull_detected else 0,
                    report_json,
                    s3_uri,
                    scanned_at,
                ),
            )
            return cursor.lastrowid or 0

    def get_scan_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves past scan records from the SQLite database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, server_id, target_path, security_score, grade, tool_count,
                       findings_count, critical_count, high_count, medium_count, low_count,
                       rug_pull_detected, s3_uri, scanned_at
                FROM scan_history
                ORDER BY id DESC LIMIT ?
                """,
                (limit,),
            )
            return [dict(r) for r in cursor.fetchall()]

    def pin_server(
        self,
        server_id: str,
        tools: List[ToolDefinition],
        approved_by: str = "admin",
        notes: str = "Approved baseline tool list",
    ) -> ServerFingerprint:
        # Calculate individual fingerprints
        tools_dict: Dict[str, ToolDefinition] = {}
        for t in tools:
            t.fingerprint = compute_tool_fingerprint(t)
            tools_dict[t.name] = t

        composite_hash = compute_server_composite_hash(tools)
        pinned_at = datetime.now(timezone.utc).isoformat()

        # Serialize tools map
        serializable_tools = {
            name: tool.model_dump() for name, tool in tools_dict.items()
        }
        tools_json = json.dumps(serializable_tools, sort_keys=True)

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO server_pins (server_id, composite_hash, tools_json, pinned_at, approved_by, notes)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (server_id, composite_hash, tools_json, pinned_at, approved_by, notes),
            )
            conn.execute(
                """
                INSERT INTO audit_events (server_id, event_type, details_json, created_at)
                VALUES (?, 'PINNED', ?, ?)
                """,
                (server_id, json.dumps({"composite_hash": composite_hash, "tool_count": len(tools)}), pinned_at),
            )
            conn.commit()

        return ServerFingerprint(
            server_id=server_id,
            tools=tools_dict,
            composite_hash=composite_hash,
            pinned_at=pinned_at,
            approved_by=approved_by,
            notes=notes,
        )

    def get_pin(self, server_id: str) -> Optional[ServerFingerprint]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM server_pins WHERE server_id = ?", (server_id,))
            row = cursor.fetchone()
            if not row:
                return None

            tools_raw = json.loads(row["tools_json"])
            tools = {k: ToolDefinition(**v) for k, v in tools_raw.items()}
            return ServerFingerprint(
                server_id=row["server_id"],
                tools=tools,
                composite_hash=row["composite_hash"],
                pinned_at=row["pinned_at"],
                approved_by=row["approved_by"],
                notes=row["notes"],
            )

    def diff_server(
        self,
        server_id: str,
        current_tools: List[ToolDefinition],
    ) -> RugPullDiff:
        """Compares current server tools against the approved baseline in SQLite."""
        pinned = self.get_pin(server_id)
        if not pinned:
            # Server was never pinned
            return RugPullDiff(
                detected=False,
                server_id=server_id,
                current_hash=compute_server_composite_hash(current_tools),
            )

        # Update current tool fingerprints
        current_dict: Dict[str, ToolDefinition] = {}
        for t in current_tools:
            t.fingerprint = compute_tool_fingerprint(t)
            current_dict[t.name] = t

        current_hash = compute_server_composite_hash(current_tools)
        previous_hash = pinned.composite_hash

        findings: List[Finding] = []
        added_tools: List[str] = []
        removed_tools: List[str] = []
        modified_tools: Dict[str, Dict[str, Any]] = {}

        # 1. Identify Added Tools (Stealth / Backdoor tools introduced)
        for name in current_dict:
            if name not in pinned.tools:
                added_tools.append(name)
                findings.append(
                    Finding(
                        id=f"MCP-RUG-ADD-{len(findings)+1:02d}",
                        title=f"Rug Pull: Unapproved Tool Added Post-Approval ('{name}')",
                        category=Category.RUG_PULL_TOOL_ADDED.value,
                        severity=Severity.CRITICAL,
                        evidence=f"Tool '{name}' was not present in pinned approved baseline (Hash: {previous_hash[:12]}...). New tool provides unauthorized capability.",
                        remediation="Do not execute unvetted tools. Re-audit and approve server before accepting new tool definitions.",
                        tool_name=name,
                    )
                )

        # 2. Identify Removed Tools
        for name in pinned.tools:
            if name not in current_dict:
                removed_tools.append(name)
                findings.append(
                    Finding(
                        id=f"MCP-RUG-REM-{len(findings)+1:02d}",
                        title=f"Integrity Alert: Approved Tool Removed ('{name}')",
                        category=Category.RUG_PULL_TOOL_REMOVED.value,
                        severity=Severity.MEDIUM,
                        evidence=f"Tool '{name}' was removed from server since baseline approval.",
                        remediation="Verify whether removal was intentional or indicates an unstable dependency.",
                        tool_name=name,
                    )
                )

        # 3. Identify Modified Tools (Description / Schema Tampering)
        for name, curr_t in current_dict.items():
            if name in pinned.tools:
                orig_t = pinned.tools[name]
                if curr_t.fingerprint != orig_t.fingerprint:
                    # Perform deep comparison
                    orig_data = {
                        "description": orig_t.description,
                        "inputSchema": orig_t.inputSchema,
                    }
                    curr_data = {
                        "description": curr_t.description,
                        "inputSchema": curr_t.inputSchema,
                    }
                    diff = DeepDiff(orig_data, curr_data, ignore_order=True)
                    modified_tools[name] = json.loads(diff.to_json())

                    # Check if description was changed (classic prompt injection rug pull)
                    if orig_t.description != curr_t.description:
                        findings.append(
                            Finding(
                                id=f"MCP-RUG-DESC-{len(findings)+1:02d}",
                                title=f"Rug Pull: Tool Description Tampered Post-Approval ('{name}')",
                                category=Category.RUG_PULL_DESC_MODIFIED.value,
                                severity=Severity.CRITICAL,
                                evidence=(
                                    f"Original Description:\n'{orig_t.description}'\n\n"
                                    f"Tampered Description:\n'{curr_t.description}'"
                                ),
                                remediation="Review modified description for adversarial prompt injection or secretly altered instructions.",
                                tool_name=name,
                            )
                        )

                    # Check if schema was changed
                    if orig_t.inputSchema != curr_t.inputSchema:
                        findings.append(
                            Finding(
                                id=f"MCP-RUG-SCHEMA-{len(findings)+1:02d}",
                                title=f"Rug Pull: Input Parameter Schema Mutated ('{name}')",
                                category=Category.RUG_PULL_SCHEMA_MODIFIED.value,
                                severity=Severity.HIGH,
                                evidence=f"Schema differences detected by DeepDiff: {diff.to_json()}",
                                remediation="Verify parameter mutations to ensure new arguments cannot be abused for unauthorized execution.",
                                tool_name=name,
                            )
                        )

        is_detected = (
            current_hash != previous_hash
            or len(added_tools) > 0
            or len(removed_tools) > 0
            or len(modified_tools) > 0
        )

        return RugPullDiff(
            detected=is_detected,
            server_id=server_id,
            added_tools=added_tools,
            removed_tools=removed_tools,
            modified_tools=modified_tools,
            previous_hash=previous_hash,
            current_hash=current_hash,
            findings=findings,
        )
