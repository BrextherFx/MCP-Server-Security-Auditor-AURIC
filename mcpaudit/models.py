from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Category(str, Enum):
    # Static Analysis
    STATIC_COMMAND_INJECTION = "Static: Command Injection"
    STATIC_UNSAFE_DESERIALIZATION = "Static: Unsafe Deserialization"
    STATIC_HARDCODED_SECRET = "Static: Hardcoded Secret"
    STATIC_SENSITIVE_FILE_ACCESS = "Static: Sensitive File Access"
    STATIC_SUSPICIOUS_NETWORK = "Static: Suspicious Network Access"
    
    # Description / Prompt Injection Analysis
    DESC_PROMPT_INJECTION = "Description: Prompt Injection"
    DESC_SYSTEM_OVERRIDE = "Description: System Override / Jailbreak"
    DESC_DATA_EXFILTRATION = "Description: Exfiltration Directive"
    DESC_AGENT_STEERING = "Description: Agent Steering / Hidden Instruction"
    DESC_STEGANOGRAPHY = "Description: Hidden Characters / Delimiters"
    
    # Dynamic Probing
    DYNAMIC_EXECUTION_ERROR = "Dynamic: Server Fault / Crash"
    DYNAMIC_UNAUTHORIZED_ACCESS = "Dynamic: Unauthorized Access"
    DYNAMIC_BEHAVIOR_MISMATCH = "Dynamic: Behavior Mismatch"
    DYNAMIC_CANARY_LEAK = "Dynamic: Information Leak / Canary Triggered"
    
    # Rug Pull / Pin-and-Diff
    RUG_PULL_TOOL_ADDED = "Integrity: Unapproved Tool Added"
    RUG_PULL_TOOL_REMOVED = "Integrity: Approved Tool Removed"
    RUG_PULL_DESC_MODIFIED = "Integrity: Tool Description Tampered"
    RUG_PULL_SCHEMA_MODIFIED = "Integrity: Tool Parameter Schema Mutated"
    RUG_PULL_HASH_MISMATCH = "Integrity: Fingerprint Mismatch"


class Finding(BaseModel):
    id: str
    title: str
    category: str
    severity: Severity
    evidence: str
    remediation: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    tool_name: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_sarif_result(self) -> Dict[str, Any]:
        sarif_level = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "none",
        }.get(self.severity, "warning")

        location = {}
        if self.file_path:
            physical_loc = {
                "artifactLocation": {"uri": self.file_path.replace("\\", "/")}
            }
            if self.line_number:
                physical_loc["region"] = {"startLine": self.line_number}
            location = {"physicalLocation": physical_loc}

        return {
            "ruleId": self.id,
            "level": sarif_level,
            "message": {
                "text": f"{self.title}\n\nEvidence: {self.evidence}\n\nRemediation: {self.remediation}"
            },
            "locations": [location] if location else [],
            "properties": {
                "category": self.category,
                "tool_name": self.tool_name,
                "severity": self.severity.value,
            },
        }


class ToolDefinition(BaseModel):
    name: str
    description: Optional[str] = ""
    inputSchema: Dict[str, Any] = Field(default_factory=dict)
    fingerprint: str = ""


class ServerFingerprint(BaseModel):
    server_id: str
    tools: Dict[str, ToolDefinition] = Field(default_factory=dict)
    composite_hash: str = ""
    pinned_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    approved_by: Optional[str] = "admin"
    notes: Optional[str] = "Baseline approved state"


class RugPullDiff(BaseModel):
    detected: bool = False
    server_id: str
    added_tools: List[str] = Field(default_factory=list)
    removed_tools: List[str] = Field(default_factory=list)
    modified_tools: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    previous_hash: Optional[str] = None
    current_hash: Optional[str] = None
    findings: List[Finding] = Field(default_factory=list)


class ScanReport(BaseModel):
    target: str
    scanned_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings: List[Finding] = Field(default_factory=list)
    tool_count: int = 0
    tools: List[ToolDefinition] = Field(default_factory=list)
    security_score: int = 100
    grade: str = "A+"
    summary: Dict[str, int] = Field(default_factory=dict)
    rug_pull_detected: bool = False
    rug_pull_details: Optional[RugPullDiff] = None

    def calculate_score(self):
        # Penalty weights
        penalties = {
            Severity.CRITICAL: 35,
            Severity.HIGH: 20,
            Severity.MEDIUM: 10,
            Severity.LOW: 5,
            Severity.INFO: 0,
        }
        total_deduction = sum(penalties.get(f.severity, 0) for f in self.findings)
        self.security_score = max(0, 100 - total_deduction)

        if self.rug_pull_detected:
            # Rug pull is an immediate integrity breach
            self.security_score = min(self.security_score, 20)

        if self.security_score >= 90:
            self.grade = "A" if self.security_score < 95 else "A+"
        elif self.security_score >= 80:
            self.grade = "B"
        elif self.security_score >= 65:
            self.grade = "C"
        elif self.security_score >= 50:
            self.grade = "D"
        else:
            self.grade = "F"

        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        self.summary = counts
