"""Domain models for audit findings and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Finding severity aligned with CVSS-style triage."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CheckStatus(str, Enum):
    """Outcome of an individual security check."""

    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    ERROR = "error"
    SKIP = "skip"


# Weight used when computing the 0–100 security score.
SEVERITY_WEIGHTS: Dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}


@dataclass
class Finding:
    """A single security finding produced by an audit check.

    Enterprise-grade metadata fields follow Nessus/Lynis conventions:
    each finding carries its own detection context, CVSS scoring,
    technical narrative, and actionable remediation.
    """

    check_id: str
    title: str
    description: str
    severity: Severity
    status: CheckStatus
    category: str = "general"
    remediation: Optional[str] = None
    cve_ids: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    references: List[str] = field(default_factory=list)

    # --- Enterprise enrichment fields ---
    detection_command: Optional[str] = None
    confidence: Optional[str] = None          # "high", "medium", "low"
    cvss_score: Optional[float] = None        # 0.0–10.0 (CVSS 3.1 base)
    cvss_vector: Optional[str] = None         # e.g. "CVSS:3.1/AV:N/AC:L/..."
    affected_asset: Optional[str] = None      # process, service, file, or config
    pid: Optional[int] = None                 # process ID if applicable
    listening_interface: Optional[str] = None  # e.g. "0.0.0.0:22"
    timestamp: Optional[str] = None           # ISO 8601 detection time
    technical_detail: Optional[str] = None    # multi-sentence technical explanation
    business_impact: Optional[str] = None     # plain-language risk statement
    remediation_steps: List[str] = field(default_factory=list)  # ordered fix steps
    verification_command: Optional[str] = None  # command to verify the fix

    @property
    def is_finding(self) -> bool:
        return self.status in (CheckStatus.FAIL, CheckStatus.WARN)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "check_id": self.check_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "status": self.status.value,
            "category": self.category,
            "remediation": self.remediation,
            "cve_ids": self.cve_ids,
            "evidence": self.evidence,
            "references": self.references,
        }
        # Include enrichment fields only when populated (keeps JSON clean)
        _optional = {
            "detection_command": self.detection_command,
            "confidence": self.confidence,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "affected_asset": self.affected_asset,
            "pid": self.pid,
            "listening_interface": self.listening_interface,
            "timestamp": self.timestamp,
            "technical_detail": self.technical_detail,
            "business_impact": self.business_impact,
            "remediation_steps": self.remediation_steps if self.remediation_steps else None,
            "verification_command": self.verification_command,
        }
        for key, val in _optional.items():
            if val is not None:
                d[key] = val
        return d


@dataclass
class AuditReport:
    """Complete audit output for a host."""

    hostname: str
    platform: str
    platform_version: str
    findings: List[Finding]
    score: int
    started_at: str
    completed_at: str
    checks_run: int = 0
    checks_failed: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def empty(cls, hostname: str, platform: str, platform_version: str) -> AuditReport:
        now = datetime.now(timezone.utc).isoformat()
        return cls(
            hostname=hostname,
            platform=platform,
            platform_version=platform_version,
            findings=[],
            score=100,
            started_at=now,
            completed_at=now,
        )

    @property
    def failed_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.status == CheckStatus.FAIL]

    @property
    def warn_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.status == CheckStatus.WARN]

    def summary_by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {s.value: 0 for s in Severity}
        for finding in self.findings:
            if finding.is_finding:
                counts[finding.severity.value] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "product": "HostSentinel",
            "hostname": self.hostname,
            "platform": self.platform,
            "platform_version": self.platform_version,
            "score": self.score,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "checks_run": self.checks_run,
            "checks_failed": self.checks_failed,
            "summary": self.summary_by_severity(),
            "findings": [f.to_dict() for f in self.findings],
            "metadata": self.metadata,
        }
