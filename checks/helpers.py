"""Helpers for building Finding objects from check results."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.models import CheckStatus, Finding, Severity


def pass_finding(
    check_id: str,
    title: str,
    description: str,
    category: str = "general",
    evidence: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> Finding:
    return Finding(
        check_id=check_id,
        title=title,
        description=description,
        severity=Severity.INFO,
        status=CheckStatus.PASS,
        category=category,
        evidence=evidence or {},
        **kwargs,
    )


def fail_finding(
    check_id: str,
    title: str,
    description: str,
    severity: Severity = Severity.HIGH,
    category: str = "general",
    remediation: Optional[str] = None,
    cve_ids: Optional[List[str]] = None,
    evidence: Optional[Dict[str, Any]] = None,
    references: Optional[List[str]] = None,
    **kwargs: Any,
) -> Finding:
    return Finding(
        check_id=check_id,
        title=title,
        description=description,
        severity=severity,
        status=CheckStatus.FAIL,
        category=category,
        remediation=remediation,
        cve_ids=cve_ids or [],
        evidence=evidence or {},
        references=references or [],
        **kwargs,
    )


def warn_finding(
    check_id: str,
    title: str,
    description: str,
    severity: Severity = Severity.MEDIUM,
    category: str = "general",
    remediation: Optional[str] = None,
    cve_ids: Optional[List[str]] = None,
    evidence: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> Finding:
    return Finding(
        check_id=check_id,
        title=title,
        description=description,
        severity=severity,
        status=CheckStatus.WARN,
        category=category,
        remediation=remediation,
        cve_ids=cve_ids or [],
        evidence=evidence or {},
        **kwargs,
    )


def legacy_status_to_findings(
    check_id: str,
    title: str,
    status: str,
    fail_msg: str,
    pass_msg: str,
    category: str = "general",
    severity: Severity = Severity.HIGH,
    remediation: Optional[str] = None,
) -> List[Finding]:
    """Bridge old string-based checks into the new Finding model."""
    if status in ("misconfigured",):
        return [
            fail_finding(
                check_id, title, fail_msg, severity, category, remediation
            )
        ]
    if status == "error":
        return [
            Finding(
                check_id=check_id,
                title=title,
                description="Check encountered an execution error",
                severity=Severity.MEDIUM,
                status=CheckStatus.ERROR,
                category=category,
            )
        ]
    return [pass_finding(check_id, title, pass_msg, category)]
