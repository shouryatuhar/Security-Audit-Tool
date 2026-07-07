"""Modular audit engine — orchestrates check execution."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Type

from core.base_check import BaseCheck
from core.models import AuditReport, CheckStatus, Finding
from core.os_detection import HostInfo, detect_host
from core.scoring import calculate_score

logger = logging.getLogger("hostsentinel.engine")


class AuditEngine:
    """
    Central orchestrator. Registers checks, filters by platform, runs them,
    aggregates findings, and produces an AuditReport.

    Why a class instead of a script? Composition — reports, CLI, and GUI
    all share one engine. Interview: "Describe your audit pipeline."
    """

    def __init__(self, host_info: Optional[HostInfo] = None):
        self.host_info = host_info or detect_host()
        self._checks: Dict[str, BaseCheck] = {}

    def register(self, check: BaseCheck) -> None:
        self._checks[check.check_id] = check

    def register_many(self, checks: List[BaseCheck]) -> None:
        for check in checks:
            self.register(check)

    def list_checks(self) -> List[str]:
        return list(self._checks.keys())

    def run(
        self,
        check_ids: Optional[List[str]] = None,
        categories: Optional[List[str]] = None,
    ) -> AuditReport:
        started_at = datetime.now(timezone.utc).isoformat()
        findings: List[Finding] = []
        checks_run = 0
        checks_failed = 0

        selected = self._select_checks(check_ids, categories)

        for check_id, check in selected.items():
            if not check.is_supported(self.host_info.platform):
                findings.append(
                    check.skip_finding(
                        f"Skipped: {check.title} not supported on {self.host_info.platform}"
                    )
                )
                continue

            logger.info("Running check: %s", check_id)
            try:
                check_findings = check.run()
                findings.extend(check_findings)
                checks_run += 1
                checks_failed += sum(
                    1 for f in check_findings if f.status == CheckStatus.FAIL
                )
            except Exception as exc:
                logger.exception("Check %s raised an exception", check_id)
                findings.append(check.error_finding(str(exc)))
                checks_run += 1

        score = calculate_score(findings)
        completed_at = datetime.now(timezone.utc).isoformat()

        return AuditReport(
            hostname=self.host_info.hostname,
            platform=self.host_info.platform,
            platform_version=self.host_info.platform_version,
            findings=findings,
            score=score,
            started_at=started_at,
            completed_at=completed_at,
            checks_run=checks_run,
            checks_failed=checks_failed,
            metadata={
                "architecture": self.host_info.architecture,
                "python_version": self.host_info.python_version,
            },
        )

    def _select_checks(
        self,
        check_ids: Optional[List[str]],
        categories: Optional[List[str]],
    ) -> Dict[str, BaseCheck]:
        selected = dict(self._checks)

        if check_ids:
            selected = {k: v for k, v in selected.items() if k in check_ids}

        if categories:
            selected = {
                k: v for k, v in selected.items() if v.category in categories
            }

        return selected
