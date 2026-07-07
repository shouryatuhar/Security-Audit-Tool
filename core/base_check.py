"""Abstract base class for all audit checks."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional

from core.models import Finding


class BaseCheck(ABC):
    """
    Every audit module inherits from BaseCheck.

    Why: Single Responsibility — each subclass owns one security domain
    (SSH, firewall, etc.). The engine only knows about BaseCheck, not
    platform specifics. Interview question: "How do you extend a plugin
    architecture without modifying the orchestrator?" — Open/Closed Principle.
    """

    check_id: str = "base"
    title: str = "Base Check"
    category: str = "general"
    supported_platforms: tuple = ("linux", "darwin", "windows")

    @abstractmethod
    def run(self) -> List[Finding]:
        """Execute the check and return zero or more findings."""

    def is_supported(self, platform: str) -> bool:
        return platform in self.supported_platforms

    def skip_finding(self, reason: str) -> Finding:
        from core.models import CheckStatus, Severity

        return Finding(
            check_id=self.check_id,
            title=self.title,
            description=reason,
            severity=Severity.INFO,
            status=CheckStatus.SKIP,
            category=self.category,
        )

    def error_finding(self, error: str) -> Finding:
        from core.models import CheckStatus, Severity

        return Finding(
            check_id=self.check_id,
            title=self.title,
            description=f"Check failed to execute: {error}",
            severity=Severity.MEDIUM,
            status=CheckStatus.ERROR,
            category=self.category,
        )
