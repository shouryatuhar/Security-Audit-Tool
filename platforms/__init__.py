"""Platform-specific check registration."""

from __future__ import annotations

from typing import Any, Dict, List

from core.base_check import BaseCheck
from core.engine import AuditEngine
from checks.registry import build_checks


def create_engine(config: Dict[str, Any] | None = None) -> AuditEngine:
    """
    Factory that builds an AuditEngine with platform-appropriate checks.

    Why platforms/ as a separate package? Even when checks are cross-platform,
    registration order and platform-only modules live here. Keeps core/ OS-agnostic.
    """
    engine = AuditEngine()
    engine.register_many(build_checks(config))
    return engine
