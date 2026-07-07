"""Security score calculation (0–100)."""

from __future__ import annotations

from typing import Iterable

from core.models import CheckStatus, Finding, SEVERITY_WEIGHTS, Severity


def calculate_score(findings: Iterable[Finding]) -> int:
    """
    Start at 100 and deduct weighted points for FAIL/WARN findings.

    Scoring Tiers:
    80-100: Healthy developer machine
    70-80: Minor issues
    50-70: Medium issues
    20-50: Serious security issues
    <20: Critical compromise indicators
    
    Uses logarithmic/diminishing penalties to avoid zeroing out from many low-severity issues.
    """
    score = 100
    severity_counts: dict[Severity, int] = {s: 0 for s in Severity}

    for finding in findings:
        if finding.status not in (CheckStatus.FAIL, CheckStatus.WARN):
            continue
        severity_counts[finding.severity] += 1

    # Apply tiered deductions with diminishing returns
    # The first issue of a severity hurts the most, subsequent issues hurt less
    
    # Critical: -30 for the first, -15 for each additional
    crit_count = severity_counts[Severity.CRITICAL]
    if crit_count > 0:
        score -= (30 + (crit_count - 1) * 15)
        
    # High: -15 for the first, -7 for each additional
    high_count = severity_counts[Severity.HIGH]
    if high_count > 0:
        score -= (15 + (high_count - 1) * 7)
        
    # Medium: -8 for the first, -4 for each additional
    med_count = severity_counts[Severity.MEDIUM]
    if med_count > 0:
        score -= (8 + (med_count - 1) * 4)
        
    # Low: -3 for the first, -1 for each additional (capped at -15 total)
    low_count = severity_counts[Severity.LOW]
    if low_count > 0:
        low_penalty = 3 + (low_count - 1) * 1
        score -= min(15, low_penalty)

    return max(0, min(100, score))
