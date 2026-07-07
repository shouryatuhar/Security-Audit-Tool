"""CVE correlation utilities (offline-first with optional enrichment)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Optional


# Curated high-impact CVE patterns for common outdated packages (offline baseline).
# In production you'd query NVD/OSV APIs; this gives interview-ready correlation.
KNOWN_PACKAGE_CVES: Dict[str, List[str]] = {
    "openssl": ["CVE-2022-3602", "CVE-2023-0286"],
    "openssh": ["CVE-2023-38408", "CVE-2023-48795"],
    "sudo": ["CVE-2023-22809", "CVE-2021-3156"],
    "curl": ["CVE-2023-38545"],
    "nginx": ["CVE-2023-44487"],
    "apache2": ["CVE-2023-25690"],
    "log4j": ["CVE-2021-44228"],
    "polkit": ["CVE-2021-4034"],
    "glibc": ["CVE-2023-4911"],
}


def correlate_package_cves(package_name: str) -> List[str]:
    """Match package name against known vulnerable components."""
    normalised = package_name.lower().split("/")[0].split(":")[0]
    for key, cves in KNOWN_PACKAGE_CVES.items():
        if key in normalised:
            return list(cves)
    return []


def correlate_from_cache(package_name: str, cache_dir: str = ".cache/cve") -> List[str]:
    """Load cached CVE data if a prior enrichment run stored results."""
    cache_path = Path(cache_dir) / f"{package_name.lower()}.json"
    if cache_path.is_file():
        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))
            return data.get("cves", [])
        except (json.JSONDecodeError, OSError):
            pass
    return correlate_package_cves(package_name)


def extract_cve_ids(text: str) -> List[str]:
    return sorted(set(re.findall(r"CVE-\d{4}-\d+", text, re.IGNORECASE)))
