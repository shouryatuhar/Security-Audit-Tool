"""HostSentinel configuration loader."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_CONFIG: Dict[str, Any] = {
    "product_name": "HostSentinel",
    "version": "1.0.0",
    "logging": {
        "level": "INFO",
        "file": "logs/hostsentinel.log",
        "audit_file": "logs/audit.log",
    },
    "reports": {
        "output_dir": "reports",
        "formats": ["json", "html"],
    },
    "checks": {
        "enabled": [],  # empty = run all registered checks
        "categories": [],
        "skip": [],
    },
    "scoring": {
        "pass_threshold": 80,
        "warn_threshold": 60,
    },
    "cve": {
        "enabled": True,
        "cache_dir": ".cache/cve",
    },
    "port_scan": {
        "enabled": True,
        "risky_ports": [21, 23, 135, 139, 445, 3389, 5900, 6379, 27017],
    },
    "file_permissions": {
        "monitored_paths": [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/ssh/sshd_config",
        ],
        "max_mode": "0644",
    },
    "password_policy": {
        "min_length": 12,
        "require_complexity": True,
    },
    "unused_account_days": 90,
}


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load YAML config if present, else return defaults.

    Search order: explicit path → ./hostsentinel.yaml → ./config/hostsentinel.yaml
    """
    config = dict(DEFAULT_CONFIG)
    candidates = []

    if path:
        candidates.append(Path(path))
    candidates.extend([
        Path("hostsentinel.yaml"),
        Path("config/hostsentinel.yaml"),
    ])

    for candidate in candidates:
        if candidate.is_file():
            try:
                import yaml  # type: ignore

                with open(candidate, "r", encoding="utf-8") as fh:
                    user_config = yaml.safe_load(fh) or {}
                config = _deep_merge(config, user_config)
                config["_config_path"] = str(candidate.resolve())
                break
            except ImportError:
                config["_config_warning"] = "PyYAML not installed; using defaults"
                break
            except Exception as exc:
                config["_config_warning"] = f"Failed to load {candidate}: {exc}"

    return config


def get_enabled_checks(config: Dict[str, Any]) -> Optional[List[str]]:
    enabled = config.get("checks", {}).get("enabled", [])
    return enabled if enabled else None
