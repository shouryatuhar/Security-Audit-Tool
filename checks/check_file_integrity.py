"""File integrity and permission auditing."""

from __future__ import annotations

import hashlib
import os
import platform as _platform
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from core.base_check import BaseCheck
from core.models import Finding, Severity
from checks.helpers import fail_finding, pass_finding, warn_finding


MONITORED_FILES = ["/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config"]
KNOWN_HASHES: Dict[str, str] = {
    "/etc/passwd": "your_known_hash_here",
    "/etc/shadow": "your_known_hash_here",
    "/etc/ssh/sshd_config": "your_known_hash_here",
}


def get_file_hash(file_path: str) -> str | None:
    if not os.path.exists(file_path):
        return None
    with open(file_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class FileIntegrityCheck(BaseCheck):
    check_id = "file_integrity"
    title = "Critical File Integrity"
    category = "integrity"
    supported_platforms = ("linux", "darwin")

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        for file_path in MONITORED_FILES:
            if not os.path.exists(file_path):
                continue
            current = get_file_hash(file_path)
            known = KNOWN_HASHES.get(file_path)
            if known and known != "your_known_hash_here" and current != known:
                findings.append(
                    fail_finding(
                        self.check_id,
                        f"Integrity Violation: {file_path}",
                        "File hash does not match baseline",
                        Severity.HIGH,
                        self.category,
                        remediation="Investigate unauthorized changes; restore from backup",
                        evidence={"path": file_path, "current_hash": current},
                        detection_command=f"sha256sum {file_path}",
                        confidence="high",
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                        affected_asset=file_path,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        technical_detail=(
                            f"SHA-256 hash of {file_path} ({current}) differs from "
                            f"the stored baseline ({known}). This indicates the file "
                            f"was modified outside of approved change-management."
                        ),
                        business_impact=(
                            "Unauthorized modification of critical system files may "
                            "indicate active compromise, backdoor installation, or "
                            "configuration tampering."
                        ),
                        remediation_steps=[
                            f"Compare with backup: diff {file_path} {file_path}.bak",
                            "Review recent changes: stat and auditd logs for the file",
                            f"Restore from trusted backup if tampering confirmed",
                            "Update baseline hash after verified legitimate change",
                        ],
                        verification_command=f"sha256sum {file_path}",
                    )
                )
        if not findings:
            findings.append(
                pass_finding(
                    self.check_id,
                    self.title,
                    "Monitored files present (baseline hashes not configured)",
                    self.category,
                    evidence={"monitored": MONITORED_FILES},
                    detection_command="sha256sum " + " ".join(MONITORED_FILES),
                    confidence="medium",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    technical_detail=(
                        "All monitored files exist but baseline hashes have not "
                        "been configured yet. Integrity verification is inactive "
                        "until known-good hashes are populated in KNOWN_HASHES."
                    ),
                )
            )
        return findings


class FilePermissionsCheck(BaseCheck):
    check_id = "file_permissions"
    title = "Critical File Permissions"
    category = "integrity"
    supported_platforms = ("linux", "darwin")

    EXPECTED = {
        "/etc/shadow": 0o640,
        "/etc/gshadow": 0o640,
        "/etc/sudoers": 0o440,
        "/etc/passwd": 0o644,
    }

    def __init__(self, config: Dict[str, Any] | None = None):
        cfg = config or {}
        extra = cfg.get("monitored_paths", [])
        for path in extra:
            if path not in self.EXPECTED:
                self.EXPECTED[path] = 0o644

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        for path, max_mode in self.EXPECTED.items():
            if not os.path.exists(path):
                continue
            mode = stat.S_IMODE(os.stat(path).st_mode)
            if mode > max_mode:
                _is_mac = _platform.system().lower() == "darwin"
                _stat_cmd = f"stat -f %Lp {path}" if _is_mac else f"stat -c %a {path}"
                findings.append(
                    fail_finding(
                        self.check_id,
                        f"Overly Permissive: {path}",
                        f"Mode {oct(mode)} exceeds maximum {oct(max_mode)}",
                        Severity.HIGH,
                        self.category,
                        remediation=f"Run: chmod {oct(max_mode)[-3:]} {path}",
                        evidence={"path": path, "mode": oct(mode)},
                        detection_command=_stat_cmd,
                        confidence="high",
                        cvss_score=6.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                        affected_asset=path,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        technical_detail=(
                            f"{path} has mode {oct(mode)} which is more permissive "
                            f"than the policy maximum of {oct(max_mode)}. Excess "
                            f"permissions may expose sensitive data such as "
                            f"password hashes or sudoers directives."
                        ),
                        business_impact=(
                            "Over-permissive files can leak credentials or "
                            "allow unprivileged users to escalate privileges, "
                            "violating regulatory and compliance requirements."
                        ),
                        remediation_steps=[
                            f"Tighten permissions: chmod {oct(max_mode)[-3:]} {path}",
                            f"Verify ownership: chown root:root {path}",
                            "Review auditd logs for recent permission changes",
                            "Add a cron/systemd timer to monitor permission drift",
                        ],
                        verification_command=_stat_cmd,
                    )
                )
        if not findings:
            _is_mac = _platform.system().lower() == "darwin"
            _stat_flag = "-f %Lp" if _is_mac else "-c %a"
            findings.append(
                pass_finding(
                    self.check_id,
                    self.title,
                    "Critical file permissions within policy",
                    self.category,
                    detection_command=f"stat {_stat_flag} " + " ".join(self.EXPECTED.keys()),
                    confidence="high",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    technical_detail=(
                        "All monitored critical files have permissions at or "
                        "below the maximum policy threshold."
                    ),
                )
            )
        return findings
