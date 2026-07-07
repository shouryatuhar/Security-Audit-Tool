"""Dangerous configuration detection."""

from __future__ import annotations

import os
import platform
from datetime import datetime, timezone
from typing import List

from core.base_check import BaseCheck
from core.models import Finding, Severity
from checks.helpers import fail_finding, pass_finding, warn_finding
from utils.command import run_command


class DangerousConfigCheck(BaseCheck):
    check_id = "dangerous_config"
    title = "Dangerous Configuration"
    category = "hardening"
    supported_platforms = ("linux", "darwin", "windows")

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        system = platform.system().lower()

        if system in ("linux", "darwin"):
            findings.extend(self._check_core_dumps())
            findings.extend(self._check_world_writable())
            findings.extend(self._check_ip_forwarding())

        if system == "windows":
            findings.extend(self._check_autorun())

        if not findings:
            findings.append(
                pass_finding(
                    self.check_id,
                    self.title,
                    "No dangerous configurations detected",
                    self.category,
                    confidence="high",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    technical_detail=(
                        "All checked kernel, filesystem, and network configurations "
                        "are within acceptable security baselines."
                    ),
                )
            )
        return findings

    def _check_core_dumps(self) -> List[Finding]:
        _, stdout, _ = run_command(["sysctl", "kernel.core_pattern"])
        if stdout and "core" in stdout.lower():
            return [
                warn_finding(
                    self.check_id,
                    "Core Dumps Enabled",
                    "Core dumps may leak sensitive memory contents",
                    Severity.LOW,
                    self.category,
                    remediation="Set kernel.core_pattern to disable or pipe to secure handler",
                    detection_command="sysctl kernel.core_pattern",
                    confidence="high",
                    cvss_score=4.0,
                    cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    affected_asset="kernel-core-dump-config",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    technical_detail=(
                        "The kernel.core_pattern sysctl is configured to write core "
                        "dumps. Crash dumps can contain cleartext credentials, "
                        "cryptographic keys, and PII from process memory."
                    ),
                    business_impact=(
                        "An attacker with local read access could harvest credentials "
                        "or secrets from core dump files."
                    ),
                    remediation_steps=[
                        "Run 'sysctl -w kernel.core_pattern=/dev/null' to disable core dumps",
                        "Persist in /etc/sysctl.d/99-security.conf",
                        "Set 'ulimit -c 0' in /etc/security/limits.conf",
                    ],
                    verification_command="sysctl kernel.core_pattern",
                )
            ]
        return []

    def _check_world_writable(self) -> List[Finding]:
        risky_paths = ["/tmp", "/var/tmp", "/dev/shm"]
        world_writable = []
        for path in risky_paths:
            if os.path.isdir(path):
                st_mode = os.stat(path).st_mode
                is_world_writable = bool(st_mode & 0o002)
                has_sticky_bit = bool(st_mode & 0o1000)
                
                if is_world_writable and not has_sticky_bit:
                    mode_str = oct(st_mode)[-4:]
                    world_writable.append(f"{path} ({mode_str})")

        if world_writable:
            return [
                warn_finding(
                    self.check_id,
                    "World-Writable Directories without Sticky Bit",
                    f"Review permissions: {', '.join(world_writable)}",
                    Severity.MEDIUM,
                    self.category,
                    detection_command="stat /tmp",
                    confidence="high",
                    cvss_score=6.5,
                    cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                    affected_asset="filesystem-permissions",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    technical_detail=(
                        f"Directories {', '.join(world_writable)} have world-writable "
                        "permissions (777) but lack the sticky bit (t). Without the sticky bit, "
                        "any local user can delete or rename files owned by others in these directories."
                    ),
                    business_impact=(
                        "World-writable directories without proper sticky bits enable "
                        "symlink attacks, race conditions, local privilege escalation, "
                        "and unprivileged data destruction."
                    ),
                    remediation_steps=[
                        "Set sticky bit to prevent unauthorized deletion: 'chmod +t <directory>'",
                        "Remove world-writable permissions if not needed: 'chmod o-w <directory>'",
                    ],
                    verification_command="stat -c '%a %n' /tmp /var/tmp /dev/shm",
                    references=["CIS Control 3: Data Protection", "MITRE ATT&CK T1222: File and Directory Permissions Modification"],
                )
            ]
        return []

    def _check_ip_forwarding(self) -> List[Finding]:
        _, stdout, _ = run_command(["sysctl", "net.ipv4.ip_forward"])
        if "= 1" in stdout:
            return [
                warn_finding(
                    self.check_id,
                    "IP Forwarding Enabled",
                    "Host is configured as a router — verify intent",
                    Severity.MEDIUM,
                    self.category,
                    remediation="Set net.ipv4.ip_forward = 0 if not a gateway",
                    detection_command="sysctl net.ipv4.ip_forward",
                    confidence="high",
                    cvss_score=6.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    affected_asset="kernel-network-stack",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    technical_detail=(
                        "net.ipv4.ip_forward is set to 1, meaning the host will "
                        "route packets between network interfaces. Unless this host "
                        "is an intentional gateway/router, this exposes adjacent "
                        "network segments to lateral movement."
                    ),
                    business_impact=(
                        "An attacker who compromises this host can use IP forwarding "
                        "to pivot between network segments, bypassing network-level "
                        "access controls."
                    ),
                    remediation_steps=[
                        "Run 'sysctl -w net.ipv4.ip_forward=0' to disable immediately",
                        "Persist via 'echo net.ipv4.ip_forward=0 >> /etc/sysctl.d/99-security.conf'",
                        "Reload with 'sysctl --system'",
                        "If this host is a legitimate router, document the exception",
                    ],
                    verification_command="sysctl net.ipv4.ip_forward",
                )
            ]
        return []

    def _check_autorun(self) -> List[Finding]:
        _, stdout, _ = run_command(
            ["reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"]
        )
        if stdout:
            return [
                pass_finding(
                    self.check_id,
                    "Windows Autorun Entries",
                    "Autorun registry keys enumerated for review",
                    self.category,
                    evidence={"entries": stdout[:500]},
                    detection_command="reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    confidence="medium",
                    affected_asset="windows-autorun-registry",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    technical_detail=(
                        "Windows Run registry key entries enumerated. These programs "
                        "launch automatically at user login and should be reviewed "
                        "for unauthorized persistence mechanisms."
                    ),
                )
            ]
        return []
