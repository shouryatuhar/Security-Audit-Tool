"""Rootkit detection audit."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List

from core.base_check import BaseCheck
from core.models import Finding, Severity
from checks.helpers import fail_finding, pass_finding, warn_finding
from utils.command import command_exists, run_command


class RootkitCheck(BaseCheck):
    check_id = "rootkit_detection"
    title = "Rootkit Detection"
    category = "malware"
    supported_platforms = ("linux",)

    def run(self) -> List[Finding]:
        now = datetime.now(timezone.utc).isoformat()
        if command_exists("rkhunter"):
            return self._rkhunter()
        if command_exists("chkrootkit"):
            return self._chkrootkit()
        return [
            warn_finding(
                self.check_id,
                self.title,
                "No rootkit scanner installed (rkhunter/chkrootkit)",
                Severity.LOW,
                self.category,
                remediation="Install rkhunter: sudo apt install rkhunter",
                detection_command="which rkhunter chkrootkit",
                confidence="high",
                timestamp=now,
                technical_detail=(
                    "Neither rkhunter nor chkrootkit is present on the system PATH. "
                    "Without a rootkit scanner, kernel-level and userland rootkits "
                    "cannot be detected."
                ),
                business_impact=(
                    "Rootkits can persist undetected, granting attackers "
                    "persistent privileged access and undermining all other controls."
                ),
                remediation_steps=[
                    "Install rkhunter: sudo apt install rkhunter",
                    "Alternatively install chkrootkit: sudo apt install chkrootkit",
                    "Run an initial baseline scan after installation",
                ],
                verification_command="which rkhunter || which chkrootkit",
            )
        ]

    def _rkhunter(self) -> List[Finding]:
        now = datetime.now(timezone.utc).isoformat()
        det_cmd = "rkhunter --check --sk --nocolors"
        code, stdout, stderr = run_command(
            ["rkhunter", "--check", "--sk", "--nocolors"], use_sudo=True, timeout=300
        )
        output = stdout + stderr
        if "Warning" in output or "Found" in output:
            return [
                fail_finding(
                    self.check_id,
                    "Rootkit Indicators Found",
                    "rkhunter reported warnings — manual investigation required",
                    Severity.CRITICAL,
                    self.category,
                    remediation="Review /var/log/rkhunter.log and validate findings",
                    evidence={"scanner": "rkhunter", "exit_code": code},
                    detection_command=det_cmd,
                    confidence="high",
                    cvss_score=10.0,
                    cvss_vector="CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
                    affected_asset="host (kernel / userland)",
                    timestamp=now,
                    technical_detail=(
                        "rkhunter flagged rootkit indicators such as modified system "
                        "binaries, hidden files, or suspicious kernel modules. "
                        "These findings may represent an active compromise of the "
                        "host's trusted computing base."
                    ),
                    business_impact=(
                        "A confirmed rootkit grants an attacker persistent, privileged, "
                        "and stealthy access. All data on the host must be considered "
                        "compromised, and the host should be isolated immediately."
                    ),
                    remediation_steps=[
                        "Isolate the host from the network immediately",
                        "Review /var/log/rkhunter.log for specific indicators",
                        "Capture forensic disk and memory images before remediation",
                        "Cross-validate with chkrootkit or a live-boot AV rescue disk",
                        "If confirmed, reimage the host from a known-good baseline",
                        "Rotate all credentials that were accessible from this host",
                    ],
                    verification_command="sudo rkhunter --check --sk --nocolors 2>&1 | grep -E 'Warning|Found'",
                )
            ]
        return [
            pass_finding(
                self.check_id,
                self.title,
                "rkhunter scan completed with no warnings",
                self.category,
                detection_command=det_cmd,
                confidence="high",
                timestamp=now,
                technical_detail="rkhunter completed a full scan with no rootkit indicators detected.",
            )
        ]

    def _chkrootkit(self) -> List[Finding]:
        now = datetime.now(timezone.utc).isoformat()
        det_cmd = "chkrootkit"
        _, stdout, _ = run_command(["chkrootkit"], use_sudo=True, timeout=300)
        if "INFECTED" in stdout:
            return [
                fail_finding(
                    self.check_id,
                    "Rootkit Infection Suspected",
                    "chkrootkit reported INFECTED status",
                    Severity.CRITICAL,
                    self.category,
                    detection_command=det_cmd,
                    confidence="high",
                    cvss_score=10.0,
                    cvss_vector="CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
                    affected_asset="host (kernel / userland)",
                    timestamp=now,
                    technical_detail=(
                        "chkrootkit detected INFECTED status in one or more checks. "
                        "This typically indicates tampered system binaries or the "
                        "presence of a known rootkit signature."
                    ),
                    business_impact=(
                        "A confirmed rootkit grants an attacker persistent, privileged, "
                        "and stealthy access. All data on the host must be considered "
                        "compromised, and the host should be isolated immediately."
                    ),
                    remediation_steps=[
                        "Isolate the host from the network immediately",
                        "Run chkrootkit again with verbose output: sudo chkrootkit -x",
                        "Capture forensic disk and memory images before remediation",
                        "Cross-validate with rkhunter or a live-boot AV rescue disk",
                        "If confirmed, reimage the host from a known-good baseline",
                        "Rotate all credentials that were accessible from this host",
                    ],
                    verification_command="sudo chkrootkit 2>&1 | grep INFECTED",
                )
            ]
        return [
            pass_finding(
                self.check_id,
                self.title,
                "chkrootkit scan clean",
                self.category,
                detection_command=det_cmd,
                confidence="high",
                timestamp=now,
                technical_detail="chkrootkit completed a full scan with no infection indicators.",
            )
        ]


