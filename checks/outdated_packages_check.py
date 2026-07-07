"""Outdated packages and installed software inventory."""

from __future__ import annotations

import platform
from datetime import datetime, timezone
from typing import Any, Dict, List

from core.base_check import BaseCheck
from core.models import Finding, Severity
from checks.helpers import fail_finding, pass_finding, warn_finding
from utils.command import command_exists, run_command
from utils.cve import correlate_from_cache


class OutdatedPackagesCheck(BaseCheck):
    check_id = "outdated_packages"
    title = "Outdated Packages"
    category = "patching"
    supported_platforms = ("linux", "darwin")

    def run(self) -> List[Finding]:
        system = platform.system().lower()
        if system == "linux":
            return self._check_linux()
        if system == "darwin":
            return self._check_macos()
        return [self.skip_finding("Package manager check not supported")]

    def _check_linux(self) -> List[Finding]:
        if command_exists("apt"):
            return self._check_apt()
        if command_exists("dnf"):
            return self._check_dnf()
        if command_exists("yum"):
            return self._check_yum()
        return [self.skip_finding("No supported package manager found")]

    def _check_apt(self) -> List[Finding]:
        now = datetime.now(timezone.utc).isoformat()
        _, stdout, _ = run_command(["apt", "list", "--upgradable"], use_sudo=True)
        packages = [
            line.split("/")[0]
            for line in stdout.splitlines()[1:]
            if line.strip() and "Listing" not in line
        ]
        if not packages:
            return [
                pass_finding(
                    self.check_id,
                    self.title,
                    "All packages are up to date",
                    self.category,
                    detection_command="apt list --upgradable",
                    confidence="high",
                    timestamp=now,
                    affected_asset="system-packages",
                    technical_detail="Queried APT for upgradable packages; none pending.",
                )
            ]

        cves: List[str] = []
        for pkg in packages[:10]:
            cves.extend(correlate_from_cache(pkg))

        return [
            fail_finding(
                self.check_id,
                "Outdated Packages Detected",
                f"{len(packages)} packages have available updates",
                Severity.HIGH,
                self.category,
                remediation="Run: sudo apt update && sudo apt upgrade",
                cve_ids=sorted(set(cves)),
                evidence={"sample_packages": packages[:10], "total": len(packages)},
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                detection_command="apt list --upgradable",
                confidence="high",
                timestamp=now,
                affected_asset="system-packages",
                technical_detail=(
                    f"{len(packages)} APT packages have pending security/feature updates. "
                    "Outdated packages may contain known vulnerabilities."
                ),
                business_impact=(
                    "Unpatched software exposes the host to known exploits, "
                    "risking data breach, service disruption, or lateral movement."
                ),
                remediation_steps=[
                    "Run `sudo apt update` to refresh the package index.",
                    "Run `sudo apt upgrade -y` to install all available updates.",
                    "Reboot the host if kernel or library updates were applied.",
                    "Re-run this check to confirm all packages are current.",
                ],
                verification_command="apt list --upgradable 2>/dev/null | grep -c upgradable",
            )
        ]

    def _check_dnf(self) -> List[Finding]:
        now = datetime.now(timezone.utc).isoformat()
        _, stdout, _ = run_command(["dnf", "check-update", "-q"], use_sudo=True)
        packages = [l.split()[0] for l in stdout.splitlines() if l.strip()]
        if packages:
            return [
                fail_finding(
                    self.check_id,
                    "Outdated Packages Detected",
                    f"{len(packages)} packages need updates (dnf)",
                    Severity.HIGH,
                    self.category,
                    remediation="Run: sudo dnf upgrade",
                    evidence={"sample_packages": packages[:10]},
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                    detection_command="dnf check-update -q",
                    confidence="high",
                    timestamp=now,
                    affected_asset="system-packages",
                    technical_detail=(
                        f"{len(packages)} DNF packages have pending updates."
                    ),
                    business_impact=(
                        "Unpatched software may contain known vulnerabilities "
                        "exploitable by remote attackers."
                    ),
                    remediation_steps=[
                        "Run `sudo dnf upgrade -y` to install all updates.",
                        "Reboot if kernel updates were applied.",
                    ],
                    verification_command="dnf check-update -q | wc -l",
                )
            ]
        return [
            pass_finding(
                self.check_id,
                self.title,
                "All packages are up to date",
                self.category,
                detection_command="dnf check-update -q",
                confidence="high",
                timestamp=now,
                affected_asset="system-packages",
                technical_detail="Queried DNF for upgradable packages; none pending.",
            )
        ]

    def _check_yum(self) -> List[Finding]:
        now = datetime.now(timezone.utc).isoformat()
        _, stdout, _ = run_command(["yum", "check-update", "-q"], use_sudo=True)
        packages = [l.split()[0] for l in stdout.splitlines() if l.strip()]
        if packages:
            return [
                fail_finding(
                    self.check_id,
                    "Outdated Packages Detected",
                    f"{len(packages)} packages need updates (yum)",
                    Severity.HIGH,
                    self.category,
                    remediation="Run: sudo yum update",
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                    detection_command="yum check-update -q",
                    confidence="high",
                    timestamp=now,
                    affected_asset="system-packages",
                    technical_detail=(
                        f"{len(packages)} YUM packages have pending updates."
                    ),
                    business_impact=(
                        "Unpatched software may contain known vulnerabilities "
                        "exploitable by remote attackers."
                    ),
                    remediation_steps=[
                        "Run `sudo yum update -y` to install all updates.",
                        "Reboot if kernel updates were applied.",
                    ],
                    verification_command="yum check-update -q | wc -l",
                )
            ]
        return [
            pass_finding(
                self.check_id,
                self.title,
                "All packages are up to date",
                self.category,
                detection_command="yum check-update -q",
                confidence="high",
                timestamp=now,
                affected_asset="system-packages",
                technical_detail="Queried YUM for upgradable packages; none pending.",
            )
        ]

    def _check_macos(self) -> List[Finding]:
        now = datetime.now(timezone.utc).isoformat()
        if not command_exists("softwareupdate"):
            return [self.skip_finding("softwareupdate not available")]
        _, stdout, _ = run_command(["softwareupdate", "-l"])
        if "No new software available" in stdout:
            return [
                pass_finding(
                    self.check_id,
                    self.title,
                    "macOS software is up to date",
                    self.category,
                    detection_command="softwareupdate -l",
                    confidence="high",
                    timestamp=now,
                    affected_asset="system-packages",
                    technical_detail="Queried macOS softwareupdate; no pending updates.",
                )
            ]
        return [
            warn_finding(
                self.check_id,
                "macOS Updates Available",
                "System updates are pending",
                Severity.HIGH,
                self.category,
                remediation="Run: sudo softwareupdate -i -a",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                detection_command="softwareupdate -l",
                confidence="high",
                timestamp=now,
                affected_asset="system-packages",
                technical_detail=(
                    "macOS softwareupdate reports pending system updates. "
                    "These may include critical security patches."
                ),
                business_impact=(
                    "Pending macOS updates may contain fixes for actively "
                    "exploited vulnerabilities, risking host compromise."
                ),
                remediation_steps=[
                    "Run `sudo softwareupdate -i -a` to install all available updates.",
                    "Reboot the Mac if prompted.",
                    "Re-run this check to verify.",
                ],
                verification_command="softwareupdate -l 2>&1 | grep -c 'No new software'",
            )
        ]


class PackageInventoryCheck(BaseCheck):
    check_id = "package_inventory"
    title = "Installed Package Inventory"
    category = "inventory"
    supported_platforms = ("linux", "darwin")

    def run(self) -> List[Finding]:
        now = datetime.now(timezone.utc).isoformat()
        packages: List[str] = []
        det_cmd = "unknown"
        if command_exists("dpkg"):
            det_cmd = "dpkg -l"
            _, stdout, _ = run_command(["dpkg", "-l"])
            packages = [
                l.split()[1]
                for l in stdout.splitlines()
                if l.startswith("ii")
            ]
        elif command_exists("rpm"):
            det_cmd = "rpm -qa"
            _, stdout, _ = run_command(["rpm", "-qa"])
            packages = stdout.splitlines()
        elif command_exists("brew"):
            det_cmd = "brew list"
            _, stdout, _ = run_command(["brew", "list"])
            packages = stdout.splitlines()

        return [
            pass_finding(
                self.check_id,
                self.title,
                f"Collected inventory of {len(packages)} installed packages",
                self.category,
                evidence={"count": len(packages), "sample": packages[:15]},
                detection_command=det_cmd,
                confidence="high",
                timestamp=now,
                affected_asset="system-packages",
                technical_detail=(
                    f"Enumerated {len(packages)} installed packages via `{det_cmd}`. "
                    "Inventory captured for asset management and drift detection."
                ),
            )
        ]
