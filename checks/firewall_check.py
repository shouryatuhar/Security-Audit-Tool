"""Firewall status audit — cross-platform where possible."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List

from core.base_check import BaseCheck
from core.models import Finding, Severity
from checks.helpers import fail_finding, pass_finding, warn_finding
from utils.command import command_exists, run_command


class FirewallCheck(BaseCheck):
    check_id = "firewall"
    title = "Firewall Status"
    category = "network"
    supported_platforms = ("linux", "darwin", "windows")

    def run(self) -> List[Finding]:
        import platform

        self._now = datetime.now(timezone.utc).isoformat()
        system = platform.system().lower()
        if system == "linux":
            return self._check_linux()
        if system == "darwin":
            return self._check_macos()
        if system == "windows":
            return self._check_windows()
        return [self.skip_finding("Unsupported platform for firewall check")]

    def _check_linux(self) -> List[Finding]:
        if command_exists("ufw"):
            return self._check_ufw()
        if command_exists("firewall-cmd"):
            return self._check_firewalld()
        if command_exists("iptables"):
            return self._check_iptables()
        return [
            warn_finding(
                self.check_id,
                self.title,
                "No recognised firewall tool found (ufw/firewalld/iptables)",
                Severity.HIGH,
                self.category,
                remediation="Install and enable ufw or firewalld",
                detection_command="which ufw firewall-cmd iptables",
                affected_asset="host-firewall",
                confidence="high",
                cvss_score=6.5,
                cvss_vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                timestamp=self._now,
                technical_detail=(
                    "No recognised host-based firewall binary (ufw, firewall-cmd, "
                    "iptables) was found on PATH. The host may be entirely unprotected "
                    "at the network layer."
                ),
                business_impact=(
                    "Without a firewall, the host is exposed to unauthorised network "
                    "access, increasing the risk of lateral movement and data exfiltration."
                ),
                remediation_steps=[
                    "Install a firewall: sudo apt install ufw  (Debian/Ubuntu) or sudo yum install firewalld  (RHEL/CentOS)",
                    "Enable the firewall: sudo ufw enable  or  sudo systemctl enable --now firewalld",
                    "Configure default-deny inbound policy",
                ],
                verification_command="ufw status || firewall-cmd --state || iptables -L -n",
            )
        ]

    def _check_ufw(self) -> List[Finding]:
        _, stdout, _ = run_command(["ufw", "status"], use_sudo=True)
        if "inactive" in stdout.lower():
            return [
                fail_finding(
                    self.check_id,
                    "Firewall Disabled (UFW)",
                    "UFW firewall is inactive",
                    Severity.HIGH,
                    self.category,
                    remediation="Run: sudo ufw enable",
                    evidence={"tool": "ufw", "status": "inactive"},
                    detection_command="sudo ufw status",
                    affected_asset="ufw",
                    confidence="high",
                    cvss_score=6.5,
                    cvss_vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    timestamp=self._now,
                    technical_detail=(
                        "UFW (Uncomplicated Firewall) is installed but inactive. "
                        "No inbound filtering rules are being enforced, leaving all "
                        "listening services reachable on the local network segment."
                    ),
                    business_impact=(
                        "An inactive firewall exposes all services to the network, "
                        "increasing attack surface and risk of unauthorised access."
                    ),
                    remediation_steps=[
                        "Enable UFW: sudo ufw enable",
                        "Set default deny inbound: sudo ufw default deny incoming",
                        "Allow required services: sudo ufw allow ssh",
                    ],
                    verification_command="sudo ufw status",
                )
            ]
        return [
            pass_finding(
                self.check_id,
                self.title,
                "UFW firewall is active",
                self.category,
                evidence={"tool": "ufw", "status": "active"},
                detection_command="sudo ufw status",
                affected_asset="ufw",
                confidence="high",
                timestamp=self._now,
                technical_detail="UFW is active and enforcing configured firewall rules.",
                business_impact="No additional risk — host firewall is operational.",
            )
        ]

    def _check_firewalld(self) -> List[Finding]:
        code, stdout, _ = run_command(["firewall-cmd", "--state"])
        if code != 0 or "running" not in stdout.lower():
            return [
                fail_finding(
                    self.check_id,
                    "Firewall Disabled (firewalld)",
                    "firewalld is not running",
                    Severity.HIGH,
                    self.category,
                    remediation="Run: sudo systemctl start firewalld",
                    detection_command="firewall-cmd --state",
                    affected_asset="firewalld",
                    confidence="high",
                    cvss_score=6.5,
                    cvss_vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    timestamp=self._now,
                    technical_detail=(
                        "firewalld is installed but the service is not running. "
                        "No zone-based filtering rules are active."
                    ),
                    business_impact=(
                        "Without an active firewall daemon, all listening services "
                        "are exposed, increasing attack surface significantly."
                    ),
                    remediation_steps=[
                        "Start firewalld: sudo systemctl start firewalld",
                        "Enable on boot: sudo systemctl enable firewalld",
                        "Verify active zone: sudo firewall-cmd --get-active-zones",
                    ],
                    verification_command="firewall-cmd --state",
                )
            ]
        return [
            pass_finding(
                self.check_id,
                self.title,
                "firewalld is running",
                self.category,
                detection_command="firewall-cmd --state",
                affected_asset="firewalld",
                confidence="high",
                timestamp=self._now,
                technical_detail="firewalld daemon is running and enforcing zone-based rules.",
                business_impact="No additional risk — host firewall is operational.",
            )
        ]

    def _check_iptables(self) -> List[Finding]:
        _, stdout, _ = run_command(["iptables", "-L", "-n"], use_sudo=True)
        if "Chain INPUT (policy ACCEPT)" in stdout and stdout.count("DROP") < 2:
            return [
                warn_finding(
                    self.check_id,
                    "Permissive iptables Policy",
                    "iptables INPUT chain may accept all traffic by default",
                    Severity.MEDIUM,
                    self.category,
                    detection_command="sudo iptables -L -n",
                    affected_asset="iptables",
                    confidence="medium",
                    cvss_score=5.0,
                    cvss_vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    timestamp=self._now,
                    technical_detail=(
                        "The iptables INPUT chain has a default ACCEPT policy with fewer "
                        "than two DROP rules. This indicates a permissive configuration "
                        "that may not adequately filter inbound traffic."
                    ),
                    business_impact=(
                        "A permissive default-accept policy allows most inbound traffic, "
                        "increasing the risk of exploitation of any listening service."
                    ),
                    remediation_steps=[
                        "Set default policy to DROP: sudo iptables -P INPUT DROP",
                        "Allow established connections: sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
                        "Allow required services explicitly (e.g., SSH on port 22)",
                        "Persist rules: sudo iptables-save > /etc/iptables/rules.v4",
                    ],
                    verification_command="sudo iptables -L -n",
                )
            ]
        return [
            pass_finding(
                self.check_id,
                self.title,
                "iptables rules present",
                self.category,
                detection_command="sudo iptables -L -n",
                affected_asset="iptables",
                confidence="medium",
                timestamp=self._now,
                technical_detail="iptables has a non-trivial rule set with DROP rules present.",
                business_impact="No additional risk — iptables filtering is in place.",
            )
        ]

    def _check_macos(self) -> List[Finding]:
        _, stdout, _ = run_command(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"]
        )
        if "enabled" in stdout.lower():
            return [
                pass_finding(
                    self.check_id,
                    self.title,
                    "macOS Application Firewall is enabled",
                    self.category,
                    detection_command="/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate",
                    affected_asset="socketfilterfw",
                    confidence="high",
                    timestamp=self._now,
                    technical_detail="macOS Application Firewall (ALF) is enabled and filtering inbound connections.",
                    business_impact="No additional risk — macOS firewall is active.",
                )
            ]
        return [
            fail_finding(
                self.check_id,
                "macOS Firewall Disabled",
                "Application Firewall is not enabled",
                Severity.HIGH,
                self.category,
                remediation="Enable via System Settings → Network → Firewall",
                detection_command="/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate",
                affected_asset="socketfilterfw",
                confidence="high",
                cvss_score=6.5,
                cvss_vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                timestamp=self._now,
                technical_detail=(
                    "The macOS Application Firewall (ALF / socketfilterfw) is disabled. "
                    "All listening services accept inbound connections without filtering."
                ),
                business_impact=(
                    "Without the application firewall, any listening process is reachable "
                    "from the local network, increasing exposure to exploitation."
                ),
                remediation_steps=[
                    "Open System Settings → Network → Firewall and toggle ON",
                    "Alternatively: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
                    "Verify: /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate",
                ],
                verification_command="/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate",
            )
        ]

    def _check_windows(self) -> List[Finding]:
        code, stdout, _ = run_command(
            ["netsh", "advfirewall", "show", "allprofiles", "state"]
        )
        if code == 0 and "ON" in stdout.upper():
            return [
                pass_finding(
                    self.check_id,
                    self.title,
                    "Windows Firewall is enabled",
                    self.category,
                    detection_command="netsh advfirewall show allprofiles state",
                    affected_asset="Windows Defender Firewall",
                    confidence="high",
                    timestamp=self._now,
                    technical_detail="Windows Defender Firewall reports ON for queried profiles.",
                    business_impact="No additional risk — Windows firewall is active.",
                )
            ]
        return [
            fail_finding(
                self.check_id,
                "Windows Firewall Disabled",
                "Windows Defender Firewall appears disabled",
                Severity.HIGH,
                self.category,
                remediation="Enable via: netsh advfirewall set allprofiles state on",
                detection_command="netsh advfirewall show allprofiles state",
                affected_asset="Windows Defender Firewall",
                confidence="high",
                cvss_score=6.5,
                cvss_vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                timestamp=self._now,
                technical_detail=(
                    "Windows Defender Firewall is disabled for one or more profiles "
                    "(Domain/Private/Public). All listening services are reachable "
                    "without OS-level filtering."
                ),
                business_impact=(
                    "A disabled Windows firewall exposes the host to network-based "
                    "attacks across all profiles, increasing risk of lateral movement."
                ),
                remediation_steps=[
                    "Enable firewall: netsh advfirewall set allprofiles state on",
                    "Verify: netsh advfirewall show allprofiles state",
                    "Review inbound rules via: netsh advfirewall firewall show rule name=all",
                ],
                verification_command="netsh advfirewall show allprofiles state",
            )
        ]
