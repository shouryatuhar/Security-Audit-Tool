"""SSH configuration audit — wraps and extends legacy ssh_check."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Dict, List

from core.base_check import BaseCheck
from core.models import Finding, Severity
from checks.helpers import fail_finding, pass_finding, warn_finding
from utils.command import command_exists, run_command


class SSHCheck(BaseCheck):
    check_id = "ssh_config"
    title = "SSH Configuration"
    category = "authentication"
    supported_platforms = ("linux", "darwin")

    CIS_REF = "CIS 5.2 — SSH Server Configuration"

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        now = datetime.now(timezone.utc).isoformat()

        if not command_exists("sshd"):
            return [self.skip_finding("sshd not installed on this host")]

        code, stdout, stderr = run_command(["sshd", "-T"], use_sudo=True)
        if code != 0:
            # Fallback: parse config file directly
            code2, config_text, _ = run_command(
                ["cat", "/etc/ssh/sshd_config"], use_sudo=True
            )
            if code2 != 0:
                return [self.error_finding(stderr or "Cannot read SSH configuration")]
            config = self._parse_flat_config(config_text)
        else:
            config = self._parse_flat_config(stdout)

        findings.extend(self._check_root_login(config, now))
        findings.extend(self._check_password_auth(config, now))
        findings.extend(self._check_empty_passwords(config, now))
        findings.extend(self._check_protocol(config, now))

        if not findings:
            findings.append(
                pass_finding(
                    self.check_id,
                    self.title,
                    "SSH configuration meets baseline requirements",
                    self.category,
                    evidence={"cis": self.CIS_REF},
                    detection_command="sshd -T",
                    affected_asset="sshd",
                    confidence="high",
                    timestamp=now,
                    technical_detail="All audited sshd directives conform to CIS benchmark recommendations.",
                    business_impact="No additional risk — SSH hardening baseline is met.",
                )
            )
        return findings

    def _parse_flat_config(self, text: str) -> Dict[str, str]:
        config: Dict[str, str] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                config[parts[0].lower()] = parts[1].lower()
        return config

    def _check_root_login(self, config: Dict[str, str], now: str) -> List[Finding]:
        value = config.get("permitrootlogin", "prohibit-password")
        if value in ("yes", "without-password"):
            return [
                fail_finding(
                    self.check_id,
                    "SSH Root Login Enabled",
                    f"PermitRootLogin is set to '{value}' — direct root login increases blast radius",
                    Severity.CRITICAL,
                    self.category,
                    remediation="Set PermitRootLogin no in /etc/ssh/sshd_config",
                    references=[self.CIS_REF],
                    evidence={"permitrootlogin": value},
                    detection_command="sshd -T",
                    affected_asset="sshd",
                    confidence="high",
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    timestamp=now,
                    technical_detail=(
                        f"The sshd directive PermitRootLogin is '{value}', allowing "
                        "remote attackers to authenticate directly as root. This bypasses "
                        "audit trails tied to individual user accounts and maximises the "
                        "blast radius of any compromised credential."
                    ),
                    business_impact=(
                        "A compromised root credential grants full system control, "
                        "enabling data exfiltration, service disruption, and lateral movement."
                    ),
                    remediation_steps=[
                        "Edit /etc/ssh/sshd_config and set PermitRootLogin no",
                        "Ensure at least one non-root user has sudo privileges",
                        "Restart sshd: sudo systemctl restart sshd",
                    ],
                    verification_command="sshd -T | grep -i permitrootlogin",
                )
            ]
        return []

    def _check_password_auth(self, config: Dict[str, str], now: str) -> List[Finding]:
        if config.get("passwordauthentication", "yes") == "yes":
            return [
                warn_finding(
                    self.check_id,
                    "SSH Password Authentication Enabled",
                    "Password-based SSH auth is enabled; key-based auth is preferred",
                    Severity.MEDIUM,
                    self.category,
                    remediation="Set PasswordAuthentication no and use SSH keys",
                    references=[self.CIS_REF],
                    detection_command="sshd -T",
                    affected_asset="sshd",
                    confidence="high",
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    timestamp=now,
                    technical_detail=(
                        "PasswordAuthentication is enabled, exposing SSH to brute-force "
                        "and credential-stuffing attacks. Key-based authentication provides "
                        "stronger guarantees against remote compromise."
                    ),
                    business_impact=(
                        "Password-based access is susceptible to brute-force attacks, "
                        "potentially leading to unauthorised access and data breach."
                    ),
                    remediation_steps=[
                        "Generate SSH key pairs for all users: ssh-keygen -t ed25519",
                        "Distribute public keys to ~/.ssh/authorized_keys",
                        "Set PasswordAuthentication no in /etc/ssh/sshd_config",
                        "Restart sshd: sudo systemctl restart sshd",
                    ],
                    verification_command="sshd -T | grep -i passwordauthentication",
                )
            ]
        return []

    def _check_empty_passwords(self, config: Dict[str, str], now: str) -> List[Finding]:
        if config.get("permitemptypasswords", "no") == "yes":
            return [
                fail_finding(
                    self.check_id,
                    "SSH Empty Passwords Permitted",
                    "PermitEmptyPasswords is enabled",
                    Severity.CRITICAL,
                    self.category,
                    remediation="Set PermitEmptyPasswords no",
                    detection_command="sshd -T",
                    affected_asset="sshd",
                    confidence="high",
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    timestamp=now,
                    technical_detail=(
                        "PermitEmptyPasswords is set to yes, meaning any account with "
                        "an empty password field can authenticate over SSH without a secret. "
                        "This is effectively unauthenticated remote access."
                    ),
                    business_impact=(
                        "Unauthenticated remote access can lead to full system compromise, "
                        "data theft, ransomware deployment, and regulatory non-compliance."
                    ),
                    remediation_steps=[
                        "Set PermitEmptyPasswords no in /etc/ssh/sshd_config",
                        "Audit /etc/shadow for accounts with empty password hashes",
                        "Restart sshd: sudo systemctl restart sshd",
                    ],
                    verification_command="sshd -T | grep -i permitemptypasswords",
                )
            ]
        return []

    def _check_protocol(self, config: Dict[str, str], now: str) -> List[Finding]:
        protocol = config.get("protocol", "2")
        if protocol != "2":
            return [
                warn_finding(
                    self.check_id,
                    "Legacy SSH Protocol",
                    f"SSH protocol version '{protocol}' may be insecure",
                    Severity.MEDIUM,
                    self.category,
                    detection_command="sshd -T",
                    affected_asset="sshd",
                    confidence="high",
                    cvss_score=5.9,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    timestamp=now,
                    technical_detail=(
                        f"SSH protocol version '{protocol}' is configured. SSHv1 has known "
                        "cryptographic weaknesses including vulnerability to man-in-the-middle "
                        "and session-hijacking attacks."
                    ),
                    business_impact=(
                        "Use of a deprecated protocol version may allow eavesdropping "
                        "on SSH sessions and violates most compliance frameworks."
                    ),
                    remediation_steps=[
                        "Set Protocol 2 in /etc/ssh/sshd_config",
                        "Remove any Protocol 1 references",
                        "Restart sshd: sudo systemctl restart sshd",
                    ],
                    verification_command="sshd -T | grep -i protocol",
                )
            ]
        return []
