"""Password policy and weak credential auditing."""

from __future__ import annotations

import platform
import re
from datetime import datetime, timezone
from typing import Any, Dict, List

from core.base_check import BaseCheck
from core.models import Finding, Severity
from checks.helpers import fail_finding, pass_finding, warn_finding
from utils.command import run_command


class PasswordPolicyCheck(BaseCheck):
    check_id = "password_policy"
    title = "Password Policy"
    category = "authentication"
    supported_platforms = ("linux", "darwin", "windows")

    def __init__(self, config: Dict[str, Any] | None = None):
        self.config = config or {}

    def run(self) -> List[Finding]:
        system = platform.system().lower()
        if system == "linux":
            return self._check_linux()
        if system == "darwin":
            return self._check_macos()
        if system == "windows":
            return self._check_windows()
        return [self.skip_finding("Unsupported platform")]

    def _check_linux(self) -> List[Finding]:
        findings: List[Finding] = []
        min_len = self.config.get("min_length", 12)
        now = datetime.now(timezone.utc).isoformat()

        _, login_defs, _ = run_command(["cat", "/etc/login.defs"], use_sudo=True)
        match = re.search(r"PASS_MIN_LEN\s+(\d+)", login_defs)
        if match and int(match.group(1)) < min_len:
            findings.append(
                warn_finding(
                    self.check_id,
                    "Weak Minimum Password Length",
                    f"PASS_MIN_LEN is {match.group(1)} (recommended ≥ {min_len})",
                    Severity.MEDIUM,
                    self.category,
                    remediation=f"Set PASS_MIN_LEN {min_len} in /etc/login.defs",
                    detection_command="cat /etc/login.defs | grep PASS_MIN_LEN",
                    confidence="high",
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    affected_asset="/etc/login.defs",
                    timestamp=now,
                    technical_detail=(
                        "The PASS_MIN_LEN directive in /etc/login.defs controls the "
                        "minimum acceptable password length for local accounts. A value "
                        f"of {match.group(1)} is below the recommended minimum of "
                        f"{min_len}, increasing susceptibility to brute-force and "
                        "dictionary attacks against local authentication."
                    ),
                    business_impact=(
                        "Weak password length requirements increase the risk of "
                        "credential compromise, potentially granting attackers access "
                        "to sensitive systems and data."
                    ),
                    remediation_steps=[
                        f"Edit /etc/login.defs and set PASS_MIN_LEN to {min_len} or higher.",
                        "Consider enforcing password complexity via PAM (pam_pwquality).",
                        "Audit existing accounts for passwords below the new minimum.",
                    ],
                    verification_command=f"grep '^PASS_MIN_LEN' /etc/login.defs",
                )
            )

        _, shadow, _ = run_command(["cat", "/etc/shadow"], use_sudo=True)
        weak_accounts = []
        for line in shadow.splitlines():
            parts = line.split(":")
            if len(parts) >= 2:
                user, pw_hash = parts[0], parts[1]
                if pw_hash in ("", "!", "*", "!!") or pw_hash.startswith("!"):
                    if user not in ("root", "sync", "halt", "shutdown"):
                        weak_accounts.append(user)

        if weak_accounts:
            findings.append(
                fail_finding(
                    self.check_id,
                    "Accounts Without Passwords",
                    f"Users with empty/locked passwords: {', '.join(weak_accounts[:10])}",
                    Severity.CRITICAL,
                    self.category,
                    remediation="Set strong passwords or disable unused accounts",
                    evidence={"accounts": weak_accounts[:20]},
                    detection_command="cat /etc/shadow",
                    confidence="high",
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    affected_asset="/etc/shadow",
                    timestamp=now,
                    technical_detail=(
                        "One or more local accounts have empty or locked password "
                        "hashes in /etc/shadow. Accounts with empty password fields "
                        "can be accessed without any credential, while locked accounts "
                        "may indicate orphaned users that should be removed."
                    ),
                    business_impact=(
                        "Accounts without passwords provide trivial entry points for "
                        "attackers, enabling full system compromise including data "
                        "exfiltration, lateral movement, and privilege escalation."
                    ),
                    remediation_steps=[
                        "Assign strong passwords to all active accounts: passwd <username>",
                        "Lock or disable unused accounts: usermod -L <username>",
                        "Remove orphaned accounts: userdel <username>",
                        "Enforce password-required policy in PAM configuration.",
                    ],
                    verification_command="awk -F: '($2 == \"\" || $2 == \"!\" || $2 == \"!!\" || $2 == \"*\") {print $1}' /etc/shadow",
                )
            )

        if not findings:
            findings.append(
                pass_finding(
                    self.check_id,
                    self.title,
                    "Password policy baseline satisfied",
                    self.category,
                    timestamp=now,
                    detection_command="cat /etc/login.defs | grep PASS_MIN_LEN",
                    confidence="high",
                    affected_asset="/etc/login.defs",
                )
            )
        return findings

    def _check_macos(self) -> List[Finding]:
        now = datetime.now(timezone.utc).isoformat()
        _, stdout, _ = run_command(["pwpolicy", "getaccountpolicies"])
        if "minimumLength" in stdout:
            return [
                pass_finding(
                    self.check_id,
                    self.title,
                    "macOS password policy configured",
                    self.category,
                    evidence={"policy": stdout[:200]},
                    timestamp=now,
                    detection_command="pwpolicy getaccountpolicies",
                    confidence="high",
                    affected_asset="pwpolicy",
                )
            ]
        return [
            warn_finding(
                self.check_id,
                "macOS Password Policy",
                "Could not verify password complexity policy",
                Severity.LOW,
                self.category,
                detection_command="pwpolicy getaccountpolicies",
                confidence="medium",
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                affected_asset="pwpolicy",
                timestamp=now,
                technical_detail=(
                    "The pwpolicy getaccountpolicies command did not return a "
                    "minimumLength constraint. This may indicate that no password "
                    "complexity policy has been enforced via configuration profile "
                    "or Open Directory, leaving accounts vulnerable to weak passwords."
                ),
                business_impact=(
                    "Without enforced password complexity, users may set trivially "
                    "guessable passwords, increasing the risk of unauthorized access "
                    "to the macOS system and any data it stores."
                ),
                remediation="Configure password complexity via MDM profile or pwpolicy",
                remediation_steps=[
                    "Deploy a configuration profile enforcing minLength via MDM.",
                    "Alternatively, use 'pwpolicy setaccountpolicies' to set local policy.",
                    "Verify the policy is active: pwpolicy getaccountpolicies",
                ],
                verification_command="pwpolicy getaccountpolicies | grep minimumLength",
            )
        ]

    def _check_windows(self) -> List[Finding]:
        now = datetime.now(timezone.utc).isoformat()
        _, stdout, _ = run_command(["net", "accounts"])
        if "Minimum password length" in stdout:
            return [
                pass_finding(
                    self.check_id,
                    self.title,
                    "Windows password policy retrieved",
                    self.category,
                    evidence={"policy": stdout[:300]},
                    timestamp=now,
                    detection_command="net accounts",
                    confidence="high",
                    affected_asset="Local Security Policy",
                )
            ]
        return [self.error_finding("Unable to read Windows password policy")]
