"""Unused account and user privilege auditing."""

from __future__ import annotations

import platform
from datetime import datetime, timezone
from typing import Any, Dict, List

from core.base_check import BaseCheck
from core.models import Finding, Severity
from checks.helpers import fail_finding, pass_finding, warn_finding
from utils.command import command_exists, run_command


class UnusedAccountsCheck(BaseCheck):
    check_id = "unused_accounts"
    title = "Unused User Accounts"
    category = "authentication"
    supported_platforms = ("linux", "darwin")

    def __init__(self, config: Dict[str, Any] | None = None):
        self.days = (config or {}).get("unused_account_days", 90)

    def run(self) -> List[Finding]:
        if platform.system().lower() == "darwin":
            return [self.skip_finding("lastlog not standard on macOS")]

        if not command_exists("lastlog"):
            return [self.skip_finding("lastlog command not available")]

        _, stdout, _ = run_command(["lastlog", "-b", str(self.days)])
        stale = [
            l.split()[0]
            for l in stdout.splitlines()
            if "Never logged in" in l or "**Never logged in**" in l
        ]
        stale = [u for u in stale if u and u != "Username"]

        if stale:
            return [
                warn_finding(
                    self.check_id,
                    "Stale User Accounts",
                    f"{len(stale)} accounts inactive {self.days}+ days or never logged in",
                    Severity.MEDIUM,
                    self.category,
                    remediation="Disable or remove unused accounts",
                    evidence={"accounts": stale[:20]},
                    detection_command=f"lastlog -b {self.days}",
                    confidence="high",
                    cvss_score=4.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
                    affected_asset=", ".join(stale[:20]),
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    technical_detail=(
                        f"lastlog reports {len(stale)} accounts that have not "
                        f"authenticated within {self.days} days or have never "
                        f"logged in. Dormant accounts expand the attack surface."
                    ),
                    business_impact=(
                        "Stale accounts may be compromised without detection, "
                        "providing lateral-movement opportunities for attackers."
                    ),
                    remediation_steps=[
                        f"Review each account: lastlog -u <user>",
                        "Lock dormant accounts: usermod -L <user>",
                        "Set expiry: chage -E $(date -d '+30 days' +%Y-%m-%d) <user>",
                        "Remove accounts confirmed unnecessary: userdel -r <user>",
                    ],
                    verification_command=f"lastlog -b {self.days} | grep -v 'Never logged in'",
                )
            ]
        return [
            pass_finding(
                self.check_id,
                self.title,
                f"No stale accounts detected ({self.days}-day threshold)",
                self.category,
                detection_command=f"lastlog -b {self.days}",
                confidence="high",
                timestamp=datetime.now(timezone.utc).isoformat(),
                technical_detail=(
                    f"All accounts have authenticated within the last "
                    f"{self.days} days — no dormant accounts found."
                ),
            )
        ]


class UserPrivilegeCheck(BaseCheck):
    check_id = "user_privileges"
    title = "User Privilege Audit"
    category = "authentication"
    supported_platforms = ("linux", "darwin")

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        _, passwd, _ = run_command(["cat", "/etc/passwd"], use_sudo=True)
        uid_zero = [l.split(":")[0] for l in passwd.splitlines() if l.startswith("root:") is False and l.split(":")[2] == "0"]
        if uid_zero:
            findings.append(
                fail_finding(
                    self.check_id,
                    "Non-Root UID 0 Accounts",
                    f"Accounts with root privileges: {uid_zero}",
                    Severity.CRITICAL,
                    self.category,
                    remediation="Remove UID 0 from non-root accounts immediately",
                    evidence={"accounts": uid_zero},
                    detection_command="awk -F: '$3 == 0 && $1 != \"root\"' /etc/passwd",
                    confidence="high",
                    cvss_score=8.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                    affected_asset=", ".join(uid_zero),
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    technical_detail=(
                        f"Non-root accounts {uid_zero} have UID 0 in /etc/passwd, "
                        f"granting unrestricted superuser privileges identical to root."
                    ),
                    business_impact=(
                        "A compromised UID-0 account gives an attacker full "
                        "system control with no additional escalation required."
                    ),
                    remediation_steps=[
                        "Verify each account's purpose with system owners",
                        "Assign a unique non-zero UID: usermod -u <new_uid> <user>",
                        "Grant targeted privileges via sudoers instead of UID 0",
                        "Audit /etc/passwd to confirm no other UID-0 duplicates remain",
                    ],
                    verification_command="awk -F: '$3 == 0' /etc/passwd",
                )
            )

        if command_exists("getent"):
            _, sudoers, _ = run_command(["getent", "group", "sudo"])
            if sudoers:
                members = sudoers.split(":")[-1].strip()
                if members:
                    member_list = [m.strip() for m in members.split(",") if m.strip()]
                    if len(member_list) > 5:
                        findings.append(
                            warn_finding(
                                self.check_id,
                                "Large Sudo Group",
                                f"{len(member_list)} users in sudo group",
                                Severity.MEDIUM,
                                self.category,
                                remediation="Apply least privilege; use granular sudoers rules",
                                evidence={"sudo_members": member_list},
                                detection_command="getent group sudo",
                                confidence="high",
                                cvss_score=5.3,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                affected_asset="sudo group",
                                timestamp=datetime.now(timezone.utc).isoformat(),
                                technical_detail=(
                                    f"The sudo/admin group contains {len(member_list)} "
                                    f"members ({', '.join(member_list)}), exceeding the "
                                    f"recommended maximum of 5. Over-provisioned "
                                    f"administrative groups weaken least-privilege controls."
                                ),
                                business_impact=(
                                    "Excessive sudo membership increases the blast radius "
                                    "of credential compromise and complicates access auditing."
                                ),
                                remediation_steps=[
                                    "Audit each member's need for sudo access",
                                    "Remove unnecessary members: gpasswd -d <user> sudo",
                                    "Create role-specific sudoers rules in /etc/sudoers.d/",
                                    "Enforce MFA or ticket-based privilege escalation",
                                ],
                                verification_command="getent group sudo | awk -F: '{print $4}'",
                            )
                        )

        _, sudoers_file, _ = run_command(["cat", "/etc/sudoers"], use_sudo=True)
        if "NOPASSWD" in sudoers_file:
            findings.append(
                fail_finding(
                    self.check_id,
                    "Passwordless Sudo Configured",
                    "NOPASSWD entries found in /etc/sudoers",
                    Severity.HIGH,
                    self.category,
                    remediation="Remove NOPASSWD unless strictly required",
                    references=["CIS 4.4 — Ensure sudo commands require authentication"],
                    detection_command="grep -i NOPASSWD /etc/sudoers /etc/sudoers.d/*",
                    confidence="high",
                    cvss_score=7.8,
                    cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                    affected_asset="/etc/sudoers",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    technical_detail=(
                        "The /etc/sudoers file contains NOPASSWD directives, "
                        "allowing privileged command execution without "
                        "re-authenticating. This negates password-based access "
                        "control for lateral-movement scenarios."
                    ),
                    business_impact=(
                        "An attacker who compromises a user session can escalate "
                        "to root without knowing the user's password, drastically "
                        "reducing the cost of privilege escalation."
                    ),
                    remediation_steps=[
                        "Identify NOPASSWD lines: grep -n NOPASSWD /etc/sudoers",
                        "Remove or restrict NOPASSWD to specific, low-risk commands",
                        "Use visudo to safely edit /etc/sudoers",
                        "Consider timestamp_timeout tuning as an alternative",
                    ],
                    verification_command="grep -ci NOPASSWD /etc/sudoers",
                )
            )

        if not findings:
            findings.append(
                pass_finding(
                    self.check_id,
                    self.title,
                    "User privilege configuration within baseline",
                    self.category,
                    detection_command="awk -F: '$3 == 0' /etc/passwd && grep NOPASSWD /etc/sudoers",
                    confidence="high",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    technical_detail=(
                        "No UID-0 duplicates, no NOPASSWD directives, and the "
                        "sudo group membership is within acceptable limits."
                    ),
                )
            )
        return findings


