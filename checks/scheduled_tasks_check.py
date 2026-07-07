"""Scheduled tasks and startup services auditing."""

from __future__ import annotations

import os
import platform
from datetime import datetime, timezone
from typing import List

from core.base_check import BaseCheck
from core.models import Finding, Severity
from checks.helpers import fail_finding, pass_finding, warn_finding
from utils.command import command_exists, run_command


class ScheduledTasksCheck(BaseCheck):
    check_id = "scheduled_tasks"
    title = "Scheduled Tasks"
    category = "persistence"
    supported_platforms = ("linux", "darwin", "windows")

    SUSPICIOUS_PATTERNS = [
        "/tmp/", "curl |", "wget |", "bash -c", "powershell -enc",
        "python -c", "/dev/tcp/", "nc -e",
    ]

    def run(self) -> List[Finding]:
        system = platform.system().lower()
        if system == "linux":
            return self._linux()
        if system == "darwin":
            return self._macos()
        if system == "windows":
            return self._windows()
        return [self.skip_finding("Unsupported platform")]

    def _linux(self) -> List[Finding]:
        entries: List[str] = []

        _, stdout, _ = run_command(["cat", "/etc/crontab"], use_sudo=True)
        entries.extend(stdout.splitlines())

        _, user_crontab, _ = run_command(["crontab", "-l"])
        entries.extend(user_crontab.splitlines())

        if command_exists("systemctl"):
            _, stdout, _ = run_command(["systemctl", "list-timers", "--all"])
            entries.extend(stdout.splitlines())

        suspicious = [
            e for e in entries
            if any(p in e.lower() for p in self.SUSPICIOUS_PATTERNS)
        ]
        if suspicious:
            return [
                fail_finding(
                    self.check_id,
                    "Suspicious Scheduled Tasks",
                    "Cron/systemd timers contain potentially malicious commands",
                    Severity.HIGH,
                    self.category,
                    remediation="Review and remove unauthorized scheduled tasks",
                    evidence={"entries": suspicious[:10]},
                    detection_command="crontab -l",
                    confidence="high",
                    cvss_score=7.2,
                    cvss_vector="CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
                    affected_asset="cron/systemd-timers",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    technical_detail=(
                        "Scheduled task entries matched known malicious patterns "
                        "such as reverse shells, remote code download, or execution "
                        "from world-writable directories."
                    ),
                    business_impact=(
                        "Malicious scheduled tasks can provide persistent backdoor "
                        "access, exfiltrate data, or pivot to other hosts."
                    ),
                    remediation_steps=[
                        "Run 'crontab -l' and 'cat /etc/crontab' to list all cron entries",
                        "Identify unauthorized or obfuscated commands",
                        "Remove suspicious entries with 'crontab -e'",
                        "Check /var/spool/cron/ for per-user crontabs",
                        "Review systemd timers with 'systemctl list-timers --all'",
                    ],
                    verification_command="crontab -l && systemctl list-timers --all",
                )
            ]
        return [
            pass_finding(
                self.check_id,
                self.title,
                f"Reviewed {len(entries)} scheduled task entries",
                self.category,
                detection_command="crontab -l",
                confidence="high",
                affected_asset="cron/systemd-timers",
                timestamp=datetime.now(timezone.utc).isoformat(),
                technical_detail=(
                    f"Scanned {len(entries)} cron and systemd timer entries; "
                    "no known malicious patterns detected."
                ),
            )
        ]

    def _macos(self) -> List[Finding]:
        _, stdout, _ = run_command(["launchctl", "list"])
        count = len(stdout.splitlines())
        return [
            pass_finding(
                self.check_id,
                self.title,
                f"Enumerated {count} launchd jobs",
                self.category,
                detection_command="launchctl list",
                confidence="high",
                affected_asset="launchd-jobs",
                timestamp=datetime.now(timezone.utc).isoformat(),
                technical_detail=(
                    f"Listed {count} launchd jobs via launchctl; "
                    "manual review recommended for third-party agents."
                ),
            )
        ]

    def _windows(self) -> List[Finding]:
        _, stdout, _ = run_command(["schtasks", "/query", "/fo", "LIST"])
        suspicious = [
            l for l in stdout.splitlines()
            if any(p.lower() in l.lower() for p in self.SUSPICIOUS_PATTERNS)
        ]
        if suspicious:
            return [
                warn_finding(
                    self.check_id,
                    "Review Windows Scheduled Tasks",
                    "Potentially suspicious task entries detected",
                    Severity.MEDIUM,
                    self.category,
                    evidence={"entries": suspicious[:5]},
                    detection_command="schtasks /query /fo LIST",
                    confidence="medium",
                    cvss_score=7.2,
                    cvss_vector="CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
                    affected_asset="windows-scheduled-tasks",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    technical_detail=(
                        "Windows Task Scheduler entries matched known suspicious "
                        "patterns including encoded PowerShell or remote download commands."
                    ),
                    business_impact=(
                        "Malicious scheduled tasks can survive reboots and provide "
                        "persistent attacker access to the host."
                    ),
                    remediation_steps=[
                        "Run 'schtasks /query /fo LIST /v' to review all tasks",
                        "Identify tasks with suspicious commands or unknown authors",
                        "Delete unauthorized tasks with 'schtasks /delete /tn <name>'",
                    ],
                    verification_command="schtasks /query /fo LIST /v",
                )
            ]
        return [
            pass_finding(
                self.check_id,
                self.title,
                "Windows scheduled tasks enumerated",
                self.category,
                detection_command="schtasks /query /fo LIST",
                confidence="high",
                affected_asset="windows-scheduled-tasks",
                timestamp=datetime.now(timezone.utc).isoformat(),
                technical_detail=(
                    "All Windows scheduled tasks enumerated; "
                    "no suspicious patterns detected."
                ),
            )
        ]


class StartupServicesCheck(BaseCheck):
    check_id = "startup_services"
    title = "Startup Services"
    category = "persistence"
    supported_platforms = ("linux", "darwin", "windows")

    def run(self) -> List[Finding]:
        system = platform.system().lower()
        startup_items: List[str] = []

        if system == "linux":
            for path in ["/etc/rc.local", "/etc/init.d"]:
                _, out, _ = run_command(["ls", path])
                startup_items.extend(out.splitlines())
            _, out, _ = run_command(
                ["systemctl", "list-unit-files", "--type=service", "--state=enabled"]
            )
            startup_items.extend(
                l.split()[0] for l in out.splitlines() if "enabled" in l
            )
        elif system == "darwin":
            for path in [
                "/Library/LaunchDaemons",
                "/Library/LaunchAgents",
                os.path.expanduser("~/Library/LaunchAgents"),
            ]:
                if os.path.isdir(path):
                    startup_items.extend(os.listdir(path))
        elif system == "windows":
            _, out, _ = run_command(
                ["wmic", "startup", "get", "caption,command"]
            )
            startup_items = out.splitlines()

        return [
            pass_finding(
                self.check_id,
                self.title,
                f"{len(startup_items)} startup/persistence items enumerated",
                self.category,
                evidence={"count": len(startup_items), "sample": startup_items[:10]},
                detection_command="ls /Library/LaunchDaemons",
                confidence="high",
                affected_asset="startup-services",
                timestamp=datetime.now(timezone.utc).isoformat(),
                technical_detail=(
                    f"Enumerated {len(startup_items)} startup/persistence items "
                    "across system launch daemons, agents, and init scripts."
                ),
            )
        ]
