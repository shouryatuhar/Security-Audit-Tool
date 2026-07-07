"""Check registry and factory."""

from __future__ import annotations

from typing import Any, Dict, List

from core.base_check import BaseCheck
from checks.ssh_check import SSHCheck
from checks.firewall_check import FirewallCheck
from checks.password_check import PasswordPolicyCheck
from checks.check_open_ports import OpenPortsCheck, PortScanCheck
from checks.outdated_packages_check import OutdatedPackagesCheck, PackageInventoryCheck
from checks.running_processes_check import SuspiciousProcessesCheck, RunningServicesCheck
from checks.check_rootkits import RootkitCheck
from checks.check_unused_accounts import UnusedAccountsCheck, UserPrivilegeCheck
from checks.check_file_integrity import FileIntegrityCheck, FilePermissionsCheck
from checks.scheduled_tasks_check import ScheduledTasksCheck, StartupServicesCheck
from checks.dangerous_config_check import DangerousConfigCheck


def build_checks(config: Dict[str, Any] | None = None) -> List[BaseCheck]:
    """Instantiate all audit checks with optional config injection."""
    cfg = config or {}
    skip = set(cfg.get("checks", {}).get("skip", []))

    checks: List[BaseCheck] = [
        SSHCheck(),
        FirewallCheck(),
        PasswordPolicyCheck(cfg.get("password_policy")),
        OpenPortsCheck(cfg.get("port_scan")),
        PortScanCheck(),
        OutdatedPackagesCheck(),
        PackageInventoryCheck(),
        SuspiciousProcessesCheck(),
        RunningServicesCheck(),
        RootkitCheck(),
        UnusedAccountsCheck(cfg),
        UserPrivilegeCheck(),
        FileIntegrityCheck(),
        FilePermissionsCheck(cfg.get("file_permissions")),
        ScheduledTasksCheck(),
        StartupServicesCheck(),
        DangerousConfigCheck(),
    ]

    return [c for c in checks if c.check_id not in skip]
