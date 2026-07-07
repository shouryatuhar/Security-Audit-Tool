"""Suspicious process and running services audit."""

from __future__ import annotations

import platform as _platform
from datetime import datetime, timezone
from typing import Dict, List, Optional

from core.base_check import BaseCheck
from core.models import Finding, Severity
from checks.helpers import fail_finding, pass_finding, warn_finding
from utils.command import run_command

_BEHAVIORAL_SIGS: Dict[str, str] = {
    "reverse_shell_bash": r"/dev/tcp/|/dev/udp/",
    "reverse_shell_nc": r"nc\s+.*-e\s+(/bin/sh|/bin/bash|cmd\.exe)|netcat\s+.*-e",
    "reverse_shell_python": r"python\s*-c\s*['\"].*import\s+socket.*subprocess",
    "reverse_shell_perl": r"perl\s*-e\s*['\"].*Socket",
    "reverse_shell_php": r"php\s*-r\s*['\"].*fsockopen",
    "reverse_shell_ruby": r"ruby\s*-rsocket\s*-e",
    "obfuscated_powershell": r"powershell.*-(enc|encodedcommand|w\s+hidden|nop)",
    "credential_dumping": r"mimikatz|procdump.*lsass|seclogon",
    "crypto_mining": r"minerd|xmrig|cryptonight|stratum\+tcp",
}

class SuspiciousProcessesCheck(BaseCheck):
    check_id = "suspicious_processes"
    title = "Suspicious Process Behaviors"
    category = "malware"
    supported_platforms = ("linux", "darwin", "windows")

    def run(self) -> List[Finding]:
        import re
        now = datetime.now(timezone.utc).isoformat()
        pids_by_behavior: Dict[str, List[int]] = {}
        suspicious_found = {}

        try:
            import psutil
            det_cmd = "psutil.process_iter()"
            for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                try:
                    cmdline = proc.info.get("cmdline") or []
                    if not cmdline:
                        continue
                    pcmd = " ".join(cmdline).lower()
                    
                    for sig_name, pattern in _BEHAVIORAL_SIGS.items():
                        if re.search(pattern, pcmd):
                            suspicious_found[sig_name] = f"Matches behavioral signature: {sig_name}"
                            pids_by_behavior.setdefault(sig_name, []).append(proc.info["pid"])
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
        except ImportError:
            det_cmd = "ps aux"
            _, stdout, _ = run_command(["ps", "aux"])
            for line in stdout.splitlines()[1:]:
                parts = line.split(None, 10)
                if len(parts) > 10:
                    pid_str = parts[1]
                    pcmd = parts[10].lower()
                    
                    for sig_name, pattern in _BEHAVIORAL_SIGS.items():
                        if re.search(pattern, pcmd):
                            suspicious_found[sig_name] = f"Matches behavioral signature: {sig_name}"
                            if pid_str.isdigit():
                                pids_by_behavior.setdefault(sig_name, []).append(int(pid_str))

        if suspicious_found:
            detail_parts = []
            for sig_name, reason in suspicious_found.items():
                pid_list = pids_by_behavior.get(sig_name, [])
                pid_str = f" (PIDs: {', '.join(map(str, pid_list))})" if pid_list else ""
                detail_parts.append(f"• {sig_name}{pid_str}: {reason}")
            
            technical = "\n".join(detail_parts)
            
            first_pid: Optional[int] = None
            for plist in pids_by_behavior.values():
                if plist:
                    first_pid = plist[0]
                    break
                    
            found_list = list(suspicious_found.keys())

            return [
                fail_finding(
                    self.check_id,
                    "Suspicious Process Behaviors Detected",
                    f"Malicious behaviors identified: {', '.join(found_list)}",
                    Severity.CRITICAL,
                    self.category,
                    remediation="Investigate and terminate unauthorized processes",
                    evidence={"behaviors": found_list, "pids": pids_by_behavior},
                    detection_command=det_cmd,
                    confidence="high",
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    affected_asset=", ".join(found_list),
                    pid=first_pid,
                    timestamp=now,
                    technical_detail=technical,
                    business_impact=(
                        "Active malicious behaviors indicate an ongoing compromise. "
                        "Attackers may exfiltrate sensitive data, install persistent "
                        "backdoors, or consume resources for unauthorized mining."
                    ),
                    remediation_steps=[
                        "Identify the parent process tree: ps -ef --forest",
                        "Capture a memory dump for forensic analysis if needed",
                        "Terminate the process: kill -9 <PID>",
                        "Search for persistence mechanisms (cron, systemd, rc.local)",
                    ],
                    verification_command="ps aux | grep -iE '" + "|".join(_BEHAVIORAL_SIGS.values()) + "'",
                    references=["MITRE ATT&CK T1059: Command and Scripting Interpreter"],
                )
            ]
            
        return [
            pass_finding(
                self.check_id,
                self.title,
                "No known suspicious processes detected",
                self.category,
                detection_command=det_cmd,
                confidence="high",
                timestamp=now,
                technical_detail="Process list scanned against known malicious signatures; no matches found.",
                references=["MITRE ATT&CK T1059", "CIS Control 8: Malware Defenses"],
            )
        ]


class RunningServicesCheck(BaseCheck):
    check_id = "running_services"
    title = "Running Services"
    category = "services"
    supported_platforms = ("linux", "darwin", "windows")

    RISKY_SERVICES = ["telnet", "rsh", "rlogin", "ftp", "tftp"]

    def run(self) -> List[Finding]:
        now = datetime.now(timezone.utc).isoformat()
        system = _platform.system().lower()
        det_cmd = (
            "launchctl list" if system == "darwin"
            else "systemctl list-units --type=service --state=running" if system == "linux"
            else "sc query type= service state= all"
        )
        ver_cmd = det_cmd + " | grep -iE '" + "|".join(self.RISKY_SERVICES) + "'"

        services = self._list_services()
        risky = [s for s in services if any(r in s.lower() for r in self.RISKY_SERVICES)]

        findings: List[Finding] = []
        if risky:
            findings.append(
                fail_finding(
                    self.check_id,
                    "Insecure Services Running",
                    f"Legacy/insecure services detected: {risky}",
                    Severity.HIGH,
                    self.category,
                    remediation="Disable telnet/rsh/ftp and use SSH/SFTP",
                    evidence={"risky_services": risky},
                    detection_command=det_cmd,
                    confidence="high",
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    affected_asset=", ".join(risky),
                    timestamp=now,
                    technical_detail=(
                        "The following insecure services transmit credentials and data "
                        "in cleartext, exposing them to network sniffing and MITM attacks: "
                        + ", ".join(risky) + "."
                    ),
                    business_impact=(
                        "Cleartext services allow attackers on the network segment to "
                        "intercept credentials and sensitive data, potentially leading to "
                        "full system compromise."
                    ),
                    remediation_steps=[
                        "Identify dependent users/processes for each insecure service",
                        "Migrate to encrypted alternatives (SSH, SFTP, SCP)",
                        "Disable insecure services: systemctl disable --now <service>",
                        "Block insecure service ports at the host firewall",
                        "Verify no listeners remain on legacy ports",
                    ],
                    verification_command=ver_cmd,
                )
            )

        findings.append(
            pass_finding(
                self.check_id,
                self.title,
                f"{len(services)} services enumerated",
                self.category,
                evidence={"count": len(services), "sample": services[:15]},
                detection_command=det_cmd,
                confidence="high",
                timestamp=now,
                technical_detail=(
                    f"Enumerated {len(services)} running services; "
                    f"none matched the insecure-service watchlist."
                ) if not risky else (
                    f"Enumerated {len(services)} running services in total."
                ),
            )
        )
        return findings

    def _list_services(self) -> List[str]:
        import platform

        system = platform.system().lower()
        if system == "linux":
            _, stdout, _ = run_command(["systemctl", "list-units", "--type=service", "--state=running"])
            return [
                l.split()[0]
                for l in stdout.splitlines()
                if ".service" in l and "loaded" in l
            ]
        if system == "darwin":
            _, stdout, _ = run_command(["launchctl", "list"])
            # Filter out com.apple.* system services to reduce false positives
            services = []
            for l in stdout.splitlines()[1:]:
                parts = l.split()
                if len(parts) >= 3:
                    name = parts[2]
                    if not name.startswith("com.apple."):
                        services.append(name)
            return services
        if system == "windows":
            _, stdout, _ = run_command(["sc", "query", "type=", "service", "state=", "all"])
            return [l.split(":")[1].strip() for l in stdout.splitlines() if "SERVICE_NAME" in l]
        return []
