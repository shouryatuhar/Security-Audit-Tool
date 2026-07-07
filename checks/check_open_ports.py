"""Open port and network exposure audit."""

from __future__ import annotations

import platform
import re
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Set, Tuple

from core.base_check import BaseCheck
from core.models import Finding, Severity
from checks.helpers import fail_finding, pass_finding, warn_finding
from utils.command import command_exists, run_command


class OpenPortsCheck(BaseCheck):
    check_id = "open_ports"
    title = "Open Ports"
    category = "network"
    supported_platforms = ("linux", "darwin", "windows")

    def __init__(self, config: Dict[str, Any] | None = None):
        self.config = config or {}
        self.risky_ports = set(
            self.config.get(
                "risky_ports",
                [21, 23, 135, 139, 445, 3389, 5900, 6379, 27017],
            )
        )

    def run(self) -> List[Finding]:
        port_info = self._collect_listening_ports()
        ports = set(port_info.keys())
        now = datetime.now(timezone.utc).isoformat()

        # Determine what detection command was used
        if command_exists("ss"):
            det_cmd = "ss -tuln"
        elif command_exists("netstat"):
            det_cmd = "netstat -tuln"
        else:
            det_cmd = "psutil.net_connections(kind='inet')"

        if not ports:
            return [
                pass_finding(
                    self.check_id,
                    self.title,
                    "No unexpected listening ports detected",
                    self.category,
                    detection_command=det_cmd,
                    confidence="high",
                    timestamp=now,
                    technical_detail="Enumerated all listening TCP/UDP sockets; none found.",
                    affected_asset="network",
                )
            ]

        risky = sorted(p for p in ports if p in self.risky_ports)
        risky_external = []
        risky_local = []
        
        for p in risky:
            iface = port_info[p].get("interface", f"0.0.0.0:{p}")
            if "127.0.0.1" in iface or "[::1]" in iface or "::1" in iface or "localhost" in iface:
                risky_local.append(p)
            else:
                risky_external.append(p)
                
        findings: List[Finding] = []

        if risky_external:
            interfaces = [port_info[p].get("interface", f"0.0.0.0:{p}") for p in risky_external]
            pids = [port_info[p].get("pid") for p in risky_external if port_info[p].get("pid")]
            details = [f"Port {p} ({port_info[p].get('process_name', 'unknown')} as {port_info[p].get('user', 'unknown')})" for p in risky_external]

            findings.append(
                fail_finding(
                    self.check_id,
                    "Risky Ports Exposed Externally",
                    f"High-risk ports listening on public interfaces: {risky_external}",
                    Severity.HIGH,
                    self.category,
                    remediation="Close or firewall risky services; verify business need",
                    evidence={"risky_ports": risky_external, "port_details": port_info},
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                    detection_command=det_cmd,
                    confidence="high",
                    listening_interface=", ".join(interfaces),
                    pid=pids[0] if pids else None,
                    timestamp=now,
                    affected_asset="network",
                    technical_detail=(
                        f"Detected {len(risky_external)} high-risk port(s) bound to external interfaces: "
                        f"{', '.join(details)}. These services are commonly targeted by attackers "
                        "and are exposed to the network."
                    ),
                    business_impact=(
                        "Exposed risky services increase the probability of "
                        "unauthorized access, lateral movement, or data exfiltration."
                    ),
                    remediation_steps=[
                        "Identify the process bound to each risky port using `ss -tlnp` or `lsof -i`.",
                        "Disable or stop unnecessary services.",
                        "Apply host-firewall rules (iptables/nftables/pf) to restrict access.",
                        "Re-run this check to confirm remediation.",
                    ],
                    verification_command="ss -tuln | grep -E ':({})\\s'".format(
                        "|".join(str(p) for p in risky_external)
                    ),
                    references=["CIS Control 9: Email and Web Browser Protections (Network Ports)", "MITRE ATT&CK T1190: Exploit Public-Facing Application"],
                )
            )

        if risky_local:
            interfaces = [port_info[p].get("interface", f"127.0.0.1:{p}") for p in risky_local]
            pids = [port_info[p].get("pid") for p in risky_local if port_info[p].get("pid")]
            details = [f"Port {p} ({port_info[p].get('process_name', 'unknown')} as {port_info[p].get('user', 'unknown')})" for p in risky_local]

            findings.append(
                warn_finding(
                    self.check_id,
                    "Risky Ports Bound to Localhost",
                    f"High-risk ports listening on loopback: {risky_local}",
                    Severity.LOW,
                    self.category,
                    remediation="Ensure local services do not trust unauthenticated local users",
                    evidence={"risky_ports": risky_local, "port_details": port_info},
                    cvss_score=3.1,
                    cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    detection_command=det_cmd,
                    confidence="high",
                    listening_interface=", ".join(interfaces),
                    pid=pids[0] if pids else None,
                    timestamp=now,
                    affected_asset="network-localhost",
                    technical_detail=(
                        f"Detected {len(risky_local)} high-risk port(s) bound to localhost (127.0.0.1): "
                        f"{', '.join(details)}. While not externally exposed, these "
                        "services could be exploited via Server-Side Request Forgery (SSRF) or by local attackers."
                    ),
                    business_impact=(
                        "Locally bound services reduce the attack surface but can still be "
                        "leveraged by malware or compromised unprivileged accounts for privilege escalation."
                    ),
                    remediation_steps=[
                        "Review if the service is actually required.",
                        "Ensure the local service requires authentication.",
                    ],
                    verification_command="ss -tuln | grep -E '127.0.0.1:({})\\s'".format(
                        "|".join(str(p) for p in risky_local)
                    ),
                    references=["MITRE ATT&CK T1068: Exploitation for Privilege Escalation"],
                )
            )

        if len(ports) > 20:
            findings.append(
                warn_finding(
                    self.check_id,
                    "Large Attack Surface",
                    f"{len(ports)} listening ports detected — review necessity",
                    Severity.MEDIUM,
                    self.category,
                    evidence={"port_count": len(ports)},
                    cvss_score=3.1,
                    cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    detection_command=det_cmd,
                    confidence="medium",
                    timestamp=now,
                    affected_asset="network",
                    technical_detail=(
                        f"The host has {len(ports)} listening ports, which significantly "
                        "increases the attack surface. Each port is a potential entry point."
                    ),
                    business_impact=(
                        "A large number of open ports complicates hardening and "
                        "increases the likelihood of an exploitable misconfiguration."
                    ),
                    remediation_steps=[
                        "Audit every listening port with `ss -tlnp` and disable unneeded services.",
                        "Apply the principle of least privilege to network exposure.",
                    ],
                    verification_command="ss -tuln | wc -l",
                )
            )

        if not findings:
            findings.append(
                pass_finding(
                    self.check_id,
                    self.title,
                    f"{len(ports)} listening ports; none in risky list",
                    self.category,
                    evidence={"ports": sorted(ports)},
                    detection_command=det_cmd,
                    confidence="high",
                    timestamp=now,
                    affected_asset="network",
                    technical_detail=(
                        f"Found {len(ports)} listening port(s); none match the "
                        f"configured risky-port list ({sorted(self.risky_ports)})."
                    ),
                )
            )
        return findings

    def _collect_listening_ports(self) -> Dict[int, Dict[str, Any]]:
        """Return {port: {"interface": "addr:port", "pid": int|None, ...}} for listening ports."""
        info: Dict[int, Dict[str, Any]] = {}

        if command_exists("ss"):
            _, stdout, _ = run_command(["ss", "-tulnp"])
            info.update(self._parse_ss_output(stdout))
        elif command_exists("netstat"):
            _, stdout, _ = run_command(["netstat", "-tulnp"])
            info.update(self._parse_netstat_output(stdout))
        else:
            info.update(self._psutil_ports())

        # Enrich with psutil if available
        try:
            import psutil
            for port, data in info.items():
                pid = data.get("pid")
                if pid:
                    try:
                        p = psutil.Process(pid)
                        data["process_name"] = p.name()
                        data["exe_path"] = p.exe()
                        data["user"] = p.username()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
        except ImportError:
            pass

        return info

    def _parse_ss_output(self, text: str) -> Dict[int, Dict[str, Any]]:
        info: Dict[int, Dict[str, Any]] = {}
        for line in text.splitlines():
            addr_match = re.search(r'(\S+):(\d+)\s', line)
            if addr_match:
                addr = addr_match.group(1)
                port = int(addr_match.group(2))
                pid_match = re.search(r'pid=(\d+)', line)
                pid = int(pid_match.group(1)) if pid_match else None
                info[port] = {
                    "interface": f"{addr}:{port}",
                    "pid": pid,
                }
        return info

    def _parse_netstat_output(self, text: str) -> Dict[int, Dict[str, Any]]:
        info: Dict[int, Dict[str, Any]] = {}
        for line in text.splitlines():
            if "LISTEN" in line or "listening" in line.lower():
                parts = line.split()
                for part in parts:
                    if ":" in part:
                        try:
                            port = int(part.rsplit(":", 1)[-1])
                            addr = part.rsplit(":", 1)[0]
                            pid = None
                            for p in parts:
                                if "/" in p:
                                    try:
                                        pid = int(p.split("/")[0])
                                    except ValueError:
                                        pass
                            info[port] = {
                                "interface": f"{addr}:{port}",
                                "pid": pid,
                            }
                        except ValueError:
                            pass
        return info

    def _psutil_ports(self) -> Dict[int, Dict[str, Any]]:
        try:
            import psutil

            info: Dict[int, Dict[str, Any]] = {}
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "LISTEN" and conn.laddr:
                    info[conn.laddr.port] = {
                        "interface": f"{conn.laddr.ip}:{conn.laddr.port}",
                        "pid": conn.pid,
                    }
            return info
        except Exception:
            return {}


class PortScanCheck(BaseCheck):
    """Localhost port scan integration — lightweight nmap-style check."""

    check_id = "port_scan"
    title = "Local Port Scan"
    category = "network"
    supported_platforms = ("linux", "darwin", "windows")

    COMMON_PORTS = [22, 80, 443, 445, 3306, 5432, 8080, 8443]

    def run(self) -> List[Finding]:
        now = datetime.now(timezone.utc).isoformat()
        open_ports: List[int] = []
        for port in self.COMMON_PORTS:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            try:
                if sock.connect_ex(("127.0.0.1", port)) == 0:
                    open_ports.append(port)
            except OSError:
                pass
            finally:
                sock.close()

        if not open_ports:
            return [
                pass_finding(
                    self.check_id,
                    self.title,
                    "No common ports open on localhost",
                    self.category,
                    detection_command="socket connect to 127.0.0.1:<common_ports>",
                    confidence="high",
                    timestamp=now,
                    affected_asset="localhost",
                    technical_detail=(
                        f"Attempted TCP connections to {len(self.COMMON_PORTS)} "
                        "common ports on 127.0.0.1; all refused."
                    ),
                )
            ]
        return [
            warn_finding(
                self.check_id,
                "Localhost Services Detected",
                f"Common ports open on 127.0.0.1: {open_ports}",
                Severity.LOW,
                self.category,
                evidence={"open_ports": open_ports},
                cvss_score=3.1,
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                detection_command="socket connect to 127.0.0.1:{}".format(
                    ",".join(str(p) for p in open_ports)
                ),
                confidence="high",
                timestamp=now,
                affected_asset="localhost",
                technical_detail=(
                    f"{len(open_ports)} common port(s) accepted TCP connections on "
                    f"localhost: {open_ports}. These may be development or production services."
                ),
                business_impact=(
                    "Locally-bound services are lower risk but may be pivoted through "
                    "if the host is compromised."
                ),
                remediation_steps=[
                    "Identify the services on each port with `lsof -i -P -n`.",
                    "Stop services that are not needed.",
                    "Ensure services bind only to required interfaces.",
                ],
                verification_command="for p in {}; do nc -z 127.0.0.1 $p && echo $p open; done".format(
                    " ".join(str(p) for p in open_ports)
                ),
            )
        ]
