# HostSentinel

**HostSentinel** is an enterprise-grade, cross-platform host security auditing and posture management framework. It performs automated security assessments, behavioural anomaly detection, and compliance baselining comparable to commercial endpoint security tools and CIS benchmark scanners.

Designed for security engineers, penetration testers, and system administrators, HostSentinel identifies misconfigurations, exposes vulnerable software, and detects indicators of compromise (IoCs) across Linux, macOS, and Windows.

---

## 🛡️ Core Capabilities

- **Behavioural Threat Detection:** Identifies reverse shells, credential dumping, and crypto-mining behaviours in running processes rather than relying solely on naive binary names.
- **Enterprise Reporting:** Generates professional HTML, PDF, and JSON reports with rich contextual fields including CVSS v3.1 scoring, affected assets, detection commands, and actionable remediation steps.
- **Modular Plugin Architecture:** Extensible `BaseCheck` interface allows for rapid development of custom compliance and security checks without modifying the core engine.
- **Multi-Platform Support:** OS-aware orchestration automatically routes checks to appropriate platform implementations (Linux, macOS, Windows).
- **Vulnerability Correlation:** Integrates offline CVE mapping for installed packages, providing immediate visibility into known exploitability.

---

## 🏗️ Architecture

HostSentinel is built on a clean, decoupled architecture:

```text
HostSentinel/
├── core/           # Audit orchestration, Finding models, tiered scoring, OS detection
├── checks/         # Modular security checks (plugins inheriting BaseCheck)
├── platforms/      # Platform-specific check registration factories
├── reports/        # Enterprise JSON, HTML, and PDF report generators
├── config/         # YAML-based configuration management
├── cli/            # Professional argparse-based command-line interface
├── utils/          # Logging, command helpers, CVE correlation
├── fixes/          # Interactive remediation workflows
└── hostsentinel.py # Main entry point
```

### The `Finding` Data Model

Every security check returns instances of the `Finding` dataclass, which strictly enforces enterprise-grade metadata:

- **CVSS Score & Vector:** Approximate severity based on CVSS v3.1.
- **Confidence:** Detection confidence (Low, Medium, High, Exact).
- **Affected Asset & PID:** Exact mapping to the compromised entity.
- **Technical Detail & Business Impact:** Clear, executive-friendly explanations.
- **Remediation Steps & Verification:** Actionable commands to resolve and verify fixes.

---

## 📊 Tiered Scoring System

HostSentinel employs a logarithmic, diminishing-penalty scoring algorithm (0–100) to accurately reflect overall host risk without zeroing out from numerous low-severity issues:

- **80–100 (Healthy):** Host meets security baselines; minor tweaks recommended.
- **70–80 (Minor Issues):** Low-risk configuration deviations.
- **50–70 (Medium Issues):** Several moderate risks requiring scheduled remediation.
- **20–50 (Serious Security Issues):** Multiple high-risk vulnerabilities exposing the host to exploitation.
- **< 20 (Critical Compromise):** Indicators of active compromise or catastrophic exposure.

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- `pip install -r requirements.txt`

### Usage

```bash
# Run a full audit across all domains
python hostsentinel.py

# List all available security modules
python hostsentinel.py --list-checks

# Run targeted checks (e.g., SSH and Firewall) with PDF and HTML reporting
python hostsentinel.py -k ssh_config -k firewall -f json -f html -f pdf

# Generate reports in a specific directory
python hostsentinel.py -o /path/to/reports/
```

---

## 🧩 Security Modules

HostSentinel includes 18+ comprehensive audit modules:

| Check ID | Category | Description |
|----------|----------|-------------|
| `ssh_config` | Authentication | SSH daemon hardening, root login, password auth checks. |
| `firewall` | Network | Validates state of UFW, firewalld, iptables, macOS ALF, Windows Firewall. |
| `password_policy` | Authentication | Verifies password length constraints and detects empty passwords. |
| `open_ports` | Network | Identifies risky externally-facing services vs. localhost bindings. |
| `port_scan` | Network | Lightweight socket enumeration for localhost pivoting risks. |
| `outdated_packages` | Patching | Validates pending system updates (APT/DNF/YUM/macOS) with CVE correlation. |
| `package_inventory` | Inventory | Baseline enumeration for software asset management. |
| `suspicious_processes` | Malware | Behavioural detection (e.g., netcat reverse shells, obfuscated PowerShell). |
| `running_services` | Services | Identifies legacy cleartext protocols (Telnet, FTP, RSH). |
| `rootkit_detection` | Malware | Integrates with rkhunter and chkrootkit. |
| `unused_accounts` | Authentication | Detects stale logins and dormant accounts. |
| `user_privileges` | Authentication | Audits UID 0 duplicates, NOPASSWD sudoers, and admin group sprawl. |
| `file_integrity` | Integrity | Monitors critical binaries for tampering via SHA256 hashes. |
| `file_permissions` | Integrity | Validates strict permissions on `/etc/shadow`, `/etc/sudoers`. |
| `scheduled_tasks` | Persistence | Audits crontabs and launch daemons for persistence mechanisms. |
| `startup_services` | Persistence | Enumerates boot-level persistence items. |
| `dangerous_config` | Hardening | Checks IP forwarding, core dumps, and world-writable directories. |

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to add new checks, improve reporting, or fix bugs. 

Ensure you adhere to our [Code of Conduct](CODE_OF_CONDUCT.md).

## 🛡️ Security

If you discover a security vulnerability within HostSentinel, please see our [Security Policy](SECURITY.md).

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
