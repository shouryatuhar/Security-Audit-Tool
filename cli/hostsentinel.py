#!/usr/bin/env python3
"""HostSentinel CLI — enterprise host security auditing."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Ensure project root is on sys.path when run as script
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config.loader import get_enabled_checks, load_config
from core.models import CheckStatus
from checks.vulnerability_summary_check import VulnerabilitySummaryCheck
from platforms import create_engine
from reports import generate_reports
from utils.logger import log_audit_event, setup_logging


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hostsentinel",
        description="HostSentinel — Cross-platform host security auditing framework",
    )
    parser.add_argument(
        "--config", "-c", help="Path to hostsentinel.yaml", default=None
    )
    parser.add_argument(
        "--check", "-k", action="append", dest="checks", help="Run specific check ID(s)"
    )
    parser.add_argument(
        "--category", action="append", dest="categories", help="Run checks in category"
    )
    parser.add_argument(
        "--list-checks", action="store_true", help="List registered checks and exit"
    )
    parser.add_argument(
        "--format",
        "-f",
        action="append",
        dest="formats",
        choices=["json", "html", "pdf"],
        help="Report format(s)",
    )
    parser.add_argument(
        "--output-dir", "-o", default=None, help="Report output directory"
    )
    parser.add_argument(
        "--no-report", action="store_true", help="Skip report generation"
    )
    parser.add_argument(
        "--gui", action="store_true", help="Launch legacy GUI mode"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Debug logging")
    return parser


def print_banner() -> None:
    print(
        """
╔══════════════════════════════════════════════════╗
║           HostSentinel v1.0.0                    ║
║   Enterprise Host Security Auditing Framework    ║
╚══════════════════════════════════════════════════╝
"""
    )


def print_summary(report) -> None:
    print(f"\n{'='*50}")
    print(f"  Host:     {report.hostname}")
    print(f"  Platform: {report.platform}")
    print(f"  Score:    {report.score}/100")
    print(f"  Checks:   {report.checks_run} run, {report.checks_failed} failed")
    print(f"{'='*50}")

    findings = [f for f in report.findings if f.is_finding]
    if findings:
        print("\nFindings:")
        for f in findings:
            icon = "🔴" if f.status == CheckStatus.FAIL else "🟡"
            cves = f" [{', '.join(f.cve_ids)}]" if f.cve_ids else ""
            print(f"  {icon} [{f.severity.value.upper()}] {f.title}{cves}")
    else:
        print("\n✅ No security findings detected.")

    summary = report.summary_by_severity()
    print(
        f"\nSeverity: CRIT={summary['critical']} HIGH={summary['high']} "
        f"MED={summary['medium']} LOW={summary['low']}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.gui:
        from security_audit import SecurityAuditGUI
        import tkinter as tk

        root = tk.Tk()
        app = SecurityAuditGUI(root)
        root.mainloop()
        return 0

    config = load_config(args.config)
    log_level = "DEBUG" if args.verbose else config.get("logging", {}).get("level", "INFO")
    logger = setup_logging(log_level, config.get("logging", {}).get("file"))

    engine = create_engine(config)

    if args.list_checks:
        print_banner()
        for check_id in engine.list_checks():
            check = engine._checks[check_id]
            print(f"  {check_id:25s} [{check.category:15s}] {check.title}")
        return 0

    print_banner()
    check_ids = args.checks or get_enabled_checks(config)

    logger.info("Starting HostSentinel audit")
    log_audit_event(
        f"AUDIT_START host={engine.host_info.hostname} platform={engine.host_info.platform}",
        config.get("logging", {}).get("audit_file", "logs/audit.log"),
    )

    report = engine.run(check_ids=check_ids, categories=args.categories)

    # Append vulnerability summary based on collected findings
    vuln_check = VulnerabilitySummaryCheck(prior_findings=report.findings)
    vuln_findings = vuln_check.run()
    report.findings.extend(vuln_findings)

    from core.scoring import calculate_score
    report.score = calculate_score(report.findings)

    print_summary(report)

    if not args.no_report:
        formats = args.formats or config.get("reports", {}).get("formats", ["json", "html"])
        output_dir = args.output_dir or config.get("reports", {}).get("output_dir", "reports")
        paths = generate_reports(report, output_dir, formats)
        print("\nReports generated:")
        for fmt, path in paths.items():
            print(f"  {fmt}: {path}")

    log_audit_event(
        f"AUDIT_COMPLETE score={report.score} findings={len([f for f in report.findings if f.is_finding])}",
        config.get("logging", {}).get("audit_file", "logs/audit.log"),
    )

    return 1 if report.score < config.get("scoring", {}).get("warn_threshold", 60) else 0


if __name__ == "__main__":
    sys.exit(main())
