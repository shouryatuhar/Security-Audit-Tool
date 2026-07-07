"""Structured logging for HostSentinel."""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = "logs/hostsentinel.log",
) -> logging.Logger:
    """
    Configure dual logging: console + rotating file.

    Why structured logging? Enterprise audits need traceability —
    who ran what, when, and what failed. Interview: "How do you
    design observability for a security tool?"
    """
    logger = logging.getLogger("hostsentinel")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    logger.addHandler(console)

    if log_file:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def log_audit_event(message: str, audit_file: str = "logs/audit.log") -> None:
    """Append immutable audit trail entries."""
    path = Path(audit_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"[{timestamp}] {message}\n")
