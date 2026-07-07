"""Subprocess and command execution helpers."""

from __future__ import annotations

import shutil
import subprocess
from typing import List, Optional, Tuple


def run_command(
    cmd: List[str],
    use_sudo: bool = False,
    timeout: int = 60,
) -> Tuple[int, str, str]:
    """
    Safe wrapper around subprocess.run.

    Why centralise? Consistent timeout, error handling, and
    optional sudo — avoids duplicated shell logic in every check.
    """
    if use_sudo and shutil.which("sudo"):
        cmd = ["sudo"] + cmd

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except Exception as exc:
        return -1, "", str(exc)


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None
