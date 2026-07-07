"""Cross-platform OS detection."""

from __future__ import annotations

import platform
import socket
from dataclasses import dataclass


@dataclass(frozen=True)
class HostInfo:
    hostname: str
    platform: str  # linux | darwin | windows
    platform_version: str
    architecture: str
    python_version: str


def detect_host() -> HostInfo:
    """
    Normalise platform.system() into our three supported targets.

    Why not use sys.platform alone? platform.system() gives clearer
    semantics for enterprise reporting. Interview: "How would you
    design cross-platform tooling when checks diverge per OS?"
    """
    system = platform.system().lower()
    if system == "darwin":
        normalised = "darwin"
    elif system == "windows":
        normalised = "windows"
    else:
        normalised = "linux"

    return HostInfo(
        hostname=socket.gethostname(),
        platform=normalised,
        platform_version=platform.version(),
        architecture=platform.machine(),
        python_version=platform.python_version(),
    )
