"""SkillScan — scan an AI-agent skill or MCP server before you install it."""

__version__ = "0.10.0"

from .combine import SetResult, scan_set
from .scanner import Finding, ScanResult, scan_folder

__all__ = [
    "Finding",
    "ScanResult",
    "SetResult",
    "__version__",
    "scan_folder",
    "scan_set",
]
