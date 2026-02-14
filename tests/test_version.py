"""Version consistency tests."""

from __future__ import annotations

import importlib.metadata
import re

from tool_scan import grade_tool
from tool_scan.grader import REPORT_FORMAT_VERSION, RULESET_VERSION


def test_version_matches_metadata() -> None:
    """Ensure __version__ matches pyproject.toml version."""
    from tool_scan import __version__

    pkg_version = importlib.metadata.version("tool-scan")
    assert __version__ == pkg_version, (
        f"__version__ ({__version__}) != pyproject.toml ({pkg_version})"
    )


def test_version_is_semver() -> None:
    """Ensure version follows semver pattern."""
    from tool_scan import __version__

    parts = __version__.split(".")
    assert len(parts) == 3, f"Expected 3-part semver, got {__version__}"
    for part in parts:
        assert part.isdigit(), f"Non-numeric version part: {part}"


def test_json_report_contains_version_metadata() -> None:
    """JSON report must include report_version, tool_scan_version, and ruleset_version."""
    from tool_scan import __version__

    tool = {"name": "test", "description": "A test tool", "inputSchema": {"type": "object"}}
    report = grade_tool(tool)
    jr = report.json_report

    assert jr["report_version"] == REPORT_FORMAT_VERSION
    assert jr["tool_scan_version"] == __version__
    assert jr["ruleset_version"] == RULESET_VERSION


def test_report_format_version_is_semver() -> None:
    """REPORT_FORMAT_VERSION must follow semver."""
    assert re.match(r"^\d+\.\d+\.\d+$", REPORT_FORMAT_VERSION)
