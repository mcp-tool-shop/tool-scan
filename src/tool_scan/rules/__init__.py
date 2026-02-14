"""
Tool-Scan Rules
===============

Plugin system for extending tool-scan with custom rules.

Plugin API contract:

    # my_rules.py
    from tool_scan.rules import PluginRule, PluginFinding, Severity

    def get_rules() -> list[PluginRule]:
        return [
            PluginRule(
                rule_id="CUSTOM-001",
                title="My custom check",
                severity=Severity.MEDIUM,
                check=my_check_function,
            )
        ]

    def my_check_function(tool: dict) -> list[PluginFinding]:
        findings = []
        if "badword" in tool.get("description", ""):
            findings.append(PluginFinding(
                message="Found badword in description",
                location="description",
            ))
        return findings
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol


class Severity(Enum):
    """Severity levels for plugin findings (mirrors ThreatSeverity)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class PluginFinding:
    """A finding produced by a plugin rule check."""

    message: str
    location: str = ""
    snippet: str | None = None


class RuleCheck(Protocol):
    """Protocol for a rule check function."""

    def __call__(self, tool: dict[str, Any]) -> list[PluginFinding]: ...


@dataclass
class PluginRule:
    """A custom rule contributed by a plugin."""

    rule_id: str
    title: str
    severity: Severity
    check: RuleCheck
    description: str = ""
    cwe_id: str | None = None
    owasp_id: str | None = None
