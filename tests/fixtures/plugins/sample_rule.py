"""Sample plugin rule for testing."""

from __future__ import annotations

from typing import Any

from tool_scan.rules import PluginFinding, PluginRule, Severity


def _check_forbidden_word(tool: dict[str, Any]) -> list[PluginFinding]:
    """Flag tools whose description contains 'forbidden'."""
    desc = tool.get("description", "")
    if "forbidden" in desc.lower():
        return [
            PluginFinding(
                message="Description contains the word 'forbidden'",
                location="description",
            )
        ]
    return []


def get_rules() -> list[PluginRule]:
    return [
        PluginRule(
            rule_id="TEST-001",
            title="Forbidden word check",
            severity=Severity.MEDIUM,
            check=_check_forbidden_word,
            description="Checks for the word 'forbidden' in tool descriptions.",
        ),
    ]
