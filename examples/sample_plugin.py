"""
Example Custom Rule Plugin
==========================

Place in a directory and use: tool-scan --rules-dir ./my_rules tools/*.json

API contract: expose a get_rules() function returning list[PluginRule].
"""

from __future__ import annotations

from typing import Any

from tool_scan.rules import PluginFinding, PluginRule, Severity


def _check_no_wildcards(tool: dict[str, Any]) -> list[PluginFinding]:
    """Flag tools that accept wildcard patterns in inputs."""
    schema = tool.get("inputSchema", {})
    properties = schema.get("properties", {})
    findings: list[PluginFinding] = []

    for prop_name, prop_schema in properties.items():
        if not isinstance(prop_schema, dict):
            continue
        default = prop_schema.get("default", "")
        if isinstance(default, str) and "*" in default:
            findings.append(PluginFinding(
                message=f"Property '{prop_name}' has wildcard in default value",
                location=f"inputSchema.properties.{prop_name}.default",
            ))

    return findings


def get_rules() -> list[PluginRule]:
    """Return custom rules for this project."""
    return [
        PluginRule(
            rule_id="PROJ-001",
            title="No wildcard defaults",
            severity=Severity.MEDIUM,
            check=_check_no_wildcards,
            description="Ensures input properties don't have wildcard default values.",
        ),
    ]
