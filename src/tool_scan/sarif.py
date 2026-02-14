"""
SARIF Output
============

Generates SARIF v2.1.0 output for GitHub Code Scanning integration.

References:
- https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
- https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
"""

from __future__ import annotations

from typing import Any

from . import __version__
from .grader import RULESET_VERSION, GradeReport

# SARIF severity mapping
_LEVEL_MAP: dict[str, str] = {
    "CRITICAL": "error",
    "SECURITY": "error",
    "COMPLIANCE": "warning",
    "QUALITY": "note",
    "BEST_PRACTICE": "note",
    "INFO": "note",
}


def grade_report_to_sarif(
    report: GradeReport,
    tool_definition_path: str = "tool.json",
) -> dict[str, Any]:
    """Convert a single GradeReport into a SARIF v2.1.0 log.

    Args:
        report: The grading report to convert.
        tool_definition_path: File path to use in SARIF location URIs.

    Returns:
        A dict that serialises to valid SARIF JSON.
    """
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    seen_rule_ids: set[str] = set()

    for remark in report.remarks:
        # Determine a stable ruleId
        rule_id = remark.rule_id or remark.title
        level = _LEVEL_MAP.get(remark.category.name, "note")

        # Add rule if first occurrence
        if rule_id not in seen_rule_ids:
            seen_rule_ids.add(rule_id)
            rule_descriptor: dict[str, Any] = {
                "id": rule_id,
                "shortDescription": {"text": remark.title},
                "fullDescription": {"text": remark.description},
            }
            if remark.reference:
                rule_descriptor["helpUri"] = (
                    f"https://cwe.mitre.org/data/definitions/{remark.cwe_id.split('-')[1]}.html"
                    if remark.cwe_id
                    else remark.reference
                )
            properties: dict[str, Any] = {}
            if remark.cwe_id:
                properties["cwe"] = remark.cwe_id
            if remark.owasp_id:
                properties["owasp"] = remark.owasp_id
            if properties:
                rule_descriptor["properties"] = properties
            rules.append(rule_descriptor)

        # Build result
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": remark.description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": tool_definition_path},
                    },
                },
            ],
        }
        if remark.snippet:
            result["locations"][0]["physicalLocation"]["region"] = {
                "snippet": {"text": remark.snippet},
            }
        results.append(result)

    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "tool-scan",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/mcp-tool-shop-org/tool-scan",
                        "rules": rules,
                        "properties": {
                            "ruleset_version": RULESET_VERSION,
                        },
                    },
                },
                "results": results,
            },
        ],
    }


def reports_to_sarif(
    reports: dict[str, GradeReport],
    base_path: str = "",
) -> dict[str, Any]:
    """Convert multiple GradeReports into a single SARIF log.

    Each tool's findings are merged into one run so GitHub Code Scanning
    shows them under a single tool entry.

    Args:
        reports: Mapping of tool names to grade reports.
        base_path: Optional prefix for artifact URIs.

    Returns:
        A dict that serialises to valid SARIF JSON.
    """
    all_rules: list[dict[str, Any]] = []
    all_results: list[dict[str, Any]] = []
    seen_rule_ids: set[str] = set()

    for name, report in reports.items():
        path = f"{base_path}{name}.json" if base_path else f"{name}.json"
        single = grade_report_to_sarif(report, tool_definition_path=path)
        run = single["runs"][0]

        # Merge rules (deduplicate by id)
        for rule in run["tool"]["driver"]["rules"]:
            if rule["id"] not in seen_rule_ids:
                seen_rule_ids.add(rule["id"])
                all_rules.append(rule)

        all_results.extend(run["results"])

    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "tool-scan",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/mcp-tool-shop-org/tool-scan",
                        "rules": all_rules,
                        "properties": {
                            "ruleset_version": RULESET_VERSION,
                        },
                    },
                },
                "results": all_results,
            },
        ],
    }
