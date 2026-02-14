"""
JUnit XML Output
================

Generates JUnit XML compatible with CI runners (Jenkins, GitHub Actions, etc.).

Each scanned tool becomes a ``<testcase>``.  Findings above the severity
threshold produce ``<failure>`` elements; tools that could not be loaded
produce ``<error>`` elements.
"""

from __future__ import annotations

from typing import Any
from xml.etree.ElementTree import Element, SubElement, tostring

from . import __version__
from .grader import GradeReport


def _escape(text: str) -> str:
    """XML-safe text (ElementTree handles this, but belt-and-suspenders)."""
    return text


def grade_reports_to_junit(
    reports: dict[str, GradeReport],
    *,
    min_score: float = 70.0,
    fail_on_unsafe: bool = True,
    suite_name: str = "tool-scan",
) -> str:
    """Convert grade reports into a JUnit XML string.

    Args:
        reports: Mapping of tool names to grade reports.
        min_score: Score below which a tool is considered failing.
        fail_on_unsafe: Whether unsafe tools should be marked as failures.
        suite_name: Name of the JUnit test suite.

    Returns:
        A string of JUnit-compatible XML.
    """
    testsuite = Element("testsuite", {
        "name": suite_name,
        "tests": str(len(reports)),
        "failures": "0",
        "errors": "0",
        "timestamp": "",
    })

    # Add a property with the tool-scan version
    props = SubElement(testsuite, "properties")
    SubElement(props, "property", {
        "name": "tool-scan-version",
        "value": __version__,
    })

    failures = 0
    for name, report in reports.items():
        tc = SubElement(testsuite, "testcase", {
            "classname": suite_name,
            "name": name,
        })

        failed = report.score < min_score or (fail_on_unsafe and not report.is_safe)
        if failed:
            failures += 1
            # Build failure message from remarks
            lines = [
                f"Score: {report.score:.0f}/100  Grade: {report.grade.letter}  Safe: {report.is_safe}",
            ]
            for remark in report.remarks:
                prefix = f"[{remark.rule_id}] " if remark.rule_id else ""
                lines.append(f"  {prefix}{remark.category.value}: {remark.title}")
                if remark.action:
                    lines.append(f"    -> {remark.action}")
            message = lines[0]
            failure_text = "\n".join(lines)

            failure = SubElement(tc, "failure", {
                "message": message,
                "type": "SecurityFailure" if not report.is_safe else "ScoreFailure",
            })
            failure.text = failure_text

    testsuite.set("failures", str(failures))

    return tostring(testsuite, encoding="unicode", xml_declaration=True)


def grade_report_to_junit(
    report: GradeReport,
    **kwargs: Any,
) -> str:
    """Convenience wrapper for a single report."""
    return grade_reports_to_junit({report.tool_name: report}, **kwargs)
