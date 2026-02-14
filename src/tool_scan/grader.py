"""
Tool-Scan Grader
================

Unified scoring system for MCP tools with actionable remarks.

Provides a 1-100 score with letter grades and specific recommendations
for improving tool quality, security, and MCP compliance.

Usage:
    from tool_scan import grade_tool

    report = grade_tool(tool_definition)

    print(report.grade)        # "A", "B", "C", "D", "F"
    print(report.score)        # 0-100
    print(report.summary)      # Human-readable summary
    print(report.remarks)      # List of actionable recommendations
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .compliance_checker import ComplianceChecker, ComplianceReport, ComplianceStatus
from .security_scanner import SecurityScanner, SecurityScanResult, ThreatSeverity
from .tool_validator import MCPToolValidator, ValidationResult, ValidationSeverity


class Grade(Enum):
    """Letter grades with thresholds."""

    A_PLUS = ("A+", 97, 100, "Excellent - Production Ready")
    A = ("A", 93, 96, "Excellent")
    A_MINUS = ("A-", 90, 92, "Very Good")
    B_PLUS = ("B+", 87, 89, "Good")
    B = ("B", 83, 86, "Good")
    B_MINUS = ("B-", 80, 82, "Above Average")
    C_PLUS = ("C+", 77, 79, "Satisfactory")
    C = ("C", 73, 76, "Satisfactory")
    C_MINUS = ("C-", 70, 72, "Below Average")
    D_PLUS = ("D+", 67, 69, "Poor")
    D = ("D", 63, 66, "Poor")
    D_MINUS = ("D-", 60, 62, "Barely Passing")
    F = ("F", 0, 59, "Failing - Do Not Use")

    def __init__(self, letter: str, min_score: int, max_score: int, description: str):
        self.letter = letter
        self.min_score = min_score
        self.max_score = max_score
        self.description = description

    @classmethod
    def from_score(cls, score: float) -> Grade:
        """Get grade from numeric score."""
        score_int = int(round(score))
        for grade in cls:
            if grade.min_score <= score_int <= grade.max_score:
                return grade
        return cls.F


class RemarkCategory(Enum):
    """Categories of remarks."""

    CRITICAL = "[!!] Critical"
    SECURITY = "[!!] Security"
    COMPLIANCE = "[i] Compliance"
    QUALITY = "[*] Quality"
    BEST_PRACTICE = "[+] Best Practice"
    INFO = "[i] Info"


@dataclass
class Remark:
    """A single actionable remark."""

    category: RemarkCategory
    title: str
    description: str
    action: str | None = None
    reference: str | None = None
    rule_id: str | None = None
    cwe_id: str | None = None
    owasp_id: str | None = None
    snippet: str | None = None

    def __str__(self) -> str:
        lines = [f"{self.category.value}: {self.title}"]
        lines.append(f"  {self.description}")
        if self.action:
            lines.append(f"  → Action: {self.action}")
        return "\n".join(lines)


@dataclass
class GradeReport:
    """Complete grading report for an MCP tool."""

    tool_name: str
    score: float
    grade: Grade
    remarks: list[Remark] = field(default_factory=list)
    is_safe: bool = True
    is_compliant: bool = True
    validation_result: ValidationResult | None = None
    security_result: SecurityScanResult | None = None
    compliance_result: ComplianceReport | None = None

    @property
    def summary(self) -> str:
        """Generate a human-readable summary."""
        lines = [
            "=" * 60,
            f"Tool-Scan Report: {self.tool_name}",
            "=" * 60,
            "",
            f"  Score: {self.score:.0f}/100",
            f"  Grade: {self.grade.letter} ({self.grade.description})",
            "",
            f"  Safe: {'✓ Yes' if self.is_safe else '✗ No - Security Issues Found'}",
            f"  Compliant: {'✓ Yes' if self.is_compliant else '✗ No - MCP Spec Violations'}",
            "",
        ]

        if self.remarks:
            lines.append(f"  Remarks ({len(self.remarks)}):")
            for remark in self.remarks[:10]:  # Show top 10
                lines.append(f"    • {remark.category.value}: {remark.title}")
            if len(self.remarks) > 10:
                lines.append(f"    ... and {len(self.remarks) - 10} more")
        else:
            lines.append("  Remarks: None - Tool is ready for production!")

        lines.append("")
        lines.append("=" * 60)
        return "\n".join(lines)

    @property
    def json_report(self) -> dict[str, Any]:
        """Generate a JSON-serializable report."""
        return {
            "tool_name": self.tool_name,
            "score": round(self.score, 1),
            "grade": self.grade.letter,
            "grade_description": self.grade.description,
            "is_safe": self.is_safe,
            "is_compliant": self.is_compliant,
            "remarks": [
                {
                    "category": r.category.name,
                    "title": r.title,
                    "description": r.description,
                    "action": r.action,
                    "reference": r.reference,
                    "rule_id": r.rule_id,
                    "cwe_id": r.cwe_id,
                    "owasp_id": r.owasp_id,
                    "snippet": r.snippet,
                }
                for r in self.remarks
            ],
            "summary": {
                "critical_issues": len(
                    [r for r in self.remarks if r.category == RemarkCategory.CRITICAL]
                ),
                "security_issues": len(
                    [r for r in self.remarks if r.category == RemarkCategory.SECURITY]
                ),
                "compliance_issues": len(
                    [r for r in self.remarks if r.category == RemarkCategory.COMPLIANCE]
                ),
                "quality_issues": len(
                    [r for r in self.remarks if r.category == RemarkCategory.QUALITY]
                ),
            },
        }


class MCPToolGrader:
    """
    Unified grader for MCP tools.

    Combines validation, security scanning, and compliance checking
    into a single 1-100 score with actionable remarks.

    Scoring weights:
    - Security (40%): No vulnerabilities = full points
    - Compliance (35%): MCP spec adherence
    - Quality (25%): Best practices, documentation, etc.
    """

    WEIGHT_SECURITY = 0.40
    WEIGHT_COMPLIANCE = 0.35
    WEIGHT_QUALITY = 0.25

    def __init__(
        self,
        strict_security: bool = True,
        include_optional_checks: bool = False,
    ):
        """
        Initialize the grader.

        Args:
            strict_security: Fail on any high/critical security issues
            include_optional_checks: Include enterprise-level optional checks
        """
        self.strict_security = strict_security
        self.include_optional_checks = include_optional_checks

        # Initialize validators
        self.validator = MCPToolValidator(strict_mode=False, check_security=True)
        self.security = SecurityScanner(fail_on_medium=strict_security)
        self.compliance = ComplianceChecker(
            check_required=True,
            check_recommended=True,
            check_optional=include_optional_checks,
        )

    def grade(self, tool: dict[str, Any]) -> GradeReport:
        """
        Grade an MCP tool.

        Args:
            tool: The tool definition to grade

        Returns:
            GradeReport with score, grade, and remarks
        """
        tool_name = tool.get("name", "<unnamed>")
        remarks: list[Remark] = []

        # Run all validators
        validation_result = self.validator.validate(tool)
        security_result = self.security.scan(tool)
        compliance_result = self.compliance.check(tool)

        # Calculate component scores
        security_score = self._calculate_security_score(security_result, remarks)
        compliance_score = self._calculate_compliance_score(compliance_result, remarks)
        quality_score = self._calculate_quality_score(validation_result, remarks)

        # Calculate weighted final score
        final_score = (
            security_score * self.WEIGHT_SECURITY
            + compliance_score * self.WEIGHT_COMPLIANCE
            + quality_score * self.WEIGHT_QUALITY
        )

        # Determine grade
        grade = Grade.from_score(final_score)

        # Override grade if critical issues
        if security_result.critical_threats:
            grade = Grade.F
            final_score = min(final_score, 30)

        # Sort remarks by importance
        remarks.sort(
            key=lambda r: (
                0
                if r.category == RemarkCategory.CRITICAL
                else 1
                if r.category == RemarkCategory.SECURITY
                else 2
                if r.category == RemarkCategory.COMPLIANCE
                else 3
                if r.category == RemarkCategory.QUALITY
                else 4
            )
        )

        return GradeReport(
            tool_name=tool_name,
            score=final_score,
            grade=grade,
            remarks=remarks,
            is_safe=security_result.is_safe,
            is_compliant=compliance_result.is_compliant,
            validation_result=validation_result,
            security_result=security_result,
            compliance_result=compliance_result,
        )

    def _calculate_security_score(
        self,
        result: SecurityScanResult,
        remarks: list[Remark],
    ) -> float:
        """Calculate security component score (0-100)."""
        score = 100.0

        # Deductions per threat severity
        deductions = {
            ThreatSeverity.LOW: 5,
            ThreatSeverity.MEDIUM: 15,
            ThreatSeverity.HIGH: 30,
            ThreatSeverity.CRITICAL: 50,
        }

        for threat in result.threats:
            score -= deductions.get(threat.severity, 0)

            # Generate remark
            if threat.severity == ThreatSeverity.CRITICAL:
                category = RemarkCategory.CRITICAL
            else:
                category = RemarkCategory.SECURITY

            remarks.append(
                Remark(
                    category=category,
                    title=threat.title,
                    description=threat.description,
                    action=threat.mitigation,
                    reference=threat.owasp_id or threat.cwe_id,
                    rule_id=threat.rule_id,
                    cwe_id=threat.cwe_id,
                    owasp_id=threat.owasp_id,
                    snippet=threat.snippet,
                )
            )

        return max(0.0, score)

    def _calculate_compliance_score(
        self,
        result: ComplianceReport,
        remarks: list[Remark],
    ) -> float:
        """Calculate compliance component score (0-100)."""
        # Use the compliance checker's built-in score
        score = result.compliance_score

        # Add remarks for failed checks
        for check in result.checks:
            if check.status == ComplianceStatus.FAIL:
                remarks.append(
                    Remark(
                        category=RemarkCategory.COMPLIANCE,
                        title=f"[{check.id}] {check.name}",
                        description=check.message,
                        action=check.details,
                        reference=check.spec_reference,
                    )
                )
            elif check.status == ComplianceStatus.WARN:
                remarks.append(
                    Remark(
                        category=RemarkCategory.BEST_PRACTICE,
                        title=f"[{check.id}] {check.name}",
                        description=check.message,
                        action=check.details,
                    )
                )

        return score

    def _calculate_quality_score(
        self,
        result: ValidationResult,
        remarks: list[Remark],
    ) -> float:
        """Calculate quality component score (0-100)."""
        score = result.score

        # Add remarks for issues not already covered
        seen_codes = set()
        for issue in result.issues:
            # Skip security issues (handled separately)
            if "SECURITY" in issue.code or "DANGEROUS" in issue.code:
                continue

            # Skip duplicates
            if issue.code in seen_codes:
                continue
            seen_codes.add(issue.code)

            if issue.severity == ValidationSeverity.ERROR:
                category = RemarkCategory.COMPLIANCE
            elif issue.severity == ValidationSeverity.WARNING:
                category = RemarkCategory.QUALITY
            else:
                category = RemarkCategory.INFO

            remarks.append(
                Remark(
                    category=category,
                    title=issue.code,
                    description=issue.message,
                    action=issue.suggestion,
                    reference=issue.reference,
                )
            )

        return score

    def grade_batch(self, tools: list[dict[str, Any]]) -> dict[str, GradeReport]:
        """
        Grade multiple tools.

        Args:
            tools: List of tool definitions

        Returns:
            Dict mapping tool names to grade reports
        """
        results = {}
        for tool in tools:
            name = tool.get("name", f"<unnamed_{id(tool)}>")
            results[name] = self.grade(tool)
        return results

    def generate_summary_table(self, reports: dict[str, GradeReport]) -> str:
        """Generate a summary table for multiple tools."""
        lines = [
            "┌" + "─" * 40 + "┬" + "─" * 7 + "┬" + "─" * 7 + "┬" + "─" * 10 + "┐",
            "│ {:38} │ {:5} │ {:5} │ {:8} │".format("Tool Name", "Score", "Grade", "Status"),
            "├" + "─" * 40 + "┼" + "─" * 7 + "┼" + "─" * 7 + "┼" + "─" * 10 + "┤",
        ]

        for name, report in sorted(reports.items(), key=lambda x: -x[1].score):
            status = "✓ Safe" if report.is_safe else "✗ Unsafe"
            lines.append(
                f"│ {name[:38]:38} │ {report.score:5.0f} │ {report.grade.letter:5} │ {status:8} │"
            )

        lines.append("└" + "─" * 40 + "┴" + "─" * 7 + "┴" + "─" * 7 + "┴" + "─" * 10 + "┘")

        return "\n".join(lines)


def grade_tool(tool: dict[str, Any], strict: bool = True) -> GradeReport:
    """
    Convenience function to grade a single tool.

    Args:
        tool: Tool definition
        strict: Use strict security mode

    Returns:
        GradeReport
    """
    grader = MCPToolGrader(strict_security=strict)
    return grader.grade(tool)
