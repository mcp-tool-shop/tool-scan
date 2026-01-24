"""
Tool-Scan: MCP Tool Security Scanner
====================================

Security scanning and validation for MCP (Model Context Protocol) tools.

Features:
- Security vulnerability detection (prompt injection, tool poisoning, etc.)
- MCP 2025-11-25 specification compliance
- Quality scoring (1-100) with letter grades
- Actionable remediation remarks

Quick Start:
    from tool_scan import grade_tool

    report = grade_tool(tool_definition)
    print(f"Score: {report.score}/100")
    print(f"Grade: {report.grade.letter}")
    print(f"Safe: {report.is_safe}")

References:
- https://modelcontextprotocol.io/specification/2025-11-25
- MCP Security Best Practices (2026)
"""

__version__ = "1.0.0"
__author__ = "MCP Tool Shop"

from .tool_validator import MCPToolValidator, ValidationSeverity, ValidationResult, ValidationIssue
from .schema_validator import SchemaValidator, SchemaDialect, SchemaIssue
from .security_scanner import SecurityScanner, SecurityScanResult, SecurityThreat, ThreatCategory, ThreatSeverity
from .compliance_checker import ComplianceChecker, ComplianceReport, ComplianceCheck, ComplianceLevel, ComplianceStatus
from .grader import MCPToolGrader, GradeReport, Grade, Remark, RemarkCategory, grade_tool

__all__ = [
    # Version
    "__version__",
    # Tool Validator
    "MCPToolValidator",
    "ValidationSeverity",
    "ValidationResult",
    "ValidationIssue",
    # Schema Validator
    "SchemaValidator",
    "SchemaDialect",
    "SchemaIssue",
    # Security Scanner
    "SecurityScanner",
    "SecurityScanResult",
    "SecurityThreat",
    "ThreatCategory",
    "ThreatSeverity",
    # Compliance Checker
    "ComplianceChecker",
    "ComplianceReport",
    "ComplianceCheck",
    "ComplianceLevel",
    "ComplianceStatus",
    # Grader (main entry point)
    "MCPToolGrader",
    "GradeReport",
    "Grade",
    "Remark",
    "RemarkCategory",
    "grade_tool",
]
