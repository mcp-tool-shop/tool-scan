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

__version__ = "1.0.1"
__author__ = "MCP Tool Shop"

from .compliance_checker import (
    ComplianceCheck,
    ComplianceChecker,
    ComplianceLevel,
    ComplianceReport,
    ComplianceStatus,
)
from .config import ToolScanConfig, load_config
from .discovery import discover_files
from .grader import Grade, GradeReport, MCPToolGrader, Remark, RemarkCategory, grade_tool
from .profile import ProfileResult, ScanProfiler, StageResult
from .schema_validator import SchemaDialect, SchemaIssue, SchemaValidator
from .security_scanner import (
    SecurityScanner,
    SecurityScanResult,
    SecurityThreat,
    ThreatCategory,
    ThreatSeverity,
)
from .tool_validator import MCPToolValidator, ValidationIssue, ValidationResult, ValidationSeverity

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
    # Config
    "ToolScanConfig",
    "load_config",
    # Discovery
    "discover_files",
    # Profiler
    "ScanProfiler",
    "ProfileResult",
    "StageResult",
    # Grader (main entry point)
    "MCPToolGrader",
    "GradeReport",
    "Grade",
    "Remark",
    "RemarkCategory",
    "grade_tool",
]
