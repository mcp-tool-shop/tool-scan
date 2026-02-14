"""
MCP Tool Validator
==================

Main entry point for comprehensive MCP tool validation.

Based on MCP Specification 2025-11-25 and 2026 security best practices.

Key validation areas:
1. Schema compliance (JSON Schema 2020-12 / draft-07)
2. Security vulnerabilities (injection, poisoning, exfiltration)
3. Tool metadata and annotations
4. Input/output contract validation
5. Name and description requirements
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, TypedDict

from .security_scanner import SecurityScanner, ThreatSeverity


class ValidationSeverity(Enum):
    """Severity levels for validation issues."""

    INFO = auto()  # Informational, best practice suggestions
    WARNING = auto()  # Non-blocking issues that should be addressed
    ERROR = auto()  # Blocking issues that fail validation
    CRITICAL = auto()  # Security vulnerabilities that must be fixed


@dataclass
class ValidationIssue:
    """A single validation issue found during tool inspection."""

    code: str
    message: str
    severity: ValidationSeverity
    field: str | None = None
    suggestion: str | None = None
    reference: str | None = None  # Link to spec or docs

    def __str__(self) -> str:
        prefix = f"[{self.severity.name}]"
        location = f" in '{self.field}'" if self.field else ""
        return f"{prefix}{location}: {self.message}"


@dataclass
class ValidationResult:
    """Complete validation result for an MCP tool."""

    tool_name: str
    is_valid: bool
    issues: list[ValidationIssue] = field(default_factory=list)
    score: float = 100.0  # 0-100 quality score
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def errors(self) -> list[ValidationIssue]:
        return [
            i
            for i in self.issues
            if i.severity in (ValidationSeverity.ERROR, ValidationSeverity.CRITICAL)
        ]

    @property
    def warnings(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == ValidationSeverity.WARNING]

    @property
    def critical_issues(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == ValidationSeverity.CRITICAL]

    def summary(self) -> str:
        """Generate a summary of the validation result."""
        status = "✓ PASS" if self.is_valid else "✗ FAIL"
        lines = [
            f"Tool: {self.tool_name}",
            f"Status: {status}",
            f"Score: {self.score:.1f}/100",
            f"Issues: {len(self.critical_issues)} critical, {len(self.errors)} errors, {len(self.warnings)} warnings",
        ]
        return "\n".join(lines)


class MCPToolDefinition(TypedDict, total=False):
    """Type definition for an MCP tool as per specification."""

    name: str
    description: str
    inputSchema: dict[str, Any]
    annotations: dict[str, Any]


class MCPToolValidator:
    """
    Comprehensive validator for MCP tools.

    Validates tools against:
    - MCP Specification 2025-11-25
    - 2026 Security Best Practices
    - JSON Schema standards (2020-12, draft-07)

    Usage:
        validator = MCPToolValidator()
        result = validator.validate(tool_definition)

        if not result.is_valid:
            for issue in result.errors:
                print(issue)
    """

    # MCP naming requirements
    VALID_NAME_PATTERN = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_-]*$")
    MAX_NAME_LENGTH = 64
    MAX_DESCRIPTION_LENGTH = 4096
    MIN_DESCRIPTION_LENGTH = 10

    # Reserved/dangerous tool names
    RESERVED_NAMES: set[str] = {
        "system",
        "admin",
        "root",
        "sudo",
        "exec",
        "eval",
        "shell",
        "rm",
        "delete",
        "drop",
        "truncate",
        "format",
        "shutdown",
        "__init__",
        "__call__",
        "__exec__",
    }

    # Dangerous patterns in descriptions (tool poisoning indicators)
    DANGEROUS_DESCRIPTION_PATTERNS = [
        (
            r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|constraints?)",
            "instruction_override",
        ),
        (r"you\s+(must|should|have\s+to)\s+always", "forced_behavior"),
        (r"never\s+tell\s+(the\s+)?user", "deception_attempt"),
        (r"pretend\s+(to\s+be|you\s+are)", "identity_manipulation"),
        (r"bypass\s+(security|validation|auth)", "security_bypass"),
        (r"execute\s+(this\s+)?(silently|secretly|without)", "covert_execution"),
        (r"(read|access|exfiltrate)\s+(all\s+)?(files?|data|credentials?)", "data_exfiltration"),
        (r"send\s+(to|data\s+to)\s+https?://", "external_transmission"),
        (r"<script[^>]*>", "xss_attempt"),
        (r"\$\{.*\}", "template_injection"),
        (r"{{.*}}", "template_injection"),
    ]

    def __init__(
        self,
        strict_mode: bool = True,
        check_security: bool = True,
        check_schema: bool = True,
        custom_validators: list[Callable[[dict[str, Any]], list[ValidationIssue]]] | None = None,
    ):
        """
        Initialize the validator.

        Args:
            strict_mode: If True, treat warnings as errors
            check_security: Enable security vulnerability scanning
            check_schema: Enable JSON schema validation
            custom_validators: Additional validation functions
        """
        self.strict_mode = strict_mode
        self.check_security = check_security
        self.check_schema = check_schema
        self.custom_validators = custom_validators or []

        # Compile dangerous patterns
        self._dangerous_patterns = [
            (re.compile(pattern, re.IGNORECASE), name)
            for pattern, name in self.DANGEROUS_DESCRIPTION_PATTERNS
        ]

    def validate(self, tool: dict[str, Any]) -> ValidationResult:
        """
        Validate an MCP tool definition.

        Args:
            tool: The tool definition to validate

        Returns:
            ValidationResult with all issues found
        """
        issues: list[ValidationIssue] = []
        tool_name = tool.get("name", "<unnamed>")

        # Core validation
        issues.extend(self._validate_name(tool))
        issues.extend(self._validate_description(tool))
        issues.extend(self._validate_input_schema(tool))
        issues.extend(self._validate_annotations(tool))

        # Security scanning
        if self.check_security:
            issues.extend(self._scan_security(tool))

        # Custom validators
        for validator in self.custom_validators:
            try:
                issues.extend(validator(tool))
            except Exception as e:
                issues.append(
                    ValidationIssue(
                        code="CUSTOM_VALIDATOR_ERROR",
                        message=f"Custom validator failed: {e}",
                        severity=ValidationSeverity.WARNING,
                    )
                )

        # Calculate score
        score = self._calculate_score(issues)

        # Determine validity
        has_errors = any(
            i.severity in (ValidationSeverity.ERROR, ValidationSeverity.CRITICAL) for i in issues
        )
        has_warnings = any(i.severity == ValidationSeverity.WARNING for i in issues)

        is_valid = not has_errors and (not self.strict_mode or not has_warnings)

        return ValidationResult(
            tool_name=tool_name,
            is_valid=is_valid,
            issues=issues,
            score=score,
            metadata={
                "strict_mode": self.strict_mode,
                "security_checked": self.check_security,
                "schema_checked": self.check_schema,
            },
        )

    def _validate_name(self, tool: dict[str, Any]) -> list[ValidationIssue]:
        """Validate tool name requirements."""
        issues = []
        name = tool.get("name")

        # Name is required
        if not name:
            issues.append(
                ValidationIssue(
                    code="NAME_MISSING",
                    message="Tool name is required",
                    severity=ValidationSeverity.ERROR,
                    field="name",
                    reference="https://modelcontextprotocol.io/specification/2025-11-25",
                )
            )
            return issues

        # Name format validation
        if not self.VALID_NAME_PATTERN.match(name):
            issues.append(
                ValidationIssue(
                    code="NAME_INVALID_FORMAT",
                    message=f"Name '{name}' must start with letter/underscore, contain only alphanumeric, underscore, hyphen",
                    severity=ValidationSeverity.ERROR,
                    field="name",
                    suggestion="Use snake_case or kebab-case naming",
                )
            )

        # Name length
        if len(name) > self.MAX_NAME_LENGTH:
            issues.append(
                ValidationIssue(
                    code="NAME_TOO_LONG",
                    message=f"Name exceeds {self.MAX_NAME_LENGTH} characters",
                    severity=ValidationSeverity.ERROR,
                    field="name",
                )
            )

        # Reserved names check
        if name.lower() in self.RESERVED_NAMES:
            issues.append(
                ValidationIssue(
                    code="NAME_RESERVED",
                    message=f"Name '{name}' is reserved and cannot be used",
                    severity=ValidationSeverity.CRITICAL,
                    field="name",
                    suggestion="Choose a more specific, descriptive name",
                )
            )

        # Naming conventions (warnings)
        if name.startswith("_"):
            issues.append(
                ValidationIssue(
                    code="NAME_UNDERSCORE_PREFIX",
                    message="Names starting with underscore suggest internal/private tools",
                    severity=ValidationSeverity.WARNING,
                    field="name",
                )
            )

        return issues

    def _validate_description(self, tool: dict[str, Any]) -> list[ValidationIssue]:
        """Validate tool description requirements."""
        issues = []
        description = tool.get("description")

        # Description is required
        if not description:
            issues.append(
                ValidationIssue(
                    code="DESCRIPTION_MISSING",
                    message="Tool description is required",
                    severity=ValidationSeverity.ERROR,
                    field="description",
                    reference="https://modelcontextprotocol.io/specification/2025-11-25",
                )
            )
            return issues

        # Description length
        if len(description) < self.MIN_DESCRIPTION_LENGTH:
            issues.append(
                ValidationIssue(
                    code="DESCRIPTION_TOO_SHORT",
                    message=f"Description should be at least {self.MIN_DESCRIPTION_LENGTH} characters",
                    severity=ValidationSeverity.WARNING,
                    field="description",
                    suggestion="Provide a clear, helpful description of what the tool does",
                )
            )

        if len(description) > self.MAX_DESCRIPTION_LENGTH:
            issues.append(
                ValidationIssue(
                    code="DESCRIPTION_TOO_LONG",
                    message=f"Description exceeds {self.MAX_DESCRIPTION_LENGTH} characters",
                    severity=ValidationSeverity.ERROR,
                    field="description",
                )
            )

        # Check for tool poisoning patterns
        for pattern, pattern_name in self._dangerous_patterns:
            if pattern.search(description):
                issues.append(
                    ValidationIssue(
                        code=f"DESCRIPTION_DANGEROUS_{pattern_name.upper()}",
                        message=f"Description contains suspicious pattern: {pattern_name}",
                        severity=ValidationSeverity.CRITICAL,
                        field="description",
                        suggestion="Remove any instructions that attempt to manipulate AI behavior",
                        reference="https://www.practical-devsecops.com/mcp-security-vulnerabilities/",
                    )
                )

        return issues

    def _validate_input_schema(self, tool: dict[str, Any]) -> list[ValidationIssue]:
        """Validate the inputSchema according to JSON Schema standards."""
        issues = []
        schema = tool.get("inputSchema")

        # inputSchema is required per MCP spec
        if schema is None:
            issues.append(
                ValidationIssue(
                    code="INPUT_SCHEMA_MISSING",
                    message="inputSchema is required for tool definitions",
                    severity=ValidationSeverity.ERROR,
                    field="inputSchema",
                )
            )
            return issues

        if not isinstance(schema, dict):
            issues.append(
                ValidationIssue(
                    code="INPUT_SCHEMA_INVALID_TYPE",
                    message="inputSchema must be an object",
                    severity=ValidationSeverity.ERROR,
                    field="inputSchema",
                )
            )
            return issues

        # Must have type: "object" at root
        if schema.get("type") != "object":
            issues.append(
                ValidationIssue(
                    code="INPUT_SCHEMA_NOT_OBJECT",
                    message="inputSchema root type must be 'object'",
                    severity=ValidationSeverity.ERROR,
                    field="inputSchema.type",
                    reference="https://modelcontextprotocol.io/specification/2025-11-25",
                )
            )

        # Check $schema declaration
        schema_version = schema.get("$schema", "")
        valid_schemas = [
            "https://json-schema.org/draft/2020-12/schema",
            "http://json-schema.org/draft-07/schema#",
            "http://json-schema.org/draft-07/schema",
        ]
        if schema_version and schema_version not in valid_schemas:
            issues.append(
                ValidationIssue(
                    code="INPUT_SCHEMA_VERSION_UNKNOWN",
                    message=f"Unknown schema version: {schema_version}",
                    severity=ValidationSeverity.WARNING,
                    field="inputSchema.$schema",
                    suggestion="Use draft-07 or 2020-12 JSON Schema",
                )
            )

        # Validate properties
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            issues.append(
                ValidationIssue(
                    code="INPUT_SCHEMA_PROPERTIES_INVALID",
                    message="properties must be an object",
                    severity=ValidationSeverity.ERROR,
                    field="inputSchema.properties",
                )
            )
        else:
            # Check each property
            for prop_name, prop_schema in properties.items():
                issues.extend(self._validate_property(prop_name, prop_schema))

        # Check required array
        required = schema.get("required", [])
        if required and not isinstance(required, list):
            issues.append(
                ValidationIssue(
                    code="INPUT_SCHEMA_REQUIRED_INVALID",
                    message="required must be an array",
                    severity=ValidationSeverity.ERROR,
                    field="inputSchema.required",
                )
            )
        elif required:
            # Verify required properties exist
            for req_prop in required:
                if req_prop not in properties:
                    issues.append(
                        ValidationIssue(
                            code="INPUT_SCHEMA_REQUIRED_MISSING",
                            message=f"Required property '{req_prop}' not defined in properties",
                            severity=ValidationSeverity.ERROR,
                            field="inputSchema.required",
                        )
                    )

        # Check additionalProperties (security best practice: should be false)
        additional_props = schema.get("additionalProperties", True)
        if additional_props is True:
            issues.append(
                ValidationIssue(
                    code="INPUT_SCHEMA_ADDITIONAL_PROPS",
                    message="additionalProperties should be false for security",
                    severity=ValidationSeverity.WARNING,
                    field="inputSchema.additionalProperties",
                    suggestion="Set additionalProperties: false to prevent unexpected inputs",
                )
            )

        return issues

    def _validate_property(self, name: str, schema: Any) -> list[ValidationIssue]:
        """Validate a single property in the input schema."""
        issues = []
        field_path = f"inputSchema.properties.{name}"

        if not isinstance(schema, dict):
            issues.append(
                ValidationIssue(
                    code="PROPERTY_INVALID_TYPE",
                    message=f"Property '{name}' schema must be an object",
                    severity=ValidationSeverity.ERROR,
                    field=field_path,
                )
            )
            return issues

        # Type is recommended
        if "type" not in schema and "anyOf" not in schema and "oneOf" not in schema:
            issues.append(
                ValidationIssue(
                    code="PROPERTY_NO_TYPE",
                    message=f"Property '{name}' should have a type defined",
                    severity=ValidationSeverity.WARNING,
                    field=field_path,
                )
            )

        # Description is recommended for each property
        if "description" not in schema:
            issues.append(
                ValidationIssue(
                    code="PROPERTY_NO_DESCRIPTION",
                    message=f"Property '{name}' should have a description",
                    severity=ValidationSeverity.INFO,
                    field=field_path,
                )
            )

        # Check for security-sensitive property names
        sensitive_patterns = ["password", "secret", "token", "key", "credential", "auth"]
        if any(p in name.lower() for p in sensitive_patterns):
            issues.append(
                ValidationIssue(
                    code="PROPERTY_SENSITIVE_NAME",
                    message=f"Property '{name}' appears to handle sensitive data",
                    severity=ValidationSeverity.WARNING,
                    field=field_path,
                    suggestion="Ensure proper handling and never log sensitive values",
                )
            )

        # Validate string constraints
        prop_type = schema.get("type")
        if (
            prop_type == "string"
            and "pattern" not in schema
            and "format" not in schema
            and "enum" not in schema
            and "maxLength" not in schema
        ):
            issues.append(
                ValidationIssue(
                    code="STRING_NO_CONSTRAINTS",
                    message=f"String property '{name}' has no validation constraints",
                    severity=ValidationSeverity.INFO,
                    field=field_path,
                    suggestion="Consider adding maxLength, pattern, or format",
                )
            )

        return issues

    def _validate_annotations(self, tool: dict[str, Any]) -> list[ValidationIssue]:
        """Validate tool annotations (MCP 2025-11-25 spec)."""
        issues = []
        annotations = tool.get("annotations")

        if annotations is None:
            # Annotations are optional but recommended
            issues.append(
                ValidationIssue(
                    code="ANNOTATIONS_MISSING",
                    message="Tool annotations are recommended for safety classification",
                    severity=ValidationSeverity.INFO,
                    field="annotations",
                    suggestion="Add annotations to indicate tool behavior (destructive, idempotent, etc.)",
                )
            )
            return issues

        if not isinstance(annotations, dict):
            issues.append(
                ValidationIssue(
                    code="ANNOTATIONS_INVALID_TYPE",
                    message="annotations must be an object",
                    severity=ValidationSeverity.ERROR,
                    field="annotations",
                )
            )
            return issues

        # Known annotation fields per MCP spec
        known_annotations = {
            "title": str,
            "readOnlyHint": bool,
            "destructiveHint": bool,
            "idempotentHint": bool,
            "openWorldHint": bool,
        }

        for key, value in annotations.items():
            if key in known_annotations:
                expected_type = known_annotations[key]
                if not isinstance(value, expected_type):
                    issues.append(
                        ValidationIssue(
                            code="ANNOTATION_WRONG_TYPE",
                            message=f"Annotation '{key}' should be {expected_type.__name__}",
                            severity=ValidationSeverity.ERROR,
                            field=f"annotations.{key}",
                        )
                    )

        # Warn about destructive tools
        if annotations.get("destructiveHint") is True:
            issues.append(
                ValidationIssue(
                    code="ANNOTATION_DESTRUCTIVE",
                    message="Tool is marked as destructive - ensure proper user consent",
                    severity=ValidationSeverity.WARNING,
                    field="annotations.destructiveHint",
                    suggestion="Destructive tools require explicit user confirmation before execution",
                )
            )

        return issues

    def _scan_security(self, tool: dict[str, Any]) -> list[ValidationIssue]:
        """Delegate security scanning to SecurityScanner (single source of truth).

        Converts SecurityScanner threats into ValidationIssues so callers
        that consume the validator directly still see security findings.
        """
        scanner = SecurityScanner()
        result = scanner.scan(tool)

        severity_map = {
            ThreatSeverity.LOW: ValidationSeverity.INFO,
            ThreatSeverity.MEDIUM: ValidationSeverity.WARNING,
            ThreatSeverity.HIGH: ValidationSeverity.ERROR,
            ThreatSeverity.CRITICAL: ValidationSeverity.CRITICAL,
        }

        issues: list[ValidationIssue] = []
        for threat in result.threats:
            issues.append(
                ValidationIssue(
                    code=f"SECURITY_{threat.category.name}",
                    message=threat.description,
                    severity=severity_map.get(threat.severity, ValidationSeverity.WARNING),
                    field=threat.location,
                    suggestion=threat.mitigation,
                )
            )
        return issues

    def _calculate_score(self, issues: list[ValidationIssue]) -> float:
        """Calculate a quality score based on issues found."""
        score = 100.0

        # Deductions per severity
        deductions = {
            ValidationSeverity.INFO: 1,
            ValidationSeverity.WARNING: 5,
            ValidationSeverity.ERROR: 15,
            ValidationSeverity.CRITICAL: 30,
        }

        for issue in issues:
            score -= deductions.get(issue.severity, 0)

        return max(0.0, score)

    def validate_batch(self, tools: list[dict[str, Any]]) -> dict[str, ValidationResult]:
        """
        Validate multiple tools at once.

        Args:
            tools: List of tool definitions

        Returns:
            Dict mapping tool names to validation results
        """
        results = {}
        for tool in tools:
            name = tool.get("name", f"<unnamed_{id(tool)}>")
            results[name] = self.validate(tool)
        return results
