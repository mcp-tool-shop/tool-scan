"""
Compliance Checker
==================

Validates MCP tools against specification compliance and best practices.

Compliance levels:
- MCP 2025-11-25 Specification (Required)
- MCP 2026 Security Best Practices (Recommended)
- Enterprise Security Standards (Optional)

References:
- https://modelcontextprotocol.io/specification/2025-11-25
- https://github.com/modelcontextprotocol/specification/blob/main/schema/2025-11-25/schema.ts
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


class ComplianceLevel(Enum):
    """Compliance check levels."""

    REQUIRED = auto()  # Must pass for MCP compliance
    RECOMMENDED = auto()  # Should pass for security/quality
    OPTIONAL = auto()  # Nice to have


class ComplianceStatus(Enum):
    """Status of a compliance check."""

    PASS = auto()
    FAIL = auto()
    SKIP = auto()
    WARN = auto()


@dataclass
class ComplianceCheck:
    """A single compliance check result."""

    id: str
    name: str
    level: ComplianceLevel
    status: ComplianceStatus
    message: str
    details: str | None = None
    spec_reference: str | None = None

    def __str__(self) -> str:
        status_icon = {
            ComplianceStatus.PASS: "✓",
            ComplianceStatus.FAIL: "✗",
            ComplianceStatus.SKIP: "○",
            ComplianceStatus.WARN: "⚠",
        }[self.status]
        return f"[{status_icon}] {self.id}: {self.message}"


@dataclass
class ComplianceReport:
    """Complete compliance report for an MCP tool."""

    tool_name: str
    is_compliant: bool
    checks: list[ComplianceCheck] = field(default_factory=list)
    compliance_score: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def required_failures(self) -> list[ComplianceCheck]:
        return [
            c
            for c in self.checks
            if c.level == ComplianceLevel.REQUIRED and c.status == ComplianceStatus.FAIL
        ]

    @property
    def recommended_failures(self) -> list[ComplianceCheck]:
        return [
            c
            for c in self.checks
            if c.level == ComplianceLevel.RECOMMENDED and c.status == ComplianceStatus.FAIL
        ]

    @property
    def passed_checks(self) -> list[ComplianceCheck]:
        return [c for c in self.checks if c.status == ComplianceStatus.PASS]

    def summary(self) -> str:
        """Generate a compliance summary."""
        passed = len(self.passed_checks)
        total = len([c for c in self.checks if c.status != ComplianceStatus.SKIP])
        required_failed = len(self.required_failures)

        status = "✓ COMPLIANT" if self.is_compliant else "✗ NON-COMPLIANT"
        lines = [
            f"Tool: {self.tool_name}",
            f"Status: {status}",
            f"Score: {self.compliance_score:.1f}%",
            f"Checks: {passed}/{total} passed",
        ]

        if required_failed > 0:
            lines.append(f"Required failures: {required_failed}")

        return "\n".join(lines)


class ComplianceChecker:
    """
    Comprehensive MCP compliance checker.

    Validates tools against:
    - MCP 2025-11-25 Specification requirements
    - 2026 Security best practices
    - Enterprise security standards
    """

    # MCP 2025-11-25 Specification Requirements
    SPEC_URL = "https://modelcontextprotocol.io/specification/2025-11-25"

    # Valid annotation keys per MCP spec
    VALID_ANNOTATION_KEYS: set[str] = {
        "title",
        "readOnlyHint",
        "destructiveHint",
        "idempotentHint",
        "openWorldHint",
    }

    def __init__(
        self,
        check_required: bool = True,
        check_recommended: bool = True,
        check_optional: bool = False,
        strict_annotations: bool = True,
    ):
        """
        Initialize the compliance checker.

        Args:
            check_required: Check MCP specification requirements
            check_recommended: Check security best practices
            check_optional: Check optional enterprise standards
            strict_annotations: Fail on unknown annotation keys
        """
        self.check_required = check_required
        self.check_recommended = check_recommended
        self.check_optional = check_optional
        self.strict_annotations = strict_annotations

    def check(self, tool: dict[str, Any]) -> ComplianceReport:
        """
        Check tool compliance against MCP standards.

        Args:
            tool: The tool definition to check

        Returns:
            ComplianceReport with all check results
        """
        checks: list[ComplianceCheck] = []
        tool_name = tool.get("name", "<unnamed>")

        # Required checks (MCP 2025-11-25 spec)
        if self.check_required:
            checks.extend(self._check_required_fields(tool))
            checks.extend(self._check_name_format(tool))
            checks.extend(self._check_schema_structure(tool))
            checks.extend(self._check_annotation_types(tool))

        # Recommended checks (Security best practices)
        if self.check_recommended:
            checks.extend(self._check_security_practices(tool))
            checks.extend(self._check_schema_quality(tool))
            checks.extend(self._check_description_quality(tool))

        # Optional checks (Enterprise standards)
        if self.check_optional:
            checks.extend(self._check_enterprise_standards(tool))

        # Calculate compliance
        required_passed = all(
            c.status in (ComplianceStatus.PASS, ComplianceStatus.SKIP)
            for c in checks
            if c.level == ComplianceLevel.REQUIRED
        )

        # Calculate score
        scorable_checks = [c for c in checks if c.status != ComplianceStatus.SKIP]
        if scorable_checks:
            weights = {
                ComplianceLevel.REQUIRED: 3,
                ComplianceLevel.RECOMMENDED: 2,
                ComplianceLevel.OPTIONAL: 1,
            }
            total_weight = sum(weights[c.level] for c in scorable_checks)
            passed_weight = sum(
                weights[c.level] for c in scorable_checks if c.status == ComplianceStatus.PASS
            )
            score = (passed_weight / total_weight) * 100
        else:
            score = 100.0

        return ComplianceReport(
            tool_name=tool_name,
            is_compliant=required_passed,
            checks=checks,
            compliance_score=score,
            metadata={
                "check_levels": {
                    "required": self.check_required,
                    "recommended": self.check_recommended,
                    "optional": self.check_optional,
                },
                "spec_version": "2025-11-25",
            },
        )

    def _check_required_fields(self, tool: dict[str, Any]) -> list[ComplianceCheck]:
        """Check required fields per MCP spec."""
        checks = []

        # MCP-REQ-001: name is required
        checks.append(
            ComplianceCheck(
                id="MCP-REQ-001",
                name="Tool name required",
                level=ComplianceLevel.REQUIRED,
                status=ComplianceStatus.PASS if "name" in tool else ComplianceStatus.FAIL,
                message="Tool name is present"
                if "name" in tool
                else "Tool name is missing (required)",
                spec_reference=f"{self.SPEC_URL}/server/tools",
            )
        )

        # MCP-REQ-002: description is required (per MCP spec - highly recommended)
        has_description = bool(tool.get("description"))
        checks.append(
            ComplianceCheck(
                id="MCP-REQ-002",
                name="Tool description required",
                level=ComplianceLevel.REQUIRED,
                status=ComplianceStatus.PASS if has_description else ComplianceStatus.FAIL,
                message="Tool description is present"
                if has_description
                else "Tool description is missing",
                spec_reference=f"{self.SPEC_URL}/server/tools",
            )
        )

        # MCP-REQ-003: inputSchema is required
        has_schema = "inputSchema" in tool
        checks.append(
            ComplianceCheck(
                id="MCP-REQ-003",
                name="Input schema required",
                level=ComplianceLevel.REQUIRED,
                status=ComplianceStatus.PASS if has_schema else ComplianceStatus.FAIL,
                message="inputSchema is present"
                if has_schema
                else "inputSchema is missing (required)",
                spec_reference=f"{self.SPEC_URL}/server/tools",
            )
        )

        return checks

    def _check_name_format(self, tool: dict[str, Any]) -> list[ComplianceCheck]:
        """Check tool name format requirements."""
        checks: list[ComplianceCheck] = []
        name = tool.get("name", "")

        if not name:
            return checks  # Already handled by required fields check

        # MCP-REQ-004: Name must be valid identifier
        import re

        is_valid_format = bool(re.match(r"^[a-zA-Z_][a-zA-Z0-9_-]*$", name))
        checks.append(
            ComplianceCheck(
                id="MCP-REQ-004",
                name="Valid tool name format",
                level=ComplianceLevel.REQUIRED,
                status=ComplianceStatus.PASS if is_valid_format else ComplianceStatus.FAIL,
                message="Name format is valid"
                if is_valid_format
                else f"Name '{name}' has invalid format",
                details="Must start with letter/underscore, contain only alphanumeric, underscore, hyphen",
                spec_reference=f"{self.SPEC_URL}/server/tools",
            )
        )

        # MCP-REQ-005: Name length limit
        max_length = 64
        is_valid_length = len(name) <= max_length
        checks.append(
            ComplianceCheck(
                id="MCP-REQ-005",
                name="Tool name length",
                level=ComplianceLevel.REQUIRED,
                status=ComplianceStatus.PASS if is_valid_length else ComplianceStatus.FAIL,
                message=f"Name length OK ({len(name)} chars)"
                if is_valid_length
                else f"Name too long ({len(name)} > {max_length})",
            )
        )

        return checks

    def _check_schema_structure(self, tool: dict[str, Any]) -> list[ComplianceCheck]:
        """Check input schema structure requirements."""
        checks: list[ComplianceCheck] = []
        schema = tool.get("inputSchema")

        if not schema:
            return checks  # Already handled by required fields check

        # MCP-REQ-006: Schema must be object type
        if not isinstance(schema, dict):
            checks.append(
                ComplianceCheck(
                    id="MCP-REQ-006",
                    name="Schema is object",
                    level=ComplianceLevel.REQUIRED,
                    status=ComplianceStatus.FAIL,
                    message="inputSchema must be an object",
                )
            )
            return checks

        # MCP-REQ-007: Root type must be "object"
        root_type = schema.get("type")
        is_object = root_type == "object"
        checks.append(
            ComplianceCheck(
                id="MCP-REQ-007",
                name="Schema root type",
                level=ComplianceLevel.REQUIRED,
                status=ComplianceStatus.PASS if is_object else ComplianceStatus.FAIL,
                message="Root type is 'object'"
                if is_object
                else f"Root type must be 'object', got '{root_type}'",
                spec_reference=f"{self.SPEC_URL}/server/tools",
            )
        )

        # MCP-REQ-008: Valid JSON Schema structure
        has_properties = "properties" in schema or schema.get("additionalProperties") is not None
        checks.append(
            ComplianceCheck(
                id="MCP-REQ-008",
                name="Schema has structure",
                level=ComplianceLevel.REQUIRED,
                status=ComplianceStatus.PASS if has_properties else ComplianceStatus.WARN,
                message="Schema defines structure"
                if has_properties
                else "Schema has no properties defined",
            )
        )

        # MCP-REQ-009: Required properties exist in properties
        required = schema.get("required", [])
        properties = schema.get("properties", {})

        if required and isinstance(required, list):
            missing = [r for r in required if r not in properties]
            all_present = len(missing) == 0
            checks.append(
                ComplianceCheck(
                    id="MCP-REQ-009",
                    name="Required properties defined",
                    level=ComplianceLevel.REQUIRED,
                    status=ComplianceStatus.PASS if all_present else ComplianceStatus.FAIL,
                    message="All required properties are defined"
                    if all_present
                    else f"Missing required properties: {missing}",
                )
            )

        return checks

    def _check_annotation_types(self, tool: dict[str, Any]) -> list[ComplianceCheck]:
        """Check annotation type correctness."""
        checks: list[ComplianceCheck] = []
        annotations = tool.get("annotations")

        if annotations is None:
            return checks  # Annotations are optional

        if not isinstance(annotations, dict):
            checks.append(
                ComplianceCheck(
                    id="MCP-REQ-010",
                    name="Annotations type",
                    level=ComplianceLevel.REQUIRED,
                    status=ComplianceStatus.FAIL,
                    message="annotations must be an object",
                )
            )
            return checks

        # MCP-REQ-011: Check known annotation types
        type_checks = {
            "title": str,
            "readOnlyHint": bool,
            "destructiveHint": bool,
            "idempotentHint": bool,
            "openWorldHint": bool,
        }

        for key, expected_type in type_checks.items():
            if key in annotations:
                value = annotations[key]
                is_correct_type = isinstance(value, expected_type)
                checks.append(
                    ComplianceCheck(
                        id=f"MCP-REQ-011-{key}",
                        name=f"Annotation '{key}' type",
                        level=ComplianceLevel.REQUIRED,
                        status=ComplianceStatus.PASS if is_correct_type else ComplianceStatus.FAIL,
                        message=f"'{key}' is {expected_type.__name__}"
                        if is_correct_type
                        else f"'{key}' must be {expected_type.__name__}, got {type(value).__name__}",
                        spec_reference=f"{self.SPEC_URL}/server/tools#annotations",
                    )
                )

        # Check for unknown annotation keys
        if self.strict_annotations:
            unknown_keys = set(annotations.keys()) - self.VALID_ANNOTATION_KEYS
            if unknown_keys:
                checks.append(
                    ComplianceCheck(
                        id="MCP-REQ-012",
                        name="Unknown annotations",
                        level=ComplianceLevel.RECOMMENDED,
                        status=ComplianceStatus.WARN,
                        message=f"Unknown annotation keys: {unknown_keys}",
                        details="Consider using only standard MCP annotation keys",
                    )
                )

        return checks

    def _check_security_practices(self, tool: dict[str, Any]) -> list[ComplianceCheck]:
        """Check 2026 security best practices."""
        checks = []
        schema = tool.get("inputSchema") or {}
        if not isinstance(schema, dict):
            schema = {}

        # SEC-001: additionalProperties should be false
        additional_props = schema.get("additionalProperties", True)
        is_restricted = additional_props is False
        checks.append(
            ComplianceCheck(
                id="SEC-001",
                name="Restrict additional properties",
                level=ComplianceLevel.RECOMMENDED,
                status=ComplianceStatus.PASS if is_restricted else ComplianceStatus.WARN,
                message="additionalProperties is false"
                if is_restricted
                else "additionalProperties should be false for security",
                details="Prevents injection of unexpected parameters",
            )
        )

        # SEC-002: Destructive tools should have annotations
        name = (tool.get("name") or "").lower()
        description = (tool.get("description") or "").lower()
        annotations = tool.get("annotations") or {}
        if not isinstance(annotations, dict):
            annotations = {}

        destructive_indicators = [
            "delete",
            "remove",
            "drop",
            "truncate",
            "destroy",
            "erase",
            "clear",
        ]
        appears_destructive = any(
            ind in name or ind in description for ind in destructive_indicators
        )
        has_destructive_hint = annotations.get("destructiveHint") is True

        if appears_destructive:
            checks.append(
                ComplianceCheck(
                    id="SEC-002",
                    name="Destructive hint for dangerous tools",
                    level=ComplianceLevel.RECOMMENDED,
                    status=ComplianceStatus.PASS if has_destructive_hint else ComplianceStatus.WARN,
                    message="Destructive tool has destructiveHint annotation"
                    if has_destructive_hint
                    else "Tool appears destructive but lacks destructiveHint annotation",
                    details="Helps clients warn users before executing destructive operations",
                )
            )

        # SEC-003: URL/file properties should have validation
        properties = schema.get("properties", {})
        for prop_name, prop_schema in properties.items():
            if not isinstance(prop_schema, dict):
                continue

            prop_format = prop_schema.get("format", "")
            prop_schema.get("type", "")

            # Check URL properties
            if prop_format in ("uri", "url") or "url" in prop_name.lower():
                has_pattern = "pattern" in prop_schema
                checks.append(
                    ComplianceCheck(
                        id=f"SEC-003-{prop_name}",
                        name=f"URL property '{prop_name}' validation",
                        level=ComplianceLevel.RECOMMENDED,
                        status=ComplianceStatus.PASS if has_pattern else ComplianceStatus.WARN,
                        message="URL property has pattern validation"
                        if has_pattern
                        else f"URL property '{prop_name}' should have pattern validation",
                        details="Prevents SSRF attacks by restricting allowed URLs",
                    )
                )

            # Check file/path properties
            if any(hint in prop_name.lower() for hint in ["file", "path", "directory"]):
                has_pattern = "pattern" in prop_schema
                checks.append(
                    ComplianceCheck(
                        id=f"SEC-004-{prop_name}",
                        name=f"Path property '{prop_name}' validation",
                        level=ComplianceLevel.RECOMMENDED,
                        status=ComplianceStatus.PASS if has_pattern else ComplianceStatus.WARN,
                        message="Path property has pattern validation"
                        if has_pattern
                        else f"Path property '{prop_name}' should have pattern validation",
                        details="Prevents path traversal attacks",
                    )
                )

        return checks

    def _check_schema_quality(self, tool: dict[str, Any]) -> list[ComplianceCheck]:
        """Check input schema quality."""
        checks: list[ComplianceCheck] = []
        schema = tool.get("inputSchema") or {}
        if not isinstance(schema, dict):
            return checks
        properties = schema.get("properties") or {}
        if not isinstance(properties, dict):
            properties = {}

        # QUAL-001: Properties should have descriptions
        props_with_descriptions = sum(
            1 for p in properties.values() if isinstance(p, dict) and p.get("description")
        )
        total_props = len(properties)

        if total_props > 0:
            ratio = props_with_descriptions / total_props
            is_good = ratio >= 0.8  # 80% threshold
            checks.append(
                ComplianceCheck(
                    id="QUAL-001",
                    name="Property descriptions",
                    level=ComplianceLevel.RECOMMENDED,
                    status=ComplianceStatus.PASS if is_good else ComplianceStatus.WARN,
                    message=f"{props_with_descriptions}/{total_props} properties have descriptions",
                    details="Property descriptions help AI understand parameter usage",
                )
            )

        # QUAL-002: Properties should have types
        props_with_types = sum(
            1
            for p in properties.values()
            if isinstance(p, dict) and ("type" in p or "anyOf" in p or "oneOf" in p)
        )

        if total_props > 0:
            ratio = props_with_types / total_props
            is_good = ratio >= 0.9  # 90% threshold
            checks.append(
                ComplianceCheck(
                    id="QUAL-002",
                    name="Property types",
                    level=ComplianceLevel.RECOMMENDED,
                    status=ComplianceStatus.PASS if is_good else ComplianceStatus.WARN,
                    message=f"{props_with_types}/{total_props} properties have types",
                    details="Type definitions enable proper validation",
                )
            )

        # QUAL-003: String properties should have constraints
        string_props = [
            (name, p)
            for name, p in properties.items()
            if isinstance(p, dict) and p.get("type") == "string"
        ]
        constrained_strings = sum(
            1
            for _, p in string_props
            if any(k in p for k in ["maxLength", "pattern", "format", "enum"])
        )

        if string_props:
            ratio = constrained_strings / len(string_props)
            is_good = ratio >= 0.5  # 50% threshold
            checks.append(
                ComplianceCheck(
                    id="QUAL-003",
                    name="String constraints",
                    level=ComplianceLevel.RECOMMENDED,
                    status=ComplianceStatus.PASS if is_good else ComplianceStatus.WARN,
                    message=f"{constrained_strings}/{len(string_props)} string properties have constraints",
                    details="Constraints (maxLength, pattern, enum) prevent abuse",
                )
            )

        return checks

    def _check_description_quality(self, tool: dict[str, Any]) -> list[ComplianceCheck]:
        """Check tool description quality."""
        checks = []
        description = tool.get("description") or ""

        # QUAL-004: Description length
        min_length = 20
        max_length = 2000
        desc_length = len(description)

        if desc_length < min_length:
            status = ComplianceStatus.WARN
            message = f"Description too short ({desc_length} chars, minimum {min_length})"
        elif desc_length > max_length:
            status = ComplianceStatus.WARN
            message = f"Description too long ({desc_length} chars, maximum {max_length})"
        else:
            status = ComplianceStatus.PASS
            message = f"Description length OK ({desc_length} chars)"

        checks.append(
            ComplianceCheck(
                id="QUAL-004",
                name="Description length",
                level=ComplianceLevel.RECOMMENDED,
                status=status,
                message=message,
                details="Good descriptions are concise but informative",
            )
        )

        # QUAL-005: Description should explain what tool does
        action_words = [
            "returns",
            "gets",
            "creates",
            "updates",
            "deletes",
            "sends",
            "reads",
            "writes",
            "performs",
            "executes",
        ]
        has_action = any(word in description.lower() for word in action_words)
        checks.append(
            ComplianceCheck(
                id="QUAL-005",
                name="Description clarity",
                level=ComplianceLevel.RECOMMENDED,
                status=ComplianceStatus.PASS if has_action else ComplianceStatus.WARN,
                message="Description explains tool action"
                if has_action
                else "Description should explain what the tool does",
            )
        )

        return checks

    def _check_enterprise_standards(self, tool: dict[str, Any]) -> list[ComplianceCheck]:
        """Check optional enterprise security standards."""
        checks = []
        annotations = tool.get("annotations") or {}
        if not isinstance(annotations, dict):
            annotations = {}

        # ENT-001: Tool should have all hint annotations
        hint_keys = ["readOnlyHint", "destructiveHint", "idempotentHint"]
        has_all_hints = all(key in annotations for key in hint_keys)
        checks.append(
            ComplianceCheck(
                id="ENT-001",
                name="Complete annotations",
                level=ComplianceLevel.OPTIONAL,
                status=ComplianceStatus.PASS if has_all_hints else ComplianceStatus.WARN,
                message="All behavioral hints present"
                if has_all_hints
                else f"Missing hints: {[k for k in hint_keys if k not in annotations]}",
                details="Complete annotations enable better access control",
            )
        )

        # ENT-002: Schema should have $schema declaration
        schema = tool.get("inputSchema") or {}
        if not isinstance(schema, dict):
            schema = {}
        has_schema_decl = "$schema" in schema
        checks.append(
            ComplianceCheck(
                id="ENT-002",
                name="Schema declaration",
                level=ComplianceLevel.OPTIONAL,
                status=ComplianceStatus.PASS if has_schema_decl else ComplianceStatus.WARN,
                message="$schema declaration present"
                if has_schema_decl
                else "Missing $schema declaration",
                details="Explicit schema version enables proper validation",
            )
        )

        return checks

    def check_batch(self, tools: list[dict[str, Any]]) -> dict[str, ComplianceReport]:
        """
        Check multiple tools.

        Args:
            tools: List of tool definitions

        Returns:
            Dict mapping tool names to compliance reports
        """
        results = {}
        for tool in tools:
            name = tool.get("name", f"<unnamed_{id(tool)}>")
            results[name] = self.check(tool)
        return results
