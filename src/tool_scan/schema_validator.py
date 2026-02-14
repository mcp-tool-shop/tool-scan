"""
Schema Validator
================

Deep JSON Schema validation for MCP tool inputSchema.

Supports:
- JSON Schema draft-07
- JSON Schema 2020-12
- MCP-specific schema requirements
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any


class SchemaDialect(Enum):
    """Supported JSON Schema dialects."""

    DRAFT_07 = "draft-07"
    DRAFT_2020_12 = "2020-12"
    UNKNOWN = "unknown"


@dataclass
class SchemaIssue:
    """An issue found during schema validation."""

    path: str
    message: str
    is_error: bool = True
    suggestion: str | None = None


class SchemaValidator:
    """
    Validates JSON Schema definitions for MCP tools.

    Ensures schemas are:
    - Syntactically correct
    - Semantically valid
    - Following best practices
    - Free of common vulnerabilities
    """

    # Valid JSON Schema types
    VALID_TYPES: set[str] = {"string", "number", "integer", "boolean", "array", "object", "null"}

    # Valid string formats (draft-07 + 2020-12)
    VALID_FORMATS: set[str] = {
        # Date/time
        "date-time",
        "date",
        "time",
        "duration",
        # Email/URI
        "email",
        "idn-email",
        "hostname",
        "idn-hostname",
        "uri",
        "uri-reference",
        "iri",
        "iri-reference",
        "uri-template",
        # Identifiers
        "uuid",
        "json-pointer",
        "relative-json-pointer",
        # Network
        "ipv4",
        "ipv6",
        # Regex
        "regex",
    }

    # Keywords that should be objects
    OBJECT_KEYWORDS: set[str] = {
        "properties",
        "patternProperties",
        "additionalProperties",
        "items",
        "additionalItems",
        "contains",
        "propertyNames",
        "if",
        "then",
        "else",
        "dependentSchemas",
        "$defs",
        "definitions",
    }

    # Keywords that should be arrays
    ARRAY_KEYWORDS: set[str] = {
        "required",
        "enum",
        "allOf",
        "anyOf",
        "oneOf",
        "prefixItems",
        "type",  # type can be array in some cases
    }

    def __init__(self, strict: bool = True):
        """
        Initialize the schema validator.

        Args:
            strict: If True, enforce best practices as errors
        """
        self.strict = strict

    def validate(self, schema: dict[str, Any]) -> tuple[bool, list[SchemaIssue]]:
        """
        Validate a JSON Schema.

        Args:
            schema: The schema to validate

        Returns:
            Tuple of (is_valid, issues_list)
        """
        issues: list[SchemaIssue] = []

        if not isinstance(schema, dict):
            issues.append(
                SchemaIssue(
                    path="$",
                    message="Schema must be an object",
                )
            )
            return False, issues

        # Detect dialect
        dialect = self._detect_dialect(schema)

        # Validate structure recursively
        self._validate_schema_node(schema, "$", dialect, issues)

        # Check MCP-specific requirements
        self._validate_mcp_requirements(schema, issues)

        is_valid = not any(issue.is_error for issue in issues)
        return is_valid, issues

    def _detect_dialect(self, schema: dict[str, Any]) -> SchemaDialect:
        """Detect which JSON Schema dialect is being used."""
        schema_uri = schema.get("$schema", "")

        if "2020-12" in schema_uri:
            return SchemaDialect.DRAFT_2020_12
        elif "draft-07" in schema_uri:
            return SchemaDialect.DRAFT_07
        else:
            # Default to draft-07 for MCP compatibility
            return SchemaDialect.DRAFT_07

    def _validate_schema_node(
        self,
        node: Any,
        path: str,
        dialect: SchemaDialect,
        issues: list[SchemaIssue],
    ) -> None:
        """Recursively validate a schema node."""

        # Boolean schemas (true/false) are valid in draft-07+
        if isinstance(node, bool):
            return

        if not isinstance(node, dict):
            issues.append(
                SchemaIssue(
                    path=path,
                    message=f"Schema node must be object or boolean, got {type(node).__name__}",
                )
            )
            return

        # Validate type keyword
        if "type" in node:
            self._validate_type(node["type"], path, issues)

        # Validate format keyword
        if "format" in node:
            self._validate_format(node["format"], path, issues)

        # Validate numeric constraints
        self._validate_numeric_constraints(node, path, issues)

        # Validate string constraints
        self._validate_string_constraints(node, path, issues)

        # Validate array constraints
        self._validate_array_constraints(node, path, dialect, issues)

        # Validate object constraints
        self._validate_object_constraints(node, path, dialect, issues)

        # Validate conditional keywords
        self._validate_conditionals(node, path, dialect, issues)

        # Validate composition keywords (allOf, anyOf, oneOf)
        self._validate_composition(node, path, dialect, issues)

        # Recurse into nested schemas
        self._recurse_nested_schemas(node, path, dialect, issues)

    def _validate_type(self, type_value: Any, path: str, issues: list[SchemaIssue]) -> None:
        """Validate the type keyword."""
        if isinstance(type_value, str):
            if type_value not in self.VALID_TYPES:
                issues.append(
                    SchemaIssue(
                        path=f"{path}.type",
                        message=f"Invalid type '{type_value}'",
                        suggestion=f"Valid types: {', '.join(sorted(self.VALID_TYPES))}",
                    )
                )
        elif isinstance(type_value, list):
            for i, t in enumerate(type_value):
                if not isinstance(t, str) or t not in self.VALID_TYPES:
                    issues.append(
                        SchemaIssue(
                            path=f"{path}.type[{i}]",
                            message=f"Invalid type in array: '{t}'",
                        )
                    )
        else:
            issues.append(
                SchemaIssue(
                    path=f"{path}.type",
                    message="type must be string or array of strings",
                )
            )

    def _validate_format(self, format_value: Any, path: str, issues: list[SchemaIssue]) -> None:
        """Validate the format keyword."""
        if not isinstance(format_value, str):
            issues.append(
                SchemaIssue(
                    path=f"{path}.format",
                    message="format must be a string",
                )
            )
            return

        if format_value not in self.VALID_FORMATS:
            issues.append(
                SchemaIssue(
                    path=f"{path}.format",
                    message=f"Unknown format '{format_value}'",
                    is_error=False,  # Custom formats are allowed
                    suggestion="Consider using a standard format if applicable",
                )
            )

    def _validate_numeric_constraints(
        self,
        node: dict[str, Any],
        path: str,
        issues: list[SchemaIssue],
    ) -> None:
        """Validate numeric constraint keywords."""
        numeric_keywords = {
            "minimum": (int, float),
            "maximum": (int, float),
            "exclusiveMinimum": (int, float),
            "exclusiveMaximum": (int, float),
            "multipleOf": (int, float),
        }

        for keyword, expected_types in numeric_keywords.items():
            if keyword in node:
                value = node[keyword]
                if not isinstance(value, expected_types):
                    issues.append(
                        SchemaIssue(
                            path=f"{path}.{keyword}",
                            message=f"{keyword} must be a number",
                        )
                    )

        # Check logical consistency
        minimum = node.get("minimum")
        maximum = node.get("maximum")
        if (
            minimum is not None
            and maximum is not None
            and isinstance(minimum, (int, float))
            and isinstance(maximum, (int, float))
            and minimum > maximum
        ):
            issues.append(
                SchemaIssue(
                    path=path,
                    message="minimum cannot be greater than maximum",
                )
            )

    def _validate_string_constraints(
        self,
        node: dict[str, Any],
        path: str,
        issues: list[SchemaIssue],
    ) -> None:
        """Validate string constraint keywords."""
        if "minLength" in node and (not isinstance(node["minLength"], int) or node["minLength"] < 0):
            issues.append(
                SchemaIssue(
                    path=f"{path}.minLength",
                    message="minLength must be a non-negative integer",
                )
            )

        if "maxLength" in node and (not isinstance(node["maxLength"], int) or node["maxLength"] < 0):
            issues.append(
                SchemaIssue(
                    path=f"{path}.maxLength",
                    message="maxLength must be a non-negative integer",
                )
            )

        # Check pattern is valid regex
        if "pattern" in node:
            pattern = node["pattern"]
            if isinstance(pattern, str):
                try:
                    re.compile(pattern)
                except re.error as e:
                    issues.append(
                        SchemaIssue(
                            path=f"{path}.pattern",
                            message=f"Invalid regex pattern: {e}",
                        )
                    )
            else:
                issues.append(
                    SchemaIssue(
                        path=f"{path}.pattern",
                        message="pattern must be a string",
                    )
                )

        # Check logical consistency
        min_len = node.get("minLength", 0)
        max_len = node.get("maxLength")
        if (
            max_len is not None
            and isinstance(min_len, int)
            and isinstance(max_len, int)
            and min_len > max_len
        ):
            issues.append(
                SchemaIssue(
                    path=path,
                    message="minLength cannot be greater than maxLength",
                )
            )

    def _validate_array_constraints(
        self,
        node: dict[str, Any],
        path: str,
        dialect: SchemaDialect,
        issues: list[SchemaIssue],
    ) -> None:
        """Validate array constraint keywords."""
        if "minItems" in node and (not isinstance(node["minItems"], int) or node["minItems"] < 0):
            issues.append(
                SchemaIssue(
                    path=f"{path}.minItems",
                    message="minItems must be a non-negative integer",
                )
            )

        if "maxItems" in node and (not isinstance(node["maxItems"], int) or node["maxItems"] < 0):
            issues.append(
                SchemaIssue(
                    path=f"{path}.maxItems",
                    message="maxItems must be a non-negative integer",
                )
            )

        if "uniqueItems" in node and not isinstance(node["uniqueItems"], bool):
            issues.append(
                SchemaIssue(
                    path=f"{path}.uniqueItems",
                    message="uniqueItems must be a boolean",
                )
            )

        # items validation
        if "items" in node:
            items = node["items"]
            if dialect == SchemaDialect.DRAFT_2020_12 and isinstance(items, list):
                # In 2020-12, items is a single schema
                issues.append(
                        SchemaIssue(
                            path=f"{path}.items",
                            message="In 2020-12, use prefixItems for tuple validation",
                            is_error=False,
                            suggestion="Replace items array with prefixItems",
                        )
                    )

        # Check logical consistency
        min_items = node.get("minItems", 0)
        max_items = node.get("maxItems")
        if (
            max_items is not None
            and isinstance(min_items, int)
            and isinstance(max_items, int)
            and min_items > max_items
        ):
            issues.append(
                SchemaIssue(
                    path=path,
                    message="minItems cannot be greater than maxItems",
                )
            )

    def _validate_object_constraints(
        self,
        node: dict[str, Any],
        path: str,
        dialect: SchemaDialect,
        issues: list[SchemaIssue],
    ) -> None:
        """Validate object constraint keywords."""
        if "minProperties" in node and (
            not isinstance(node["minProperties"], int) or node["minProperties"] < 0
        ):
            issues.append(
                SchemaIssue(
                    path=f"{path}.minProperties",
                    message="minProperties must be a non-negative integer",
                )
            )

        if "maxProperties" in node and (
            not isinstance(node["maxProperties"], int) or node["maxProperties"] < 0
        ):
            issues.append(
                SchemaIssue(
                    path=f"{path}.maxProperties",
                    message="maxProperties must be a non-negative integer",
                )
            )

        # required validation
        if "required" in node:
            required = node["required"]
            if not isinstance(required, list):
                issues.append(
                    SchemaIssue(
                        path=f"{path}.required",
                        message="required must be an array",
                    )
                )
            else:
                seen = set()
                for i, item in enumerate(required):
                    if not isinstance(item, str):
                        issues.append(
                            SchemaIssue(
                                path=f"{path}.required[{i}]",
                                message="required items must be strings",
                            )
                        )
                    elif item in seen:
                        issues.append(
                            SchemaIssue(
                                path=f"{path}.required[{i}]",
                                message=f"Duplicate required property: '{item}'",
                            )
                        )
                    seen.add(item)

        # properties validation
        if "properties" in node:
            props = node["properties"]
            if not isinstance(props, dict):
                issues.append(
                    SchemaIssue(
                        path=f"{path}.properties",
                        message="properties must be an object",
                    )
                )

        # additionalProperties validation
        if "additionalProperties" in node:
            additional = node["additionalProperties"]
            if not isinstance(additional, (bool, dict)):
                issues.append(
                    SchemaIssue(
                        path=f"{path}.additionalProperties",
                        message="additionalProperties must be boolean or schema",
                    )
                )

    def _validate_conditionals(
        self,
        node: dict[str, Any],
        path: str,
        dialect: SchemaDialect,
        issues: list[SchemaIssue],
    ) -> None:
        """Validate conditional keywords (if/then/else)."""
        has_if = "if" in node
        has_then = "then" in node
        has_else = "else" in node

        if (has_then or has_else) and not has_if:
            issues.append(
                SchemaIssue(
                    path=path,
                    message="then/else require if keyword",
                    is_error=False,
                    suggestion="Add if condition or remove then/else",
                )
            )

        if has_if and not (has_then or has_else):
            issues.append(
                SchemaIssue(
                    path=path,
                    message="if without then/else has no effect",
                    is_error=False,
                )
            )

    def _validate_composition(
        self,
        node: dict[str, Any],
        path: str,
        dialect: SchemaDialect,
        issues: list[SchemaIssue],
    ) -> None:
        """Validate composition keywords (allOf, anyOf, oneOf)."""
        for keyword in ("allOf", "anyOf", "oneOf"):
            if keyword in node:
                value = node[keyword]
                if not isinstance(value, list):
                    issues.append(
                        SchemaIssue(
                            path=f"{path}.{keyword}",
                            message=f"{keyword} must be an array",
                        )
                    )
                elif len(value) == 0:
                    issues.append(
                        SchemaIssue(
                            path=f"{path}.{keyword}",
                            message=f"{keyword} must have at least one item",
                        )
                    )

        if "not" in node and not isinstance(node["not"], (dict, bool)):
            issues.append(
                SchemaIssue(
                    path=f"{path}.not",
                    message="not must be a schema",
                )
            )

    def _recurse_nested_schemas(
        self,
        node: dict[str, Any],
        path: str,
        dialect: SchemaDialect,
        issues: list[SchemaIssue],
    ) -> None:
        """Recursively validate nested schemas."""
        # Properties
        if "properties" in node and isinstance(node["properties"], dict):
            for prop_name, prop_schema in node["properties"].items():
                self._validate_schema_node(
                    prop_schema,
                    f"{path}.properties.{prop_name}",
                    dialect,
                    issues,
                )

        # Items (single schema or array in draft-07)
        if "items" in node:
            items = node["items"]
            if isinstance(items, dict):
                self._validate_schema_node(items, f"{path}.items", dialect, issues)
            elif isinstance(items, list):
                for i, item in enumerate(items):
                    self._validate_schema_node(item, f"{path}.items[{i}]", dialect, issues)

        # prefixItems (2020-12)
        if "prefixItems" in node and isinstance(node["prefixItems"], list):
            for i, item in enumerate(node["prefixItems"]):
                self._validate_schema_node(item, f"{path}.prefixItems[{i}]", dialect, issues)

        # additionalProperties
        if "additionalProperties" in node:
            additional = node["additionalProperties"]
            if isinstance(additional, dict):
                self._validate_schema_node(
                    additional, f"{path}.additionalProperties", dialect, issues
                )

        # Composition keywords
        for keyword in ("allOf", "anyOf", "oneOf"):
            if keyword in node and isinstance(node[keyword], list):
                for i, sub_schema in enumerate(node[keyword]):
                    self._validate_schema_node(
                        sub_schema, f"{path}.{keyword}[{i}]", dialect, issues
                    )

        # Conditionals
        for keyword in ("if", "then", "else"):
            if keyword in node:
                self._validate_schema_node(node[keyword], f"{path}.{keyword}", dialect, issues)

        # not
        if "not" in node and isinstance(node["not"], dict):
            self._validate_schema_node(node["not"], f"{path}.not", dialect, issues)

        # $defs / definitions
        defs_key = "$defs" if dialect == SchemaDialect.DRAFT_2020_12 else "definitions"
        if defs_key in node and isinstance(node[defs_key], dict):
            for def_name, def_schema in node[defs_key].items():
                self._validate_schema_node(
                    def_schema, f"{path}.{defs_key}.{def_name}", dialect, issues
                )

    def _validate_mcp_requirements(
        self,
        schema: dict[str, Any],
        issues: list[SchemaIssue],
    ) -> None:
        """Validate MCP-specific schema requirements."""
        # Root type must be object
        root_type = schema.get("type")
        if root_type != "object":
            issues.append(
                SchemaIssue(
                    path="$.type",
                    message="MCP tool inputSchema must have type 'object' at root",
                )
            )

        # Should have properties defined
        if "properties" not in schema:
            issues.append(
                SchemaIssue(
                    path="$",
                    message="MCP tool inputSchema should define properties",
                    is_error=False,
                    suggestion="Add properties to define the tool's input parameters",
                )
            )

        # Best practice: additionalProperties should be false
        if schema.get("additionalProperties") is not False:
            issues.append(
                SchemaIssue(
                    path="$.additionalProperties",
                    message="MCP best practice: set additionalProperties to false",
                    is_error=self.strict,
                    suggestion="Prevents unexpected input parameters",
                )
            )
