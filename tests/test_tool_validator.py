"""
Tests for MCPToolValidator.

Tests validation of:
- Tool name requirements
- Description requirements
- Input schema structure
- Annotations
- Security scanning integration
"""

from __future__ import annotations

import pytest

from tool_scan import (
    MCPToolValidator,
    ValidationSeverity,
    ValidationResult,
)


class TestMCPToolValidator:
    """Test suite for MCPToolValidator."""

    @pytest.fixture
    def validator(self) -> MCPToolValidator:
        """Create default validator instance."""
        return MCPToolValidator(strict_mode=True, check_security=True)

    @pytest.fixture
    def lenient_validator(self) -> MCPToolValidator:
        """Create lenient validator (warnings don't fail)."""
        return MCPToolValidator(strict_mode=False, check_security=True)


    # =========================================================================
    # VALID TOOL TESTS
    # =========================================================================

    def test_valid_minimal_tool(self, validator, valid_minimal_tool):
        """Minimal valid tool should pass validation."""
        result = validator.validate(valid_minimal_tool)

        assert result.is_valid, f"Expected valid, got issues: {[str(i) for i in result.errors]}"
        assert result.tool_name == "get_weather"
        assert result.score >= 80  # Allow some warnings

    def test_valid_complete_tool(self, validator, valid_complete_tool):
        """Fully specified tool should pass with high score."""
        result = validator.validate(valid_complete_tool)

        assert result.is_valid
        assert result.tool_name == "search_database"
        assert result.score >= 90  # High quality tool

    def test_valid_destructive_tool(self, validator, valid_destructive_tool):
        """Properly annotated destructive tool should pass."""
        result = validator.validate(valid_destructive_tool)

        # Should pass but have warning about destructive annotation
        assert result.is_valid or any(
            i.code == "ANNOTATION_DESTRUCTIVE" for i in result.issues
        )


    # =========================================================================
    # NAME VALIDATION TESTS
    # =========================================================================

    def test_missing_name_fails(self, validator, missing_name_tool):
        """Tool without name should fail."""
        result = validator.validate(missing_name_tool)

        assert not result.is_valid
        assert any(i.code == "NAME_MISSING" for i in result.errors)

    def test_invalid_name_format_fails(self, validator, invalid_name_format_tool):
        """Tool with invalid name format should fail."""
        result = validator.validate(invalid_name_format_tool)

        assert not result.is_valid
        assert any(i.code == "NAME_INVALID_FORMAT" for i in result.errors)

    def test_reserved_name_fails(self, validator, reserved_name_tool):
        """Tool using reserved name should fail with CRITICAL."""
        result = validator.validate(reserved_name_tool)

        assert not result.is_valid
        critical = [i for i in result.issues if i.severity == ValidationSeverity.CRITICAL]
        assert len(critical) > 0
        assert any(i.code == "NAME_RESERVED" for i in critical)

    def test_name_length_limit(self, validator):
        """Name exceeding length limit should fail."""
        long_name_tool = {
            "name": "a" * 100,  # Exceeds 64 char limit
            "description": "Test tool",
            "inputSchema": {"type": "object", "properties": {}},
        }
        result = validator.validate(long_name_tool)

        assert not result.is_valid
        assert any(i.code == "NAME_TOO_LONG" for i in result.errors)

    def test_underscore_prefix_warning(self, lenient_validator):
        """Name starting with underscore should warn."""
        tool = {
            "name": "_internal_tool",
            "description": "Internal tool",
            "inputSchema": {"type": "object", "properties": {}},
        }
        result = lenient_validator.validate(tool)

        # Should pass in lenient mode but have warning
        assert result.is_valid
        assert any(i.code == "NAME_UNDERSCORE_PREFIX" for i in result.warnings)


    # =========================================================================
    # DESCRIPTION VALIDATION TESTS
    # =========================================================================

    def test_missing_description_fails(self, validator, missing_description_tool):
        """Tool without description should fail."""
        result = validator.validate(missing_description_tool)

        assert not result.is_valid
        assert any(i.code == "DESCRIPTION_MISSING" for i in result.errors)

    def test_short_description_warns(self, lenient_validator):
        """Very short description should warn."""
        tool = {
            "name": "test",
            "description": "Short",  # Less than 10 chars
            "inputSchema": {"type": "object", "properties": {}},
        }
        result = lenient_validator.validate(tool)

        assert any(i.code == "DESCRIPTION_TOO_SHORT" for i in result.warnings)

    def test_long_description_fails(self, validator):
        """Description exceeding limit should fail."""
        tool = {
            "name": "test",
            "description": "x" * 5000,  # Exceeds 4096 limit
            "inputSchema": {"type": "object", "properties": {}},
        }
        result = validator.validate(tool)

        assert not result.is_valid
        assert any(i.code == "DESCRIPTION_TOO_LONG" for i in result.errors)


    # =========================================================================
    # INPUT SCHEMA VALIDATION TESTS
    # =========================================================================

    def test_missing_schema_fails(self, validator, missing_schema_tool):
        """Tool without inputSchema should fail."""
        result = validator.validate(missing_schema_tool)

        assert not result.is_valid
        assert any(i.code == "INPUT_SCHEMA_MISSING" for i in result.errors)

    def test_non_object_schema_fails(self, validator, invalid_schema_type_tool):
        """Schema with non-object root type should fail."""
        result = validator.validate(invalid_schema_type_tool)

        assert not result.is_valid
        assert any(i.code == "INPUT_SCHEMA_NOT_OBJECT" for i in result.errors)

    def test_schema_not_dict_fails(self, validator):
        """Schema that is not a dict should fail."""
        tool = {
            "name": "test",
            "description": "Test tool",
            "inputSchema": "not a dict",
        }
        result = validator.validate(tool)

        assert not result.is_valid
        assert any(i.code == "INPUT_SCHEMA_INVALID_TYPE" for i in result.errors)

    def test_missing_required_property_fails(self, validator):
        """Required property not in properties should fail."""
        tool = {
            "name": "test",
            "description": "Test tool",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "a": {"type": "string"},
                },
                "required": ["a", "b"],  # b is not defined
            },
        }
        result = validator.validate(tool)

        assert not result.is_valid
        assert any(i.code == "INPUT_SCHEMA_REQUIRED_MISSING" for i in result.errors)

    def test_additional_properties_warning(self, lenient_validator):
        """additionalProperties: true should warn."""
        tool = {
            "name": "test",
            "description": "Test tool",
            "inputSchema": {
                "type": "object",
                "properties": {},
                # additionalProperties defaults to true
            },
        }
        result = lenient_validator.validate(tool)

        assert any(i.code == "INPUT_SCHEMA_ADDITIONAL_PROPS" for i in result.warnings)


    # =========================================================================
    # ANNOTATION VALIDATION TESTS
    # =========================================================================

    def test_missing_annotations_info(self, lenient_validator):
        """Missing annotations should generate INFO level issue."""
        tool = {
            "name": "test",
            "description": "Test tool",
            "inputSchema": {"type": "object", "properties": {}},
            # No annotations
        }
        result = lenient_validator.validate(tool)

        info_issues = [i for i in result.issues if i.severity == ValidationSeverity.INFO]
        assert any(i.code == "ANNOTATIONS_MISSING" for i in info_issues)

    def test_invalid_annotation_type_fails(self, validator):
        """Annotations with wrong types should fail."""
        tool = {
            "name": "test",
            "description": "Test tool",
            "inputSchema": {"type": "object", "properties": {}},
            "annotations": {
                "destructiveHint": "yes",  # Should be bool
            },
        }
        result = validator.validate(tool)

        assert not result.is_valid
        assert any(i.code == "ANNOTATION_WRONG_TYPE" for i in result.errors)

    def test_annotations_not_dict_fails(self, validator):
        """Annotations that is not a dict should fail."""
        tool = {
            "name": "test",
            "description": "Test tool",
            "inputSchema": {"type": "object", "properties": {}},
            "annotations": ["not", "a", "dict"],
        }
        result = validator.validate(tool)

        assert not result.is_valid
        assert any(i.code == "ANNOTATIONS_INVALID_TYPE" for i in result.errors)

    def test_destructive_annotation_warns(self, lenient_validator):
        """Destructive tools should warn about user consent."""
        tool = {
            "name": "test",
            "description": "Test tool",
            "inputSchema": {"type": "object", "properties": {}},
            "annotations": {
                "destructiveHint": True,
            },
        }
        result = lenient_validator.validate(tool)

        assert any(i.code == "ANNOTATION_DESTRUCTIVE" for i in result.warnings)


    # =========================================================================
    # SECURITY SCANNING TESTS
    # =========================================================================

    def test_prompt_injection_detected(self, validator, prompt_injection_tool):
        """Prompt injection in description should be detected."""
        result = validator.validate(prompt_injection_tool)

        assert not result.is_valid
        critical = result.critical_issues
        assert len(critical) > 0
        assert any("DANGEROUS" in i.code for i in critical)

    def test_role_manipulation_detected(self, validator, role_manipulation_tool):
        """Role manipulation should be detected."""
        result = validator.validate(role_manipulation_tool)

        # Should have warnings or critical issues
        assert len(result.issues) > 0

    def test_covert_action_detected(self, validator, covert_action_tool):
        """Covert action instructions should be detected."""
        result = validator.validate(covert_action_tool)

        assert not result.is_valid
        critical = result.critical_issues
        assert len(critical) > 0

    def test_command_injection_default_detected(self, validator, command_injection_default_tool):
        """Command injection in default value should be detected."""
        result = validator.validate(command_injection_default_tool)

        assert not result.is_valid
        critical = result.critical_issues
        assert len(critical) > 0


    # =========================================================================
    # PROPERTY VALIDATION TESTS
    # =========================================================================

    def test_property_no_type_warns(self, lenient_validator):
        """Property without type should warn."""
        tool = {
            "name": "test",
            "description": "Test tool",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "untyped": {
                        "description": "No type defined",
                    },
                },
            },
        }
        result = lenient_validator.validate(tool)

        assert any(i.code == "PROPERTY_NO_TYPE" for i in result.warnings)

    def test_sensitive_property_name_warns(self, lenient_validator):
        """Sensitive property names should warn."""
        tool = {
            "name": "test",
            "description": "Test tool",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "api_key": {
                        "type": "string",
                        "description": "The API key",
                    },
                },
            },
        }
        result = lenient_validator.validate(tool)

        assert any(i.code == "PROPERTY_SENSITIVE_NAME" for i in result.warnings)


    # =========================================================================
    # SCORE CALCULATION TESTS
    # =========================================================================

    def test_perfect_tool_high_score(self, validator, valid_complete_tool):
        """Perfect tool should have high score."""
        result = validator.validate(valid_complete_tool)
        assert result.score >= 90

    def test_issues_reduce_score(self, validator, prompt_injection_tool):
        """Issues should reduce score."""
        result = validator.validate(prompt_injection_tool)
        assert result.score < 70  # Critical issues heavily penalize

    def test_empty_tool_low_score(self, validator):
        """Tool with many issues should have low score."""
        tool = {}  # Missing everything
        result = validator.validate(tool)
        assert result.score < 60  # 3 ERROR issues = -45 points = 55


    # =========================================================================
    # BATCH VALIDATION TESTS
    # =========================================================================

    def test_validate_batch_valid(self, validator, valid_tools_batch):
        """Batch validation of valid tools."""
        results = validator.validate_batch(valid_tools_batch)

        assert len(results) == 3
        for name, result in results.items():
            assert result.is_valid or len(result.warnings) > 0

    def test_validate_batch_invalid(self, validator, invalid_tools_batch):
        """Batch validation of invalid tools."""
        results = validator.validate_batch(invalid_tools_batch)

        assert len(results) == 3
        failed = [r for r in results.values() if not r.is_valid]
        assert len(failed) >= 2  # At least 2 should fail


    # =========================================================================
    # CUSTOM VALIDATOR TESTS
    # =========================================================================

    def test_custom_validator(self, valid_minimal_tool):
        """Custom validators should be called."""
        custom_called = []

        def custom_validator(tool):
            custom_called.append(tool["name"])
            return []

        validator = MCPToolValidator(custom_validators=[custom_validator])
        result = validator.validate(valid_minimal_tool)

        assert "get_weather" in custom_called
        assert result.is_valid

    def test_custom_validator_adds_issues(self, valid_minimal_tool):
        """Custom validators can add issues."""
        from tool_scan import ValidationIssue

        def strict_naming(tool):
            name = tool.get("name", "")
            if not name.startswith("mcp_"):
                return [ValidationIssue(
                    code="CUSTOM_NAMING",
                    message="Tool name should start with 'mcp_'",
                    severity=ValidationSeverity.WARNING,
                )]
            return []

        validator = MCPToolValidator(
            strict_mode=False,
            custom_validators=[strict_naming],
        )
        result = validator.validate(valid_minimal_tool)

        assert any(i.code == "CUSTOM_NAMING" for i in result.warnings)


    # =========================================================================
    # RESULT OBJECT TESTS
    # =========================================================================

    def test_result_summary(self, validator, valid_complete_tool):
        """Result summary should be informative."""
        result = validator.validate(valid_complete_tool)

        summary = result.summary()
        assert "search_database" in summary
        assert "PASS" in summary or "FAIL" in summary

    def test_result_errors_property(self, validator, missing_name_tool):
        """Errors property should filter correctly."""
        result = validator.validate(missing_name_tool)

        assert len(result.errors) > 0
        for error in result.errors:
            assert error.severity in (ValidationSeverity.ERROR, ValidationSeverity.CRITICAL)

    def test_result_warnings_property(self, lenient_validator, valid_minimal_tool):
        """Warnings property should filter correctly."""
        result = lenient_validator.validate(valid_minimal_tool)

        for warning in result.warnings:
            assert warning.severity == ValidationSeverity.WARNING


    # =========================================================================
    # STRICT MODE TESTS
    # =========================================================================

    def test_strict_mode_fails_on_warnings(self, validator):
        """Strict mode should fail on warnings."""
        tool = {
            "name": "_test",  # Underscore prefix warning
            "description": "Test tool with underscore prefix",
            "inputSchema": {"type": "object", "properties": {}},
        }
        result = validator.validate(tool)

        # Strict mode, so warnings count as failures
        assert not result.is_valid or len(result.warnings) > 0

    def test_lenient_mode_passes_with_warnings(self, lenient_validator):
        """Lenient mode should pass with only warnings."""
        tool = {
            "name": "_test",
            "description": "Test tool with underscore prefix",
            "inputSchema": {"type": "object", "properties": {}},
        }
        result = lenient_validator.validate(tool)

        # Has warnings but no errors
        if len(result.errors) == 0:
            assert result.is_valid
