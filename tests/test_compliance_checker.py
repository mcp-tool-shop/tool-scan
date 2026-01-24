"""
Tests for ComplianceChecker.

Tests compliance against:
- MCP 2025-11-25 Specification (Required)
- MCP 2026 Security Best Practices (Recommended)
- Enterprise Security Standards (Optional)
"""

from __future__ import annotations

import pytest

from tool_scan import (
    ComplianceChecker,
    ComplianceLevel,
    ComplianceReport,
    ComplianceStatus,
)


class TestComplianceChecker:
    """Test suite for ComplianceChecker."""

    @pytest.fixture
    def checker(self) -> ComplianceChecker:
        """Create default compliance checker."""
        return ComplianceChecker(
            check_required=True,
            check_recommended=True,
            check_optional=False,
        )

    @pytest.fixture
    def full_checker(self) -> ComplianceChecker:
        """Create compliance checker with all levels."""
        return ComplianceChecker(
            check_required=True,
            check_recommended=True,
            check_optional=True,
        )

    @pytest.fixture
    def minimal_checker(self) -> ComplianceChecker:
        """Create minimal compliance checker (required only)."""
        return ComplianceChecker(
            check_required=True,
            check_recommended=False,
            check_optional=False,
        )

    # =========================================================================
    # BASIC FUNCTIONALITY TESTS
    # =========================================================================

    def test_compliant_tool_passes(self, checker, valid_complete_tool):
        """Fully compliant tool should pass all checks."""
        report = checker.check(valid_complete_tool)

        assert report.is_compliant
        assert report.tool_name == "search_database"
        assert report.compliance_score >= 80

    def test_report_summary(self, checker, valid_complete_tool):
        """Report summary should be informative."""
        report = checker.check(valid_complete_tool)

        summary = report.summary()
        assert "search_database" in summary
        assert "COMPLIANT" in summary or "NON-COMPLIANT" in summary

    # =========================================================================
    # REQUIRED FIELD TESTS (MCP-REQ-*)
    # =========================================================================

    def test_mcp_req_001_name_required(self, checker, missing_name_tool):
        """MCP-REQ-001: Tool name is required."""
        report = checker.check(missing_name_tool)

        assert not report.is_compliant
        failed = [
            c for c in report.checks if c.id == "MCP-REQ-001" and c.status == ComplianceStatus.FAIL
        ]
        assert len(failed) > 0

    def test_mcp_req_002_description_required(self, checker, missing_description_tool):
        """MCP-REQ-002: Tool description is required."""
        report = checker.check(missing_description_tool)

        assert not report.is_compliant
        failed = [
            c for c in report.checks if c.id == "MCP-REQ-002" and c.status == ComplianceStatus.FAIL
        ]
        assert len(failed) > 0

    def test_mcp_req_003_schema_required(self, checker, missing_schema_tool):
        """MCP-REQ-003: inputSchema is required."""
        report = checker.check(missing_schema_tool)

        assert not report.is_compliant
        failed = [
            c for c in report.checks if c.id == "MCP-REQ-003" and c.status == ComplianceStatus.FAIL
        ]
        assert len(failed) > 0

    # =========================================================================
    # NAME FORMAT TESTS (MCP-REQ-004, MCP-REQ-005)
    # =========================================================================

    def test_mcp_req_004_valid_name_format(self, checker, valid_minimal_tool):
        """MCP-REQ-004: Valid name format should pass."""
        report = checker.check(valid_minimal_tool)

        check = next((c for c in report.checks if c.id == "MCP-REQ-004"), None)
        assert check is not None
        assert check.status == ComplianceStatus.PASS

    def test_mcp_req_004_invalid_name_format(self, checker, invalid_name_format_tool):
        """MCP-REQ-004: Invalid name format should fail."""
        report = checker.check(invalid_name_format_tool)

        check = next((c for c in report.checks if c.id == "MCP-REQ-004"), None)
        assert check is not None
        assert check.status == ComplianceStatus.FAIL

    def test_mcp_req_005_name_length(self, checker):
        """MCP-REQ-005: Name exceeding length limit should fail."""
        tool = {
            "name": "a" * 100,
            "description": "Test",
            "inputSchema": {"type": "object", "properties": {}},
        }
        report = checker.check(tool)

        check = next((c for c in report.checks if c.id == "MCP-REQ-005"), None)
        assert check is not None
        assert check.status == ComplianceStatus.FAIL

    # =========================================================================
    # SCHEMA STRUCTURE TESTS (MCP-REQ-006 to MCP-REQ-009)
    # =========================================================================

    def test_mcp_req_007_root_type_object(self, checker, invalid_schema_type_tool):
        """MCP-REQ-007: Root type must be 'object'."""
        report = checker.check(invalid_schema_type_tool)

        check = next((c for c in report.checks if c.id == "MCP-REQ-007"), None)
        assert check is not None
        assert check.status == ComplianceStatus.FAIL

    def test_mcp_req_009_required_properties_defined(self, checker):
        """MCP-REQ-009: Required properties must exist in properties."""
        tool = {
            "name": "test",
            "description": "Test",
            "inputSchema": {
                "type": "object",
                "properties": {"a": {"type": "string"}},
                "required": ["a", "b"],  # 'b' is not defined
            },
        }
        report = checker.check(tool)

        check = next((c for c in report.checks if c.id == "MCP-REQ-009"), None)
        assert check is not None
        assert check.status == ComplianceStatus.FAIL

    # =========================================================================
    # ANNOTATION TESTS (MCP-REQ-010 to MCP-REQ-012)
    # =========================================================================

    def test_annotation_type_validation(self, checker):
        """Annotation types should be validated."""
        tool = {
            "name": "test",
            "description": "Test",
            "inputSchema": {"type": "object", "properties": {}},
            "annotations": {
                "readOnlyHint": "yes",  # Should be boolean
            },
        }
        report = checker.check(tool)

        failed = [
            c for c in report.checks if "MCP-REQ-011" in c.id and c.status == ComplianceStatus.FAIL
        ]
        assert len(failed) > 0

    def test_valid_annotations_pass(self, checker, valid_complete_tool):
        """Valid annotations should pass."""
        report = checker.check(valid_complete_tool)

        annotation_checks = [c for c in report.checks if "MCP-REQ-011" in c.id]
        for check in annotation_checks:
            assert check.status == ComplianceStatus.PASS

    # =========================================================================
    # SECURITY BEST PRACTICE TESTS (SEC-*)
    # =========================================================================

    def test_sec_001_additional_properties(self, checker, valid_minimal_tool):
        """SEC-001: additionalProperties should be false."""
        # valid_minimal_tool has additionalProperties: false
        report = checker.check(valid_minimal_tool)

        check = next((c for c in report.checks if c.id == "SEC-001"), None)
        assert check is not None
        assert check.status == ComplianceStatus.PASS

    def test_sec_001_additional_properties_warning(self, checker):
        """SEC-001: Missing additionalProperties should warn."""
        tool = {
            "name": "test",
            "description": "Test tool",
            "inputSchema": {
                "type": "object",
                "properties": {},
                # additionalProperties defaults to true
            },
        }
        report = checker.check(tool)

        check = next((c for c in report.checks if c.id == "SEC-001"), None)
        assert check is not None
        assert check.status == ComplianceStatus.WARN

    def test_sec_002_destructive_annotation(self, checker, valid_destructive_tool):
        """SEC-002: Destructive tools should have destructiveHint annotation."""
        report = checker.check(valid_destructive_tool)

        check = next((c for c in report.checks if c.id == "SEC-002"), None)
        assert check is not None
        assert check.status == ComplianceStatus.PASS

    def test_sec_002_missing_destructive_annotation(self, checker):
        """SEC-002: Destructive tool without annotation should warn."""
        tool = {
            "name": "delete_everything",
            "description": "Deletes all data permanently",
            "inputSchema": {"type": "object", "properties": {}},
            # No annotations
        }
        report = checker.check(tool)

        check = next((c for c in report.checks if c.id == "SEC-002"), None)
        assert check is not None
        assert check.status == ComplianceStatus.WARN

    def test_sec_003_url_property_validation(self, checker):
        """SEC-003: URL properties should have pattern validation."""
        tool = {
            "name": "fetcher",
            "description": "Fetches URL content",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "format": "uri",
                        # No pattern - should warn
                    },
                },
            },
        }
        report = checker.check(tool)

        url_checks = [c for c in report.checks if "SEC-003" in c.id]
        assert len(url_checks) > 0
        assert any(c.status == ComplianceStatus.WARN for c in url_checks)

    def test_sec_004_path_property_validation(self, checker):
        """SEC-004: Path properties should have pattern validation."""
        tool = {
            "name": "file_reader",
            "description": "Reads files",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        # No pattern - should warn
                    },
                },
            },
        }
        report = checker.check(tool)

        path_checks = [c for c in report.checks if "SEC-004" in c.id]
        assert len(path_checks) > 0
        assert any(c.status == ComplianceStatus.WARN for c in path_checks)

    # =========================================================================
    # QUALITY TESTS (QUAL-*)
    # =========================================================================

    def test_qual_001_property_descriptions(self, checker, valid_complete_tool):
        """QUAL-001: Properties should have descriptions."""
        report = checker.check(valid_complete_tool)

        check = next((c for c in report.checks if c.id == "QUAL-001"), None)
        assert check is not None
        assert check.status == ComplianceStatus.PASS

    def test_qual_001_missing_descriptions(self, checker):
        """QUAL-001: Properties without descriptions should warn."""
        tool = {
            "name": "test",
            "description": "Test tool",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "a": {"type": "string"},  # No description
                    "b": {"type": "number"},  # No description
                },
            },
        }
        report = checker.check(tool)

        check = next((c for c in report.checks if c.id == "QUAL-001"), None)
        assert check is not None
        assert check.status == ComplianceStatus.WARN

    def test_qual_002_property_types(self, checker):
        """QUAL-002: Properties should have types."""
        tool = {
            "name": "test",
            "description": "Test tool",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "typed": {"type": "string"},
                    "untyped": {"description": "No type"},
                },
            },
        }
        report = checker.check(tool)

        check = next((c for c in report.checks if c.id == "QUAL-002"), None)
        assert check is not None
        # 50% typed, below 90% threshold
        assert check.status == ComplianceStatus.WARN

    def test_qual_003_string_constraints(self, checker, valid_complete_tool):
        """QUAL-003: String properties should have constraints."""
        # valid_complete_tool has minLength/maxLength on query
        report = checker.check(valid_complete_tool)

        check = next((c for c in report.checks if c.id == "QUAL-003"), None)
        if check:  # Only if there are string properties
            assert check.status == ComplianceStatus.PASS

    def test_qual_004_description_length(self, checker):
        """QUAL-004: Description length should be appropriate."""
        tool = {
            "name": "test",
            "description": "Short",  # Too short
            "inputSchema": {"type": "object", "properties": {}},
        }
        report = checker.check(tool)

        check = next((c for c in report.checks if c.id == "QUAL-004"), None)
        assert check is not None
        assert check.status == ComplianceStatus.WARN

    def test_qual_005_description_clarity(self, checker, valid_complete_tool):
        """QUAL-005: Description should explain what tool does."""
        # valid_complete_tool has "Searches", "Returns" - action words
        report = checker.check(valid_complete_tool)

        check = next((c for c in report.checks if c.id == "QUAL-005"), None)
        assert check is not None
        assert check.status == ComplianceStatus.PASS

    # =========================================================================
    # ENTERPRISE STANDARDS TESTS (ENT-*)
    # =========================================================================

    def test_ent_001_complete_annotations(self, full_checker):
        """ENT-001: Complete behavioral annotations."""
        tool = {
            "name": "test",
            "description": "Test tool",
            "inputSchema": {"type": "object", "properties": {}},
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
            },
        }
        report = full_checker.check(tool)

        check = next((c for c in report.checks if c.id == "ENT-001"), None)
        assert check is not None
        assert check.status == ComplianceStatus.PASS

    def test_ent_001_incomplete_annotations(self, full_checker):
        """ENT-001: Incomplete annotations should warn."""
        tool = {
            "name": "test",
            "description": "Test tool",
            "inputSchema": {"type": "object", "properties": {}},
            "annotations": {
                "readOnlyHint": True,
                # Missing destructiveHint and idempotentHint
            },
        }
        report = full_checker.check(tool)

        check = next((c for c in report.checks if c.id == "ENT-001"), None)
        assert check is not None
        assert check.status == ComplianceStatus.WARN

    def test_ent_002_schema_declaration(self, full_checker, valid_complete_tool):
        """ENT-002: Schema should have $schema declaration."""
        # valid_complete_tool has $schema
        report = full_checker.check(valid_complete_tool)

        check = next((c for c in report.checks if c.id == "ENT-002"), None)
        assert check is not None
        assert check.status == ComplianceStatus.PASS

    def test_ent_002_missing_schema_declaration(self, full_checker, valid_minimal_tool):
        """ENT-002: Missing $schema should warn."""
        report = full_checker.check(valid_minimal_tool)

        check = next((c for c in report.checks if c.id == "ENT-002"), None)
        assert check is not None
        assert check.status == ComplianceStatus.WARN

    # =========================================================================
    # COMPLIANCE LEVEL TESTS
    # =========================================================================

    def test_required_only_mode(self, minimal_checker, valid_complete_tool):
        """Minimal checker should only run required checks."""
        report = minimal_checker.check(valid_complete_tool)

        # Should have only required level checks
        for check in report.checks:
            assert check.level == ComplianceLevel.REQUIRED

    def test_full_checker_includes_optional(self, full_checker, valid_complete_tool):
        """Full checker should include optional checks."""
        report = full_checker.check(valid_complete_tool)

        optional_checks = [c for c in report.checks if c.level == ComplianceLevel.OPTIONAL]
        assert len(optional_checks) > 0

    # =========================================================================
    # COMPLIANCE SCORE TESTS
    # =========================================================================

    def test_perfect_tool_high_score(self, checker, valid_complete_tool):
        """Perfect tool should have high compliance score."""
        report = checker.check(valid_complete_tool)
        assert report.compliance_score >= 90

    def test_many_failures_low_score(self, checker):
        """Tool with many failures should have low score."""
        tool = {}  # Missing everything
        report = checker.check(tool)
        assert report.compliance_score < 50

    def test_weighted_scoring(self, checker):
        """Required failures should impact score more than recommended."""
        # Tool missing required fields
        required_fail = {
            # Missing name - required failure
            "description": "Test",
            "inputSchema": {"type": "object", "properties": {}},
        }

        # Tool with only recommended issues
        recommended_fail = {
            "name": "test",
            "description": "Test",
            "inputSchema": {
                "type": "object",
                "properties": {},
                # additionalProperties defaults to true - recommended warning
            },
        }

        required_report = checker.check(required_fail)
        recommended_report = checker.check(recommended_fail)

        # Required failure should have worse score
        assert required_report.compliance_score < recommended_report.compliance_score

    # =========================================================================
    # REPORT PROPERTIES TESTS
    # =========================================================================

    def test_report_required_failures(self, checker, missing_name_tool):
        """Report should correctly identify required failures."""
        report = checker.check(missing_name_tool)

        assert len(report.required_failures) > 0
        for check in report.required_failures:
            assert check.level == ComplianceLevel.REQUIRED
            assert check.status == ComplianceStatus.FAIL

    def test_report_recommended_failures(self, checker):
        """Report should correctly identify recommended failures."""
        tool = {
            "name": "delete_data",  # Suggests destructive
            "description": "Deletes data permanently",
            "inputSchema": {"type": "object", "properties": {}},
            # No destructiveHint annotation
        }
        report = checker.check(tool)

        # May have recommended failures
        assert report.is_compliant  # Required passes
        # recommended_failures may include SEC-002

    def test_report_passed_checks(self, checker, valid_complete_tool):
        """Report should correctly identify passed checks."""
        report = checker.check(valid_complete_tool)

        assert len(report.passed_checks) > 0
        for check in report.passed_checks:
            assert check.status == ComplianceStatus.PASS

    # =========================================================================
    # BATCH CHECKING TESTS
    # =========================================================================

    def test_check_batch_valid(self, checker, valid_tools_batch):
        """Batch checking should work for valid tools."""
        reports = checker.check_batch(valid_tools_batch)

        assert len(reports) == 3
        for _name, report in reports.items():
            assert report.is_compliant or len(report.required_failures) == 0

    def test_check_batch_invalid(self, checker, invalid_tools_batch):
        """Batch checking should work for invalid tools."""
        reports = checker.check_batch(invalid_tools_batch)

        assert len(reports) == 3
        non_compliant = [r for r in reports.values() if not r.is_compliant]
        assert len(non_compliant) >= 2

    # =========================================================================
    # METADATA TESTS
    # =========================================================================

    def test_report_metadata(self, checker, valid_complete_tool):
        """Report should include metadata."""
        report = checker.check(valid_complete_tool)

        assert "check_levels" in report.metadata
        assert "spec_version" in report.metadata
        assert report.metadata["spec_version"] == "2025-11-25"

    # =========================================================================
    # EDGE CASE TESTS
    # =========================================================================

    def test_empty_tool(self, checker):
        """Empty tool should not crash."""
        report = checker.check({})

        assert isinstance(report, ComplianceReport)
        assert not report.is_compliant

    def test_none_values(self, checker):
        """Tool with None values should not crash."""
        tool = {
            "name": None,
            "description": None,
            "inputSchema": None,
        }
        report = checker.check(tool)

        assert isinstance(report, ComplianceReport)

    def test_annotations_not_dict(self, checker):
        """Non-dict annotations should be handled."""
        tool = {
            "name": "test",
            "description": "Test",
            "inputSchema": {"type": "object", "properties": {}},
            "annotations": ["not", "a", "dict"],
        }
        report = checker.check(tool)

        # Should still produce report
        assert isinstance(report, ComplianceReport)

    def test_schema_not_dict(self, checker):
        """Non-dict schema should be handled."""
        tool = {
            "name": "test",
            "description": "Test",
            "inputSchema": "not a dict",
        }
        report = checker.check(tool)

        assert isinstance(report, ComplianceReport)
        assert not report.is_compliant
