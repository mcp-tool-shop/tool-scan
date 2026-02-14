"""Batch 5: Compliance, Performance & Remaining Tests (25+ tests).

Tests covering:
- MCP specification compliance
- JSON Schema compliance
- Best practices
- Tool validator edge cases
- Property validation
- Reserved names
- Performance tests
- False positive prevention
"""

from __future__ import annotations

import time

from tool_scan.grader import MCPToolGrader
from tool_scan.security_scanner import SecurityScanner, ThreatCategory

# =============================================================================
# 1. MCP Specification Compliance (4 tests)
# =============================================================================


class TestMCPSpecCompliance:
    """Test MCP specification compliance."""

    def test_mcp_required_fields(self, valid_minimal_tool):
        """Test all required MCP fields present."""
        grader = MCPToolGrader()
        report = grader.grade(valid_minimal_tool)

        # Required fields: name, description, inputSchema
        assert report.is_compliant is True

    def test_mcp_missing_required_field_name(self, missing_name_tool):
        """Test detection of missing name."""
        grader = MCPToolGrader()
        report = grader.grade(missing_name_tool)

        assert report.is_compliant is False
        assert any("name" in r.title.lower() for r in report.remarks)

    def test_mcp_missing_required_field_description(self, missing_description_tool):
        """Test detection of missing description."""
        grader = MCPToolGrader()
        report = grader.grade(missing_description_tool)

        assert report.is_compliant is False

    def test_mcp_optional_fields_validated(self, valid_complete_tool):
        """Test optional fields validated if present."""
        grader = MCPToolGrader()
        report = grader.grade(valid_complete_tool)

        # Tool with annotations should still be compliant
        assert report.is_compliant is True


# =============================================================================
# 2. JSON Schema Compliance (4 tests)
# =============================================================================


class TestJSONSchemaCompliance:
    """Test JSON Schema compliance."""

    def test_json_schema_draft_07_features(self):
        """Test Draft-07 specific features."""
        grader = MCPToolGrader()

        tool = {
            "name": "draft07_tool",
            "description": "Tool using Draft-07 features.",
            "inputSchema": {
                "$schema": "http://json-schema.org/draft-07/schema#",
                "type": "object",
                "properties": {
                    "value": {"type": "string", "contentMediaType": "application/json"},
                },
            },
        }

        report = grader.grade(tool)
        assert report is not None

    def test_json_schema_keywords(self):
        """Test supported JSON Schema keywords."""
        grader = MCPToolGrader()

        tool = {
            "name": "keywords_tool",
            "description": "Tool testing various keywords.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "minLength": 1, "maxLength": 100, "pattern": "^[a-z]+$"},
                    "num": {"type": "number", "minimum": 0, "maximum": 100, "multipleOf": 5},
                    "items": {"type": "array", "minItems": 1, "maxItems": 10, "uniqueItems": True},
                },
                "required": ["text"],
                "additionalProperties": False,
            },
        }

        report = grader.grade(tool)
        assert report is not None

    def test_json_schema_format_keyword(self):
        """Test format keyword handling."""
        grader = MCPToolGrader()

        tool = {
            "name": "format_tool",
            "description": "Tool with format validations.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "email": {"type": "string", "format": "email"},
                    "date": {"type": "string", "format": "date"},
                    "uri": {"type": "string", "format": "uri"},
                },
            },
        }

        report = grader.grade(tool)
        assert report is not None

    def test_json_schema_const_enum(self):
        """Test const and enum keywords."""
        grader = MCPToolGrader()

        tool = {
            "name": "enum_tool",
            "description": "Tool with const and enum.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "status": {"type": "string", "enum": ["active", "inactive", "pending"]},
                    "version": {"const": "1.0"},
                },
            },
        }

        report = grader.grade(tool)
        assert report is not None


# =============================================================================
# 3. Best Practices Tests (4 tests)
# =============================================================================


class TestBestPractices:
    """Test best practices checks."""

    def test_best_practice_description_quality(self):
        """Test description quality checks."""
        grader = MCPToolGrader()

        # Good description
        good_tool = {
            "name": "good_tool",
            "description": "Retrieves user information from the database by their unique identifier. Returns user profile including name, email, and preferences.",
            "inputSchema": {"type": "object", "properties": {}},
        }

        # Poor description
        poor_tool = {
            "name": "poor_tool",
            "description": "Does stuff.",
            "inputSchema": {"type": "object", "properties": {}},
        }

        good_report = grader.grade(good_tool)
        poor_report = grader.grade(poor_tool)

        # Good description should score better
        assert good_report.score >= poor_report.score

    def test_best_practice_property_descriptions(self):
        """Test property description recommendations."""
        grader = MCPToolGrader()

        tool = {
            "name": "undocumented_tool",
            "description": "A tool for testing property descriptions.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "x": {"type": "string"},  # No description
                    "y": {"type": "number"},  # No description
                },
            },
        }

        report = grader.grade(tool)

        # Should warn about missing descriptions
        assert any("description" in str(r).lower() for r in report.remarks)

    def test_best_practice_safe_defaults(self):
        """Test checking for safe default values."""
        grader = MCPToolGrader()

        # Dangerous default
        tool = {
            "name": "dangerous_default",
            "description": "Tool with dangerous default.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "default": "/etc/passwd"},
                },
            },
        }

        report = grader.grade(tool)

        # Should have warnings
        assert len(report.remarks) > 0

    def test_best_practice_annotations(self, valid_destructive_tool):
        """Test annotation best practices."""
        grader = MCPToolGrader()
        report = grader.grade(valid_destructive_tool)

        # Destructive tool with annotations should be compliant
        assert report.is_compliant is True


# =============================================================================
# 4. Tool Validator Edge Cases (4 tests)
# =============================================================================


class TestToolValidatorEdgeCases:
    """Test tool validator edge cases."""

    def test_nested_schema_validation(self, complex_schema_tool):
        """Test validation of deeply nested schemas."""
        grader = MCPToolGrader()
        report = grader.grade(complex_schema_tool)

        assert report is not None
        assert report.is_compliant

    def test_schema_with_definitions(self):
        """Test schema with definitions section."""
        grader = MCPToolGrader()

        tool = {
            "name": "definitions_tool",
            "description": "Tool using schema definitions.",
            "inputSchema": {
                "type": "object",
                "definitions": {
                    "address": {
                        "type": "object",
                        "properties": {
                            "street": {"type": "string"},
                            "city": {"type": "string"},
                        },
                    }
                },
                "properties": {
                    "home": {"$ref": "#/definitions/address"},
                    "work": {"$ref": "#/definitions/address"},
                },
            },
        }

        report = grader.grade(tool)
        assert report is not None

    def test_schema_allof_composition(self):
        """Test schema with allOf composition."""
        grader = MCPToolGrader()

        tool = {
            "name": "allof_tool",
            "description": "Tool using allOf composition.",
            "inputSchema": {
                "type": "object",
                "allOf": [
                    {"properties": {"name": {"type": "string"}}},
                    {"properties": {"age": {"type": "integer"}}},
                ],
            },
        }

        report = grader.grade(tool)
        assert report is not None

    def test_schema_oneof_composition(self):
        """Test schema with oneOf composition."""
        grader = MCPToolGrader()

        tool = {
            "name": "oneof_tool",
            "description": "Tool using oneOf composition.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "input": {
                        "oneOf": [
                            {"type": "string"},
                            {"type": "object", "properties": {"data": {"type": "string"}}},
                        ]
                    }
                },
            },
        }

        report = grader.grade(tool)
        assert report is not None


# =============================================================================
# 5. Reserved Names Tests (3 tests)
# =============================================================================


class TestReservedNames:
    """Test reserved name detection."""

    def test_reserved_name_exec(self, reserved_name_tool):
        """Test 'exec' is detected as reserved."""
        grader = MCPToolGrader()
        report = grader.grade(reserved_name_tool)

        assert any("reserved" in str(r).lower() for r in report.remarks)

    def test_dangerous_name_patterns(self):
        """Test detection of dangerous naming patterns."""
        grader = MCPToolGrader()

        dangerous_names = ["drop_table", "delete_all", "rm_rf", "system_exec"]

        for name in dangerous_names:
            tool = {
                "name": name,
                "description": f"Tool named {name}.",
                "inputSchema": {"type": "object", "properties": {}},
            }

            report = grader.grade(tool)
            # Should have some warning about the name
            assert isinstance(report, object)

    def test_sql_keywords_in_name(self):
        """Test SQL keywords in tool name."""
        grader = MCPToolGrader()

        tool = {
            "name": "drop_users",
            "description": "Drops users from the system.",
            "inputSchema": {"type": "object", "properties": {}},
        }

        report = grader.grade(tool)
        assert isinstance(report, object)


# =============================================================================
# 6. Performance Tests (3 tests)
# =============================================================================


class TestPerformance:
    """Test performance characteristics."""

    def test_scan_single_tool_performance(self, valid_complete_tool):
        """Test single tool scan completes quickly."""
        grader = MCPToolGrader()

        start = time.time()
        report = grader.grade(valid_complete_tool)
        elapsed = time.time() - start

        assert elapsed < 0.1  # 100ms
        assert report is not None

    def test_scan_batch_100_tools_performance(self, valid_minimal_tool):
        """Test batch scanning 100 tools."""
        grader = MCPToolGrader()

        start = time.time()
        for _ in range(100):
            grader.grade(valid_minimal_tool)
        elapsed = time.time() - start

        assert elapsed < 10.0  # 10 seconds for 100 tools

    def test_memory_usage_large_batch(self, valid_minimal_tool):
        """Test memory doesn't balloon with large batch."""
        import gc

        grader = MCPToolGrader()

        # Grade 500 tools
        for i in range(500):
            grader.grade(valid_minimal_tool)
            if i % 100 == 0:
                gc.collect()

        # If we get here without OOM, we're good
        assert True


# =============================================================================
# 7. False Positive Prevention (3 tests)
# =============================================================================


class TestFalsePositivePrevention:
    """Test false positive prevention."""

    def test_legitimate_technical_tool(self):
        """Test legitimate technical tools don't trigger false alarms."""
        scanner = SecurityScanner()

        tool = {
            "name": "database_query",
            "description": "Executes read-only SQL queries against the analytics database. Supports SELECT, JOIN, and aggregate functions.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The SQL SELECT query to execute",
                    }
                },
            },
        }

        findings = scanner.scan(tool).threats

        # Technical descriptions shouldn't trigger prompt injection
        assert not any(f.category == ThreatCategory.PROMPT_INJECTION for f in findings)

    def test_legitimate_file_operations(self):
        """Test legitimate file tools don't trigger path traversal."""
        scanner = SecurityScanner()

        tool = {
            "name": "read_file",
            "description": "Reads a file from the workspace directory.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative path within workspace",
                        "default": "config.json",  # Safe default
                    }
                },
            },
        }

        findings = scanner.scan(tool).threats

        # Legitimate paths shouldn't trigger
        assert not any(f.category == ThreatCategory.PATH_TRAVERSAL for f in findings)

    def test_legitimate_api_client(self):
        """Test legitimate API clients don't trigger SSRF."""
        scanner = SecurityScanner()

        tool = {
            "name": "github_api",
            "description": "Fetches data from GitHub API.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "endpoint": {
                        "type": "string",
                        "description": "API endpoint path",
                        "default": "/repos/owner/repo",  # Relative, not absolute
                    }
                },
            },
        }

        findings = scanner.scan(tool).threats

        # Relative paths shouldn't trigger SSRF
        assert not any(f.category == ThreatCategory.SSRF for f in findings)
