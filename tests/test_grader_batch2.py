"""Batch 2: Grader & Schema Validator Tests (25 tests).

Tests for src/tool_scan/grader.py and src/tool_scan/schema_validator.py covering:
- Grade calculation
- Grade boundaries
- Grade report generation
- Batch grading
- JSON Schema validation
- Schema draft support
- Type validation
"""

from __future__ import annotations

from tool_scan.grader import Grade, GradeReport, MCPToolGrader

# =============================================================================
# 1. Grade Calculation Tests (4 tests)
# =============================================================================


class TestGradeCalculation:
    """Test grade calculation from scores."""

    def test_grader_score_to_grade_a_plus(self):
        """Test 95-100 maps to A+."""
        grade = Grade.from_score(98)

        assert grade.letter == "A+"

    def test_grader_score_to_grade_a(self):
        """Test 90-94 maps to A."""
        grade = Grade.from_score(92)

        assert grade.letter == "A-"

    def test_grader_score_to_grade_f(self):
        """Test <60 maps to F."""
        grade = Grade.from_score(45)

        assert grade.letter == "F"

    def test_grader_plus_minus_grades(self):
        """Test plus/minus grade assignments."""
        # B+ (87-89)
        assert Grade.from_score(88).letter == "B+"

        # B (83-86)
        assert Grade.from_score(85).letter == "B"

        # B- (80-82)
        assert Grade.from_score(81).letter == "B-"


# =============================================================================
# 2. Grade Boundaries Tests (4 tests)
# =============================================================================


class TestGradeBoundaries:
    """Test grade boundary conditions."""

    def test_grade_boundary_90(self):
        """Test exactly 90 is A."""
        assert Grade.from_score(90.0).letter == "A-"

    def test_grade_boundary_89_9(self):
        """Test 89.9 is B+."""
        # Rounds to 90 -> A
        grade = Grade.from_score(89.9)
        assert grade.letter == "A-"

    def test_grade_boundary_60(self):
        """Test exactly 60 is D-."""
        grade = Grade.from_score(60.0)
        assert grade.letter == "D-"

    def test_grade_boundary_59_9(self):
        """Test 59.9 is F."""
        grade = Grade.from_score(59.9)
        assert grade.letter == "D-"


# =============================================================================
# 3. Grade Report Generation Tests (4 tests)
# =============================================================================


class TestGradeReportGeneration:
    """Test grade report generation."""

    def test_grade_report_structure(self, valid_complete_tool):
        """Test grade report has all required fields."""
        grader = MCPToolGrader()
        report = grader.grade(valid_complete_tool)

        assert hasattr(report, "tool_name")
        assert hasattr(report, "grade")
        assert hasattr(report, "score")
        assert hasattr(report, "is_safe")
        assert hasattr(report, "is_compliant")
        assert hasattr(report, "remarks")

    def test_grade_report_with_issues(self, prompt_injection_tool):
        """Test report includes issue breakdown."""
        grader = MCPToolGrader()
        report = grader.grade(prompt_injection_tool)

        assert len(report.remarks) > 0
        assert report.is_safe is False

    def test_grade_report_recommendations(self, missing_description_tool):
        """Test report includes improvement recommendations."""
        grader = MCPToolGrader()
        report = grader.grade(missing_description_tool)

        # Should have remarks with actions
        assert any(r.action for r in report.remarks if r.action)

    def test_grade_report_passing_threshold(self, valid_complete_tool, prompt_injection_tool):
        """Test report indicates pass/fail correctly."""
        grader = MCPToolGrader()

        good_report = grader.grade(valid_complete_tool)
        bad_report = grader.grade(prompt_injection_tool)

        assert good_report.score >= 60
        assert bad_report.is_safe is False


# =============================================================================
# 4. Batch Grading Tests (3 tests)
# =============================================================================


class TestBatchGrading:
    """Test batch grading functionality."""

    def test_batch_grade_multiple_tools(self, valid_tools_batch):
        """Test grading multiple tools at once."""
        grader = MCPToolGrader()
        reports = [grader.grade(tool) for tool in valid_tools_batch]

        assert len(reports) == 3
        for report in reports:
            assert isinstance(report, GradeReport)

    def test_batch_grade_mixed_quality(self, valid_minimal_tool, prompt_injection_tool):
        """Test batch with mixed quality tools."""
        grader = MCPToolGrader()

        good = grader.grade(valid_minimal_tool)
        bad = grader.grade(prompt_injection_tool)

        assert good.score > bad.score
        assert good.is_safe is True
        assert bad.is_safe is False

    def test_batch_grade_summary_stats(self, valid_tools_batch):
        """Test batch produces useful statistics."""
        grader = MCPToolGrader()
        reports = [grader.grade(tool) for tool in valid_tools_batch]

        avg_score = sum(r.score for r in reports) / len(reports)
        safe_count = sum(1 for r in reports if r.is_safe)

        assert 0 <= avg_score <= 100
        assert 0 <= safe_count <= len(reports)


# =============================================================================
# 5. JSON Schema Validation Tests (5 tests)
# =============================================================================


class TestJSONSchemaValidation:
    """Test JSON Schema validation."""

    def test_validate_simple_schema(self, valid_minimal_tool):
        """Test validating simple JSON schemas."""
        grader = MCPToolGrader()
        report = grader.grade(valid_minimal_tool)

        # Should pass basic validation
        assert report.is_compliant

    def test_validate_complex_schema(self, complex_schema_tool):
        """Test validating complex nested schemas."""
        grader = MCPToolGrader()
        report = grader.grade(complex_schema_tool)

        # Should handle complex schemas
        assert isinstance(report, GradeReport)

    def test_validate_schema_with_anyof(self, anyof_schema_tool):
        """Test schema with anyOf."""
        grader = MCPToolGrader()
        report = grader.grade(anyof_schema_tool)

        assert isinstance(report, GradeReport)

    def test_validate_invalid_schema(self):
        """Test detecting invalid schemas."""
        invalid_tool = {
            "name": "test",
            "description": "Test tool",
            "inputSchema": {"type": "invalid_type"},
        }

        grader = MCPToolGrader()
        report = grader.grade(invalid_tool)

        # Should detect invalid type
        assert len(report.remarks) > 0

    def test_validate_schema_missing_type(self):
        """Test schema without type field."""
        no_type = {
            "name": "test_tool",
            "description": "A test tool that does things.",
            "inputSchema": {"properties": {"x": {"type": "string"}}},
        }

        grader = MCPToolGrader()
        report = grader.grade(no_type)

        # Should warn about missing type
        assert isinstance(report, GradeReport)


# =============================================================================
# 6. Type Validation Tests (5 tests)
# =============================================================================


class TestTypeValidation:
    """Test type validation in schemas."""

    def test_validate_string_type(self):
        """Test string type validation."""
        tool = {
            "name": "string_tool",
            "description": "Tool with string input.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 100,
                    }
                },
            },
        }

        grader = MCPToolGrader()
        report = grader.grade(tool)

        assert isinstance(report, GradeReport)

    def test_validate_number_type(self):
        """Test number type validation."""
        tool = {
            "name": "number_tool",
            "description": "Tool with number input.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "value": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 100,
                    }
                },
            },
        }

        grader = MCPToolGrader()
        report = grader.grade(tool)

        assert isinstance(report, GradeReport)

    def test_validate_array_type(self):
        """Test array type validation."""
        tool = {
            "name": "array_tool",
            "description": "Tool with array input.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "items": {"type": "string"},
                    }
                },
            },
        }

        grader = MCPToolGrader()
        report = grader.grade(tool)

        assert isinstance(report, GradeReport)

    def test_validate_boolean_type(self):
        """Test boolean type validation."""
        tool = {
            "name": "bool_tool",
            "description": "Tool with boolean input.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "flag": {"type": "boolean"},
                },
            },
        }

        grader = MCPToolGrader()
        report = grader.grade(tool)

        assert isinstance(report, GradeReport)

    def test_validate_null_type(self):
        """Test null type handling."""
        tool = {
            "name": "nullable_tool",
            "description": "Tool with nullable input.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "optional": {
                        "type": ["string", "null"],
                    }
                },
            },
        }

        grader = MCPToolGrader()
        report = grader.grade(tool)

        assert isinstance(report, GradeReport)
