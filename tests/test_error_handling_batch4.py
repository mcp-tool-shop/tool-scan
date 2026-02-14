"""Batch 4: Error Handling & Integration Tests (25 tests).

Tests covering:
- Malformed JSON handling
- Empty and binary files
- Very large tools
- Unicode content
- Circular references
- Permission errors
- Full pipeline integration
- Result serialization
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tool_scan.cli import load_tool, main
from tool_scan.grader import MCPToolGrader

# =============================================================================
# 1. Malformed JSON Handling (4 tests)
# =============================================================================


class TestMalformedJSONHandling:
    """Test handling of malformed JSON."""

    def test_malformed_json(self, tmp_path: Path):
        """Test handling of malformed JSON tool files."""
        tool_file = tmp_path / "malformed.json"
        tool_file.write_text("{ invalid json }", encoding="utf-8")

        with pytest.raises(json.JSONDecodeError):
            load_tool(str(tool_file))

    def test_malformed_json_cli_graceful(self, tmp_path: Path, capsys):
        """Test CLI handles malformed JSON gracefully."""
        tool_file = tmp_path / "malformed.json"
        tool_file.write_text("not json at all", encoding="utf-8")

        result = main([str(tool_file)])

        assert result == 2
        captured = capsys.readouterr()
        assert "Error" in captured.err or "Invalid" in captured.err

    def test_partial_json(self, tmp_path: Path):
        """Test handling of truncated JSON."""
        tool_file = tmp_path / "partial.json"
        tool_file.write_text('{"name": "test", "description":', encoding="utf-8")

        with pytest.raises(json.JSONDecodeError):
            load_tool(str(tool_file))

    def test_json_with_trailing_comma(self, tmp_path: Path):
        """Test JSON with trailing comma (invalid)."""
        tool_file = tmp_path / "trailing.json"
        tool_file.write_text('{"name": "test",}', encoding="utf-8")

        with pytest.raises(json.JSONDecodeError):
            load_tool(str(tool_file))


# =============================================================================
# 2. Empty and Binary Files (3 tests)
# =============================================================================


class TestEmptyAndBinaryFiles:
    """Test handling of empty and binary files."""

    def test_empty_tool_file(self, tmp_path: Path):
        """Test handling of empty files."""
        tool_file = tmp_path / "empty.json"
        tool_file.write_text("", encoding="utf-8")

        with pytest.raises(json.JSONDecodeError):
            load_tool(str(tool_file))

    def test_binary_file(self, tmp_path: Path):
        """Test handling of binary files."""
        tool_file = tmp_path / "binary.json"
        tool_file.write_bytes(b"\x00\x01\x02\x03\xff\xfe\xfd")

        with pytest.raises((json.JSONDecodeError, UnicodeDecodeError)):
            load_tool(str(tool_file))

    def test_whitespace_only_file(self, tmp_path: Path):
        """Test handling of whitespace-only files."""
        tool_file = tmp_path / "whitespace.json"
        tool_file.write_text("   \n\t\n   ", encoding="utf-8")

        with pytest.raises(json.JSONDecodeError):
            load_tool(str(tool_file))


# =============================================================================
# 3. Very Large Tools (3 tests)
# =============================================================================


class TestVeryLargeTools:
    """Test handling of very large tools."""

    def test_very_large_tool_description(self):
        """Test handling of extremely large descriptions."""
        grader = MCPToolGrader()

        tool = {
            "name": "large_desc_tool",
            "description": "A" * 100000,  # 100KB description
            "inputSchema": {"type": "object", "properties": {}},
        }

        report = grader.grade(tool)

        # Should handle without crashing
        assert report is not None
        assert report.tool_name == "large_desc_tool"

    def test_very_large_schema(self):
        """Test handling of tools with many properties."""
        grader = MCPToolGrader()

        # 1000 properties
        properties = {f"prop_{i}": {"type": "string", "description": f"Property {i}"} for i in range(1000)}

        tool = {
            "name": "huge_schema_tool",
            "description": "Tool with many properties.",
            "inputSchema": {"type": "object", "properties": properties},
        }

        report = grader.grade(tool)

        assert report is not None

    def test_deeply_nested_objects(self):
        """Test handling of deeply nested schemas."""
        grader = MCPToolGrader()

        # Build 50-level deep nesting
        inner = {"type": "string"}
        for i in range(50):
            inner = {"type": "object", "properties": {f"level_{i}": inner}}

        tool = {
            "name": "deep_tool",
            "description": "Deeply nested tool.",
            "inputSchema": inner,
        }

        report = grader.grade(tool)

        # Should handle deep nesting
        assert report is not None


# =============================================================================
# 4. Unicode Content (4 tests)
# =============================================================================


class TestUnicodeContent:
    """Test handling of unicode content."""

    def test_unicode_description(self):
        """Test tool with unicode in description."""
        grader = MCPToolGrader()

        tool = {
            "name": "emoji_tool",
            "description": "Tool with emoji 🎉 and unicode: 你好世界",
            "inputSchema": {"type": "object", "properties": {}},
        }

        report = grader.grade(tool)

        assert report is not None
        assert "emoji_tool" in report.tool_name

    def test_unicode_property_names(self):
        """Test tool with unicode property names."""
        grader = MCPToolGrader()

        tool = {
            "name": "unicode_props",
            "description": "Tool with unicode property names.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "名前": {"type": "string", "description": "Name in Japanese"},
                    "données": {"type": "string", "description": "Data in French"},
                },
            },
        }

        report = grader.grade(tool)

        assert report is not None

    def test_rtl_text(self):
        """Test tool with right-to-left text."""
        grader = MCPToolGrader()

        tool = {
            "name": "rtl_tool",
            "description": "Tool with Arabic: مرحبا بالعالم",
            "inputSchema": {"type": "object", "properties": {}},
        }

        report = grader.grade(tool)

        assert report is not None

    def test_null_bytes_in_content(self):
        """Test handling of null bytes in strings."""
        grader = MCPToolGrader()

        tool = {
            "name": "null_tool",
            "description": "Description\x00with\x00nulls",
            "inputSchema": {"type": "object", "properties": {}},
        }

        report = grader.grade(tool)

        # Should handle null bytes
        assert report is not None


# =============================================================================
# 5. Permission and File Errors (2 tests)
# =============================================================================


class TestPermissionAndFileErrors:
    """Test file permission and access errors."""

    def test_file_not_found(self):
        """Test clear error for non-existent file."""
        with pytest.raises(FileNotFoundError):
            load_tool("/nonexistent/path/tool.json")

    def test_directory_instead_of_file(self, tmp_path: Path):
        """Test error when directory provided instead of file."""
        with pytest.raises((IsADirectoryError, json.JSONDecodeError, PermissionError)):
            load_tool(str(tmp_path))


# =============================================================================
# 6. Full Pipeline Integration Tests (5 tests)
# =============================================================================


class TestFullPipelineIntegration:
    """Test complete pipeline integration."""

    def test_cli_to_validator_integration(self, tmp_path: Path, valid_complete_tool, capsys):
        """Test CLI calls validator correctly."""
        tool_file = tmp_path / "tool.json"
        tool_file.write_text(json.dumps(valid_complete_tool))

        result = main([str(tool_file)])

        captured = capsys.readouterr()
        assert result == 0
        assert "Score:" in captured.out
        assert "Grade:" in captured.out

    def test_full_pipeline_safe_tool(self, valid_complete_tool):
        """Test complete pipeline with safe tool."""
        grader = MCPToolGrader()
        report = grader.grade(valid_complete_tool)

        assert report.is_safe is True
        assert report.is_compliant is True
        assert report.score > 60

    def test_full_pipeline_malicious_tool(self, prompt_injection_tool):
        """Test complete pipeline with malicious tool."""
        grader = MCPToolGrader()
        report = grader.grade(prompt_injection_tool)

        assert report.is_safe is False
        assert len(report.remarks) > 0

    def test_full_pipeline_batch(self, valid_tools_batch):
        """Test pipeline handles batch processing."""
        grader = MCPToolGrader()

        reports = [grader.grade(tool) for tool in valid_tools_batch]

        assert len(reports) == 3
        for report in reports:
            assert report.tool_name is not None
            assert 0 <= report.score <= 100

    def test_validator_to_grader_integration(self, valid_minimal_tool):
        """Test validator produces graded results."""
        grader = MCPToolGrader()
        report = grader.grade(valid_minimal_tool)

        assert report.grade is not None
        assert report.grade.letter in ["A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-", "D+", "D", "D-", "F"]


# =============================================================================
# 7. Result Serialization (4 tests)
# =============================================================================


class TestResultSerialization:
    """Test result serialization."""

    def test_result_to_json(self, valid_complete_tool):
        """Test results can be serialized to JSON."""
        grader = MCPToolGrader()
        report = grader.grade(valid_complete_tool)

        # Should have json_report property
        json_data = report.json_report

        assert isinstance(json_data, dict)
        assert "tool_name" in json_data
        assert "score" in json_data
        assert "grade" in json_data

    def test_json_output_valid(self, tmp_path: Path, valid_minimal_tool, capsys):
        """Test --json produces valid JSON."""
        tool_file = tmp_path / "tool.json"
        tool_file.write_text(json.dumps(valid_minimal_tool))

        main(["--json", str(tool_file)])

        captured = capsys.readouterr()
        output = json.loads(captured.out)

        assert "results" in output
        assert "summary" in output
        assert output["summary"]["total"] == 1

    def test_json_output_with_errors(self, tmp_path: Path, capsys):
        """Test JSON output includes errors."""
        valid_file = tmp_path / "valid.json"
        valid_file.write_text('{"name": "t", "description": "d", "inputSchema": {"type": "object"}}')

        invalid_file = tmp_path / "invalid.json"
        invalid_file.write_text("not json")

        main(["--json", str(valid_file), str(invalid_file)])

        captured = capsys.readouterr()
        output = json.loads(captured.out)

        assert "errors" in output
        assert len(output["errors"]) > 0

    def test_json_output_summary_stats(self, tmp_path: Path, valid_complete_tool, prompt_injection_tool, capsys):
        """Test JSON summary includes correct stats."""
        safe_file = tmp_path / "safe.json"
        unsafe_file = tmp_path / "unsafe.json"
        safe_file.write_text(json.dumps(valid_complete_tool))
        unsafe_file.write_text(json.dumps(prompt_injection_tool))

        main(["--json", str(safe_file), str(unsafe_file)])

        captured = capsys.readouterr()
        output = json.loads(captured.out)

        assert output["summary"]["total"] == 2
        assert "average_score" in output["summary"]
