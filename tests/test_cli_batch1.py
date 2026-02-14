"""Batch 1: CLI Tests (25 tests).

Tests for src/tool_scan/cli.py covering:
- Basic CLI operations
- Output modes
- Strict mode & CI/CD
- Colorization functions
- Report printing
- Batch processing
- Help & version
"""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from tool_scan.cli import (
    Colors,
    colorize_grade,
    colorize_score,
    main,
    print_report,
)
from tool_scan.grader import Grade, GradeReport, Remark, RemarkCategory

# =============================================================================
# 1. Basic CLI Operations (5 tests)
# =============================================================================


class TestBasicCLIOperations:
    """Test basic CLI operations."""

    def test_cli_single_file(self, tmp_path: Path, valid_minimal_tool):
        """Test scanning a single tool file."""
        tool_file = tmp_path / "tool.json"
        tool_file.write_text(json.dumps(valid_minimal_tool))

        result = main([str(tool_file)])

        assert result == 0

    def test_cli_multiple_files(self, tmp_path: Path, valid_minimal_tool, valid_complete_tool):
        """Test scanning multiple tool files."""
        tool1 = tmp_path / "tool1.json"
        tool2 = tmp_path / "tool2.json"
        tool1.write_text(json.dumps(valid_minimal_tool))
        tool2.write_text(json.dumps(valid_complete_tool))

        result = main([str(tool1), str(tool2)])

        assert result == 0

    def test_cli_stdin_input(self, valid_minimal_tool):
        """Test reading tool from stdin."""
        stdin_data = json.dumps(valid_minimal_tool)

        with patch("sys.stdin", StringIO(stdin_data)):
            result = main(["-"])

        assert result == 0

    def test_cli_glob_pattern(self, tmp_path: Path, valid_minimal_tool):
        """Test scanning multiple files in directory."""
        for i in range(3):
            (tmp_path / f"tool{i}.json").write_text(json.dumps(valid_minimal_tool))

        # Simulate glob expansion (shell does this normally)
        files = list(tmp_path.glob("*.json"))
        result = main([str(f) for f in files])

        assert result == 0

    def test_cli_file_not_found(self, capsys):
        """Test error when file doesn't exist."""
        result = main(["nonexistent.json"])

        assert result == 2
        captured = capsys.readouterr()
        assert "not found" in captured.err.lower() or "Error" in captured.err


# =============================================================================
# 2. Output Modes (6 tests)
# =============================================================================


class TestOutputModes:
    """Test CLI output modes."""

    def test_cli_json_output(self, tmp_path: Path, valid_minimal_tool, capsys):
        """Test --json flag produces valid JSON output."""
        tool_file = tmp_path / "tool.json"
        tool_file.write_text(json.dumps(valid_minimal_tool))

        result = main(["--json", str(tool_file)])

        captured = capsys.readouterr()
        output = json.loads(captured.out)

        assert result == 0
        assert "results" in output
        assert "summary" in output

    def test_cli_text_output(self, tmp_path: Path, valid_minimal_tool, capsys):
        """Test default text output formatting."""
        tool_file = tmp_path / "tool.json"
        tool_file.write_text(json.dumps(valid_minimal_tool))

        main([str(tool_file)])

        captured = capsys.readouterr()
        assert "Tool:" in captured.out
        assert "Score:" in captured.out
        assert "Grade:" in captured.out

    def test_cli_verbose_mode(self, tmp_path: Path, valid_minimal_tool, capsys):
        """Test --verbose shows detailed information."""
        tool_file = tmp_path / "tool.json"
        tool_file.write_text(json.dumps(valid_minimal_tool))

        result = main(["--verbose", str(tool_file)])

        # Verbose mode should work without error
        assert result == 0

    def test_cli_color_output_tty(self, tmp_path: Path, valid_minimal_tool):
        """Test color output when stdout is TTY."""
        tool_file = tmp_path / "tool.json"
        tool_file.write_text(json.dumps(valid_minimal_tool))

        # Colors should be enabled by default when TTY
        with patch("sys.stdout.isatty", return_value=True):
            # Reset colors first
            Colors.RESET = "\033[0m"
            Colors.GREEN = "\033[92m"
            main([str(tool_file)])

        assert Colors.GREEN != ""

    def test_cli_no_color_flag(self, tmp_path: Path, valid_minimal_tool):
        """Test --no-color disables colors."""
        tool_file = tmp_path / "tool.json"
        tool_file.write_text(json.dumps(valid_minimal_tool))

        main(["--no-color", str(tool_file)])

        assert Colors.GREEN == ""
        assert Colors.RED == ""

    def test_cli_no_color_non_tty(self, tmp_path: Path, valid_minimal_tool):
        """Test colors disabled for non-TTY output."""
        tool_file = tmp_path / "tool.json"
        tool_file.write_text(json.dumps(valid_minimal_tool))

        with patch("sys.stdout.isatty", return_value=False):
            main([str(tool_file)])

        assert Colors.GREEN == ""


# =============================================================================
# 3. Strict Mode & CI/CD (5 tests)
# =============================================================================


class TestStrictModeAndCICD:
    """Test strict mode and CI/CD features."""

    def test_cli_strict_mode_fails_on_security_issues(self, tmp_path: Path, prompt_injection_tool):
        """Test --strict fails on security issues."""
        tool_file = tmp_path / "tool.json"
        tool_file.write_text(json.dumps(prompt_injection_tool))

        result = main(["--strict", str(tool_file)])

        assert result == 1

    def test_cli_min_score_fail(self, tmp_path: Path):
        """Test --min-score threshold failure."""
        # Create a tool that will score low
        low_score_tool = {
            "name": "x",  # Too short
            "description": "y",  # Too short
            "inputSchema": {"type": "object"},
        }
        tool_file = tmp_path / "tool.json"
        tool_file.write_text(json.dumps(low_score_tool))

        result = main(["--min-score", "95", str(tool_file)])

        assert result == 1

    def test_cli_min_score_pass(self, tmp_path: Path, valid_complete_tool):
        """Test passing min-score threshold."""
        tool_file = tmp_path / "tool.json"
        tool_file.write_text(json.dumps(valid_complete_tool))

        result = main(["--min-score", "50", str(tool_file)])

        assert result == 0

    def test_cli_exit_code_on_errors(self, tmp_path: Path):
        """Test exit code 2 for parse errors."""
        tool_file = tmp_path / "tool.json"
        tool_file.write_text("invalid json {{{")

        result = main([str(tool_file)])

        assert result == 2

    def test_cli_include_optional_checks(self, tmp_path: Path, valid_minimal_tool):
        """Test --include-optional flag."""
        tool_file = tmp_path / "tool.json"
        tool_file.write_text(json.dumps(valid_minimal_tool))

        result = main(["--include-optional", str(tool_file)])

        # Should run without error
        assert result in [0, 1]


# =============================================================================
# 4. Colorization Functions (5 tests)
# =============================================================================


class TestColorization:
    """Test colorization functions."""

    def test_colorize_grade_a(self):
        """Test A grade is green."""
        # Reset colors first
        Colors.GREEN = "\033[92m"
        Colors.BOLD = "\033[1m"
        Colors.RESET = "\033[0m"

        grade = Grade.A
        result = colorize_grade(grade)

        assert Colors.GREEN in result
        assert "A" in result

    def test_colorize_grade_f(self):
        """Test F grade is red."""
        Colors.RED = "\033[91m"
        Colors.BOLD = "\033[1m"
        Colors.RESET = "\033[0m"

        grade = Grade.F
        result = colorize_grade(grade)

        assert Colors.RED in result
        assert "F" in result

    def test_colorize_score_high(self):
        """Test high score is green."""
        Colors.GREEN = "\033[92m"
        Colors.RESET = "\033[0m"

        result = colorize_score(95.0)

        assert Colors.GREEN in result
        assert "95" in result

    def test_colorize_score_low(self):
        """Test low score is red."""
        Colors.RED = "\033[91m"
        Colors.RESET = "\033[0m"

        result = colorize_score(45.0)

        assert Colors.RED in result
        assert "45" in result

    def test_colors_disable(self):
        """Test Colors.disable() removes all colors."""
        Colors.disable()

        assert Colors.RED == ""
        assert Colors.GREEN == ""
        assert Colors.BLUE == ""
        assert Colors.RESET == ""
        assert Colors.BOLD == ""


# =============================================================================
# 5. Report Printing (2 tests)
# =============================================================================


class TestReportPrinting:
    """Test report printing functions."""

    def test_print_report_no_issues(self, capsys):
        """Test report with no issues shows success."""
        report = GradeReport(
            tool_name="perfect_tool",
            score=100.0,
            grade=Grade.A_PLUS,
            is_safe=True,
            is_compliant=True,
            remarks=[],
        )

        print_report(report)

        captured = capsys.readouterr()
        assert "perfect_tool" in captured.out
        assert "100" in captured.out

    def test_print_report_with_issues(self, capsys):
        """Test report with issues displays them."""
        remarks = [
            Remark(
                category=RemarkCategory.SECURITY,
                title="Security Issue",
                description="Details here",
                action="Fix it",
            )
        ]
        report = GradeReport(
            tool_name="risky_tool",
            score=50.0,
            grade=Grade.F,
            is_safe=False,
            is_compliant=False,
            remarks=remarks,
        )

        print_report(report, verbose=True)

        captured = capsys.readouterr()
        assert "risky_tool" in captured.out
        assert "Security Issue" in captured.out


# =============================================================================
# 6. Batch Processing (2 tests)
# =============================================================================


class TestBatchProcessing:
    """Test batch processing features."""

    def test_cli_batch_summary(self, tmp_path: Path, valid_minimal_tool, capsys):
        """Test batch scanning shows summary."""
        for i in range(3):
            (tmp_path / f"tool{i}.json").write_text(json.dumps(valid_minimal_tool))

        files = [str(f) for f in tmp_path.glob("*.json")]
        main(files)

        captured = capsys.readouterr()
        assert "Tool:" in captured.out or "Score:" in captured.out

    def test_cli_batch_continue_on_error(self, tmp_path: Path, valid_minimal_tool, capsys):
        """Test batch continues after errors."""
        # One valid, one invalid
        (tmp_path / "valid.json").write_text(json.dumps(valid_minimal_tool))
        (tmp_path / "invalid.json").write_text("not json")

        main([str(tmp_path / "valid.json"), str(tmp_path / "invalid.json")])

        # Should process valid file even with error
        captured = capsys.readouterr()
        assert "get_weather" in captured.out or "Tool:" in captured.out
