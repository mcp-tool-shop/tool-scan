"""Tests for src/tool_scan/profile.py — Per-stage profiling.

Covers:
- ScanProfiler basic usage
- Stage timing accumulation
- Disabled profiler (no-op)
- ProfileResult JSON report
- ProfileResult text summary
- CLI --profile integration
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from tool_scan.cli import main
from tool_scan.profile import ProfileResult, ScanProfiler, StageResult

# =============================================================================
# 1. ScanProfiler unit tests
# =============================================================================


class TestScanProfiler:
    """Test ScanProfiler core functionality."""

    def test_disabled_by_default(self):
        """Profiler is disabled until start() is called."""
        profiler = ScanProfiler()
        assert profiler.enabled is False

    def test_start_enables(self):
        """start() sets enabled=True and records start time."""
        profiler = ScanProfiler()
        profiler.start()
        assert profiler.enabled is True
        assert profiler._start_time > 0

    def test_stage_records_timing(self):
        """stage() context manager records elapsed time."""
        profiler = ScanProfiler()
        profiler.start()
        with profiler.stage("test_stage"):
            time.sleep(0.01)

        assert "test_stage" in profiler._timings
        assert profiler._timings["test_stage"] >= 5  # at least 5ms (generous)
        assert profiler._counts["test_stage"] == 1

    def test_stage_accumulates(self):
        """Multiple stage() calls with same name accumulate timing."""
        profiler = ScanProfiler()
        profiler.start()
        with profiler.stage("grade"):
            time.sleep(0.005)
        with profiler.stage("grade"):
            time.sleep(0.005)

        assert profiler._counts["grade"] == 2
        assert profiler._timings["grade"] >= 5  # at least 5ms total

    def test_stage_noop_when_disabled(self):
        """stage() is a no-op when profiler is disabled."""
        profiler = ScanProfiler()
        # Don't call start()
        with profiler.stage("ignored"):
            pass

        assert len(profiler._timings) == 0
        assert len(profiler._counts) == 0

    def test_multiple_stages(self):
        """Multiple named stages tracked independently."""
        profiler = ScanProfiler()
        profiler.start()
        with profiler.stage("load"):
            pass
        with profiler.stage("grade"):
            pass
        with profiler.stage("output"):
            pass

        assert set(profiler._timings.keys()) == {"load", "grade", "output"}
        assert all(c == 1 for c in profiler._counts.values())


# =============================================================================
# 2. ProfileResult tests
# =============================================================================


class TestProfileResult:
    """Test ProfileResult output formats."""

    def test_result_structure(self):
        """result() returns a ProfileResult with correct fields."""
        profiler = ScanProfiler()
        profiler.start()
        with profiler.stage("load"):
            pass
        with profiler.stage("grade"):
            pass

        result = profiler.result(tool_count=5)
        assert isinstance(result, ProfileResult)
        assert result.tool_count == 5
        assert result.total_ms >= 0
        assert len(result.stages) == 2

    def test_json_report(self):
        """json_report produces valid JSON-serializable dict."""
        profiler = ScanProfiler()
        profiler.start()
        with profiler.stage("grade"):
            time.sleep(0.005)

        result = profiler.result(tool_count=3)
        report = result.json_report

        assert report["tool_count"] == 3
        assert isinstance(report["total_ms"], float)
        assert len(report["stages"]) == 1
        assert report["stages"][0]["name"] == "grade"
        assert isinstance(report["stages"][0]["elapsed_ms"], float)
        assert report["stages"][0]["count"] == 1

        # Must be JSON-serializable
        serialized = json.dumps(report)
        assert isinstance(serialized, str)

    def test_summary_text(self):
        """summary() returns a human-readable string."""
        profiler = ScanProfiler()
        profiler.start()
        with profiler.stage("load"):
            pass
        with profiler.stage("grade"):
            pass

        result = profiler.result(tool_count=10)
        text = result.summary()

        assert "Profile:" in text
        assert "Tools scanned: 10" in text
        assert "Total time:" in text
        assert "load" in text
        assert "grade" in text
        # Percentage column present
        assert "%" in text

    def test_summary_empty_stages(self):
        """summary() works with no stages."""
        result = ProfileResult(stages=[], tool_count=0, total_ms=0.0)
        text = result.summary()
        assert "Profile:" in text
        assert "Tools scanned: 0" in text

    def test_stage_result_fields(self):
        """StageResult has name, elapsed_ms, and count."""
        stage = StageResult(name="test", elapsed_ms=42.5, count=3)
        assert stage.name == "test"
        assert stage.elapsed_ms == 42.5
        assert stage.count == 3


# =============================================================================
# 3. CLI --profile integration
# =============================================================================


class TestProfileCLI:
    """Test --profile flag in CLI."""

    def test_profile_text_output(self, tmp_path: Path, valid_minimal_tool, capsys):
        """--profile prints timing to stderr in text mode."""
        tool_file = tmp_path / "tool.json"
        tool_file.write_text(json.dumps(valid_minimal_tool))

        result = main([str(tool_file), "--profile"])
        assert result == 0

        captured = capsys.readouterr()
        # Profile output goes to stderr
        assert "Profile:" in captured.err
        assert "Tools scanned:" in captured.err
        assert "load" in captured.err
        assert "grade" in captured.err

    def test_profile_json_output(self, tmp_path: Path, valid_minimal_tool, capsys):
        """--profile with --json prints profile JSON to stderr."""
        tool_file = tmp_path / "tool.json"
        tool_file.write_text(json.dumps(valid_minimal_tool))

        result = main([str(tool_file), "--json", "--profile", "--no-color"])
        assert result == 0

        captured = capsys.readouterr()
        # Stdout has the normal JSON report
        normal_output = json.loads(captured.out)
        assert "results" in normal_output

        # Stderr has the profile JSON
        profile_output = json.loads(captured.err)
        assert "profile" in profile_output
        assert profile_output["profile"]["tool_count"] == 1
        assert isinstance(profile_output["profile"]["stages"], list)

    def test_profile_does_not_change_results(self, tmp_path: Path, valid_minimal_tool):
        """Profiling should not change scan results."""
        tool_file = tmp_path / "tool.json"
        tool_file.write_text(json.dumps(valid_minimal_tool))

        # Without profile
        result_no_profile = main([str(tool_file), "--json", "--no-color"])

        # With profile
        result_with_profile = main([str(tool_file), "--json", "--no-color", "--profile"])

        assert result_no_profile == result_with_profile

    def test_profile_does_not_change_exit_code(self, tmp_path: Path, valid_minimal_tool):
        """Profile flag does not affect exit code."""
        tool_file = tmp_path / "tool.json"
        tool_file.write_text(json.dumps(valid_minimal_tool))

        exit_without = main([str(tool_file)])
        exit_with = main([str(tool_file), "--profile"])
        assert exit_without == exit_with

    def test_profile_multiple_tools(self, tmp_path: Path, valid_minimal_tool, valid_complete_tool, capsys):
        """--profile works with multiple tool files."""
        t1 = tmp_path / "t1.json"
        t2 = tmp_path / "t2.json"
        t1.write_text(json.dumps(valid_minimal_tool))
        t2.write_text(json.dumps(valid_complete_tool))

        result = main([str(t1), str(t2), "--profile"])
        assert result == 0

        captured = capsys.readouterr()
        assert "Tools scanned: 2" in captured.err

    def test_no_profile_no_output(self, tmp_path: Path, valid_minimal_tool, capsys):
        """Without --profile, no profiling output on stderr."""
        tool_file = tmp_path / "tool.json"
        tool_file.write_text(json.dumps(valid_minimal_tool))

        main([str(tool_file), "--no-color"])

        captured = capsys.readouterr()
        assert "Profile:" not in captured.err
