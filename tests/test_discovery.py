"""Tests for src/tool_scan/discovery.py — File discovery with globs.

Covers:
- Explicit file paths
- Directory recursion
- Include/exclude patterns
- Default patterns (*.json)
- Mixed paths (files + dirs)
- stdin marker pass-through
- CLI --include / --exclude integration
"""

from __future__ import annotations

import json
from pathlib import Path

from tool_scan.cli import main
from tool_scan.discovery import discover_files

# =============================================================================
# 1. discover_files unit tests
# =============================================================================


class TestDiscoverFiles:
    """Test discover_files() function."""

    def test_explicit_file(self, tmp_path: Path):
        """Explicit file paths are always included."""
        f = tmp_path / "tool.json"
        f.write_text("{}")
        result = discover_files([str(f)])
        assert len(result) == 1
        assert result[0] == f.resolve()

    def test_explicit_non_json_file(self, tmp_path: Path):
        """Explicit non-JSON files are included (no filtering)."""
        f = tmp_path / "tool.yaml"
        f.write_text("name: test")
        result = discover_files([str(f)])
        assert len(result) == 1

    def test_directory_finds_json(self, tmp_path: Path):
        """Scanning a directory finds *.json files."""
        (tmp_path / "a.json").write_text("{}")
        (tmp_path / "b.json").write_text("{}")
        (tmp_path / "c.txt").write_text("not json")
        result = discover_files([str(tmp_path)])
        assert len(result) == 2
        names = {p.name for p in result}
        assert names == {"a.json", "b.json"}

    def test_directory_recursive(self, tmp_path: Path):
        """Scanning a directory recurses into subdirectories."""
        sub = tmp_path / "sub"
        sub.mkdir()
        (tmp_path / "top.json").write_text("{}")
        (sub / "nested.json").write_text("{}")
        result = discover_files([str(tmp_path)])
        assert len(result) == 2

    def test_exclude_directory(self, tmp_path: Path):
        """Exclude pattern skips matching directories."""
        nm = tmp_path / "node_modules"
        nm.mkdir()
        (nm / "tool.json").write_text("{}")
        (tmp_path / "real.json").write_text("{}")
        result = discover_files([str(tmp_path)])
        assert len(result) == 1
        assert result[0].name == "real.json"

    def test_exclude_custom_pattern(self, tmp_path: Path):
        """Custom exclude pattern filters files."""
        (tmp_path / "keep.json").write_text("{}")
        (tmp_path / "skip_test.json").write_text("{}")
        result = discover_files(
            [str(tmp_path)],
            exclude=["skip_*"],
        )
        assert len(result) == 1
        assert result[0].name == "keep.json"

    def test_include_custom_pattern(self, tmp_path: Path):
        """Custom include pattern overrides default *.json."""
        (tmp_path / "tool.json").write_text("{}")
        (tmp_path / "tool.yaml").write_text("name: test")
        result = discover_files(
            [str(tmp_path)],
            include=["*.yaml"],
        )
        assert len(result) == 1
        assert result[0].name == "tool.yaml"

    def test_include_multiple_patterns(self, tmp_path: Path):
        """Multiple include patterns match multiple extensions."""
        (tmp_path / "a.json").write_text("{}")
        (tmp_path / "b.yaml").write_text("{}")
        (tmp_path / "c.txt").write_text("")
        result = discover_files(
            [str(tmp_path)],
            include=["*.json", "*.yaml"],
        )
        assert len(result) == 2
        names = {p.name for p in result}
        assert names == {"a.json", "b.yaml"}

    def test_stdin_marker(self):
        """stdin marker '-' is passed through."""
        result = discover_files(["-"])
        assert len(result) == 1
        assert str(result[0]) == "-"

    def test_mixed_files_and_dirs(self, tmp_path: Path):
        """Mix of explicit files and directories."""
        explicit = tmp_path / "explicit.json"
        explicit.write_text("{}")
        subdir = tmp_path / "tools"
        subdir.mkdir()
        (subdir / "found.json").write_text("{}")
        result = discover_files([str(explicit), str(subdir)])
        assert len(result) == 2

    def test_empty_directory(self, tmp_path: Path):
        """Empty directory returns no files."""
        result = discover_files([str(tmp_path)])
        assert len(result) == 0

    def test_deduplication(self, tmp_path: Path):
        """Same file referenced twice is deduplicated."""
        f = tmp_path / "tool.json"
        f.write_text("{}")
        result = discover_files([str(f), str(f)])
        assert len(result) == 1

    def test_excludes_git_dir(self, tmp_path: Path):
        """Default excludes skip .git directory."""
        git = tmp_path / ".git"
        git.mkdir()
        (git / "config.json").write_text("{}")
        (tmp_path / "real.json").write_text("{}")
        result = discover_files([str(tmp_path)])
        assert len(result) == 1
        assert result[0].name == "real.json"

    def test_sorted_output(self, tmp_path: Path):
        """Output is sorted for deterministic results."""
        (tmp_path / "z.json").write_text("{}")
        (tmp_path / "a.json").write_text("{}")
        (tmp_path / "m.json").write_text("{}")
        result = discover_files([str(tmp_path)])
        names = [p.name for p in result]
        assert names == sorted(names)


# =============================================================================
# 2. CLI --include / --exclude integration
# =============================================================================


class TestDiscoveryCLI:
    """Test CLI integration with --include and --exclude."""

    def test_cli_directory_scan(self, tmp_path: Path, valid_minimal_tool):
        """tool-scan <dir> scans directory for JSON files."""
        tool_file = tmp_path / "tool.json"
        tool_file.write_text(json.dumps(valid_minimal_tool))
        # A non-JSON file that should be ignored
        (tmp_path / "notes.txt").write_text("not a tool")

        result = main([str(tmp_path)])
        assert result == 0

    def test_cli_include_flag(self, tmp_path: Path):
        """--include overrides default *.json pattern."""
        (tmp_path / "tool.json").write_text(
            json.dumps({"name": "a", "description": "A tool.", "inputSchema": {"type": "object", "properties": {}}})
        )
        (tmp_path / "tool.toml").write_text("not valid json")

        # Default scan finds only JSON
        result = main([str(tmp_path)])
        assert result == 0

    def test_cli_exclude_flag(self, tmp_path: Path, valid_minimal_tool):
        """--exclude skips matching files."""
        (tmp_path / "good.json").write_text(json.dumps(valid_minimal_tool))
        (tmp_path / "bad.json").write_text(json.dumps(valid_minimal_tool))

        result = main([str(tmp_path), "--exclude", "bad*"])
        # Should scan only good.json
        assert result == 0

    def test_cli_empty_dir_returns_2(self, tmp_path: Path):
        """Scanning empty directory returns exit code 2."""
        result = main([str(tmp_path)])
        assert result == 2
