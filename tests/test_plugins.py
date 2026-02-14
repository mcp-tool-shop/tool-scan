"""Tests for the rule plugin system."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tool_scan.grader import MCPToolGrader
from tool_scan.rules import PluginFinding, PluginRule, Severity
from tool_scan.rules.plugin_loader import PluginLoader, PluginLoadError

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "plugins"


class TestPluginLoader:
    """Test loading plugins from directory."""

    def test_load_sample_plugin(self) -> None:
        loader = PluginLoader(str(FIXTURES_DIR))
        rules = loader.load()
        assert len(rules) >= 1
        assert any(r.rule_id == "TEST-001" for r in rules)

    def test_load_nonexistent_dir(self) -> None:
        with pytest.raises(PluginLoadError, match="not found"):
            PluginLoader("/nonexistent/dir")

    def test_plugin_rule_callable(self) -> None:
        loader = PluginLoader(str(FIXTURES_DIR))
        rules = loader.load()
        test_rule = next(r for r in rules if r.rule_id == "TEST-001")

        # Should find "forbidden"
        tool: dict[str, Any] = {
            "name": "test",
            "description": "This is a forbidden tool",
            "inputSchema": {"type": "object"},
        }
        findings = test_rule.check(tool)
        assert len(findings) == 1
        assert "forbidden" in findings[0].message.lower()

    def test_plugin_rule_no_match(self) -> None:
        loader = PluginLoader(str(FIXTURES_DIR))
        rules = loader.load()
        test_rule = next(r for r in rules if r.rule_id == "TEST-001")

        tool: dict[str, Any] = {
            "name": "safe",
            "description": "A perfectly normal tool",
            "inputSchema": {"type": "object"},
        }
        findings = test_rule.check(tool)
        assert len(findings) == 0

    def test_bad_plugin_no_get_rules(self, tmp_path: Path) -> None:
        bad_plugin = tmp_path / "bad_plugin.py"
        bad_plugin.write_text("x = 1\n")
        loader = PluginLoader(str(tmp_path))
        with pytest.raises(PluginLoadError, match="get_rules"):
            loader.load()

    def test_bad_plugin_wrong_return_type(self, tmp_path: Path) -> None:
        bad_plugin = tmp_path / "bad_return.py"
        bad_plugin.write_text("def get_rules():\n    return 'not a list'\n")
        loader = PluginLoader(str(tmp_path))
        with pytest.raises(PluginLoadError, match="must return a list"):
            loader.load()

    def test_skips_dunder_files(self, tmp_path: Path) -> None:
        init = tmp_path / "__init__.py"
        init.write_text("# skip me\n")
        loader = PluginLoader(str(tmp_path))
        rules = loader.load()
        assert len(rules) == 0


class TestPluginIntegration:
    """Test plugins integrated with the grader."""

    def test_grader_with_plugin(self) -> None:
        """Plugin findings appear in the grader's remarks."""

        def check(tool: dict[str, Any]) -> list[PluginFinding]:
            if "bad" in tool.get("name", ""):
                return [PluginFinding(message="Bad name", location="name")]
            return []

        plugin = PluginRule(
            rule_id="INT-001",
            title="Name check",
            severity=Severity.HIGH,
            check=check,
        )

        grader = MCPToolGrader(plugin_rules=[plugin])
        report = grader.grade({
            "name": "bad_tool",
            "description": "A tool with a bad name.",
            "inputSchema": {"type": "object"},
        })

        rule_ids = [r.rule_id for r in report.remarks]
        assert "INT-001" in rule_ids

    def test_grader_without_plugin(self) -> None:
        """Without plugins, no plugin remarks appear."""
        grader = MCPToolGrader()
        report = grader.grade({
            "name": "good_tool",
            "description": "A fine tool.",
            "inputSchema": {"type": "object"},
        })
        rule_ids = [r.rule_id for r in report.remarks if r.rule_id and r.rule_id.startswith("INT-")]
        assert len(rule_ids) == 0

    def test_plugin_error_does_not_crash(self) -> None:
        """Plugin that raises should not crash the scan."""

        def bad_check(tool: dict[str, Any]) -> list[PluginFinding]:
            raise RuntimeError("boom")

        plugin = PluginRule(
            rule_id="ERR-001",
            title="Broken check",
            severity=Severity.CRITICAL,
            check=bad_check,
        )

        grader = MCPToolGrader(plugin_rules=[plugin])
        report = grader.grade({
            "name": "test",
            "description": "Test tool.",
            "inputSchema": {"type": "object"},
        })
        # Should complete without error, no ERR-001 in remarks
        rule_ids = [r.rule_id for r in report.remarks if r.rule_id]
        assert "ERR-001" not in rule_ids
