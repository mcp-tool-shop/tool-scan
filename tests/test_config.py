"""Tests for configuration loading and application."""

from __future__ import annotations

import json
from pathlib import Path

from tool_scan.config import ToolScanConfig, load_config


class TestToolScanConfig:
    """Test ToolScanConfig dataclass."""

    def test_defaults(self) -> None:
        cfg = ToolScanConfig()
        assert cfg.min_score == 70
        assert cfg.strict is False
        assert cfg.ignore_rules == []
        assert cfg.ignore_fields == []
        assert cfg.fail_severity == "high"
        assert cfg.allow_domains == []
        assert cfg.deny_domains == []

    def test_has_ignores_empty(self) -> None:
        cfg = ToolScanConfig()
        assert cfg.has_ignores is False

    def test_has_ignores_with_rules(self) -> None:
        cfg = ToolScanConfig(ignore_rules=["TS-SSR-001"])
        assert cfg.has_ignores is True

    def test_has_ignores_with_fields(self) -> None:
        cfg = ToolScanConfig(ignore_fields=["description"])
        assert cfg.has_ignores is True


class TestLoadConfigJSON:
    """Test loading JSON config files."""

    def test_load_json_config(self, tmp_path: Path) -> None:
        config = {
            "min_score": 80,
            "strict": True,
            "ignore": {
                "rules": ["TS-SSR-001", "TS-PTR-006"],
                "fields": ["inputSchema.properties.url.default"],
            },
            "thresholds": {
                "fail_severity": "medium",
            },
            "domains": {
                "allow": ["*.example.com"],
                "deny": ["evil.com"],
            },
        }
        config_file = tmp_path / ".tool-scan.json"
        config_file.write_text(json.dumps(config))

        cfg = load_config(str(config_file))
        assert cfg.min_score == 80
        assert cfg.strict is True
        assert cfg.ignore_rules == ["TS-SSR-001", "TS-PTR-006"]
        assert cfg.ignore_fields == ["inputSchema.properties.url.default"]
        assert cfg.fail_severity == "medium"
        assert cfg.allow_domains == ["*.example.com"]
        assert cfg.deny_domains == ["evil.com"]

    def test_load_empty_json(self, tmp_path: Path) -> None:
        config_file = tmp_path / ".tool-scan.json"
        config_file.write_text("{}")
        cfg = load_config(str(config_file))
        assert cfg.min_score == 70  # default
        assert cfg.strict is False

    def test_load_partial_json(self, tmp_path: Path) -> None:
        config_file = tmp_path / ".tool-scan.json"
        config_file.write_text(json.dumps({"min_score": 90}))
        cfg = load_config(str(config_file))
        assert cfg.min_score == 90
        assert cfg.strict is False  # default
        assert cfg.ignore_rules == []  # default

    def test_missing_config_raises(self) -> None:
        import pytest

        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/path.json")

    def test_invalid_format_raises(self, tmp_path: Path) -> None:
        import pytest

        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text("key: value")
        with pytest.raises(ValueError, match="Unsupported config format"):
            load_config(str(yaml_file))


class TestLoadConfigTOML:
    """Test loading TOML config files."""

    def test_load_toml_config(self, tmp_path: Path) -> None:
        toml_content = """\
min_score = 85
strict = true

[ignore]
rules = ["TS-SSR-001"]

[thresholds]
fail_severity = "critical"
"""
        config_file = tmp_path / ".tool-scan.toml"
        config_file.write_text(toml_content)

        cfg = load_config(str(config_file))
        assert cfg.min_score == 85
        assert cfg.strict is True
        assert cfg.ignore_rules == ["TS-SSR-001"]
        assert cfg.fail_severity == "critical"

    def test_pyproject_toml(self, tmp_path: Path) -> None:
        toml_content = """\
[project]
name = "my-project"

[tool.tool-scan]
min_score = 90
strict = true

[tool.tool-scan.ignore]
rules = ["TS-PTR-001"]
"""
        config_file = tmp_path / "pyproject.toml"
        config_file.write_text(toml_content)

        cfg = load_config(str(config_file))
        assert cfg.min_score == 90
        assert cfg.strict is True
        assert cfg.ignore_rules == ["TS-PTR-001"]

    def test_pyproject_without_tool_scan_section(self, tmp_path: Path) -> None:
        toml_content = """\
[project]
name = "my-project"
"""
        config_file = tmp_path / "pyproject.toml"
        config_file.write_text(toml_content)

        cfg = load_config(str(config_file))
        # Should return defaults since no [tool.tool-scan] section
        assert cfg.min_score == 70


class TestAutoDiscover:
    """Test auto-discovery of config files."""

    def test_no_config_returns_defaults(self, tmp_path: Path, monkeypatch: object) -> None:
        monkeypatch.setattr(Path, "cwd", staticmethod(lambda: tmp_path))  # type: ignore[arg-type]
        cfg = load_config()
        assert cfg.min_score == 70

    def test_autodiscover_json(self, tmp_path: Path, monkeypatch: object) -> None:
        config_file = tmp_path / ".tool-scan.json"
        config_file.write_text(json.dumps({"min_score": 88}))
        monkeypatch.setattr(Path, "cwd", staticmethod(lambda: tmp_path))  # type: ignore[arg-type]
        cfg = load_config()
        assert cfg.min_score == 88


class TestSeverityThresholdValidation:
    """Test that invalid severity values are rejected."""

    def test_invalid_severity_ignored(self, tmp_path: Path) -> None:
        config_file = tmp_path / ".tool-scan.json"
        config_file.write_text(json.dumps({"thresholds": {"fail_severity": "extreme"}}))
        cfg = load_config(str(config_file))
        assert cfg.fail_severity == "high"  # default, "extreme" is invalid

    def test_valid_severities(self, tmp_path: Path) -> None:
        for sev in ("low", "medium", "high", "critical"):
            config_file = tmp_path / ".tool-scan.json"
            config_file.write_text(json.dumps({"thresholds": {"fail_severity": sev}}))
            cfg = load_config(str(config_file))
            assert cfg.fail_severity == sev
