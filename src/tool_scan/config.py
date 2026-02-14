"""
Tool-Scan Configuration
=======================

Loads user configuration from TOML (Python 3.11+) or JSON fallback.

Config files support:
- Severity thresholds per category
- Allow/deny domain patterns
- Ignored rule IDs
- Ignored tool paths / fields

Config search order:
1. Explicit ``--config <path>`` argument
2. ``.tool-scan.toml`` or ``.tool-scan.json`` in the current directory
3. ``pyproject.toml`` under ``[tool.tool-scan]``

Example TOML (``.tool-scan.toml``):

    min_score = 80
    strict = true

    [ignore]
    rules = ["TS-SSR-001", "TS-PTR-006"]
    fields = ["inputSchema.properties.url.default"]

    [thresholds]
    fail_severity = "high"   # "low", "medium", "high", "critical"

    [domains]
    allow = ["*.example.com"]
    deny = ["evil.com"]
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# tomllib is stdlib from 3.11+; on 3.10, TOML configs are unavailable
if sys.version_info >= (3, 11):
    import tomllib
else:
    tomllib = None  # pragma: no cover


@dataclass
class ToolScanConfig:
    """Resolved configuration for a tool-scan run."""

    # CLI-level overrides
    min_score: int = 70
    strict: bool = False
    include_optional: bool = False

    # Ignore lists
    ignore_rules: list[str] = field(default_factory=list)
    ignore_fields: list[str] = field(default_factory=list)

    # Severity threshold for failure ("low", "medium", "high", "critical")
    fail_severity: str = "high"

    # Domain allow/deny patterns
    allow_domains: list[str] = field(default_factory=list)
    deny_domains: list[str] = field(default_factory=list)

    @property
    def has_ignores(self) -> bool:
        return bool(self.ignore_rules or self.ignore_fields)


def _load_toml(path: Path) -> dict[str, Any]:
    """Load a TOML file into a dict.  Requires Python 3.11+."""
    if tomllib is None:
        raise RuntimeError(
            "TOML config requires Python 3.11+ (tomllib). "
            "Use a .tool-scan.json file on Python 3.10."
        )
    with open(path, "rb") as f:
        result: dict[str, Any] = tomllib.load(f)
    return result


def _load_json(path: Path) -> dict[str, Any]:
    """Load a JSON config file into a dict."""
    with open(path) as f:
        data: Any = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Config must be a JSON object, got {type(data).__name__}")
    return data


def _extract_tool_scan_section(raw: dict[str, Any], *, from_pyproject: bool = False) -> dict[str, Any]:
    """Extract the tool-scan config section from a raw config dict.

    For ``pyproject.toml`` files the section lives under
    ``[tool.tool-scan]``; standalone config files are used as-is.
    """
    if from_pyproject:
        tool_section = raw.get("tool", {})
        if not isinstance(tool_section, dict):
            return {}
        section: dict[str, Any] = tool_section.get("tool-scan", {})
        return section
    return raw


def _resolve_config(section: dict[str, Any]) -> ToolScanConfig:
    """Build a ``ToolScanConfig`` from a flat/nested config dict."""
    cfg = ToolScanConfig()

    # Top-level scalars
    if "min_score" in section:
        cfg.min_score = int(section["min_score"])
    if "strict" in section:
        cfg.strict = bool(section["strict"])
    if "include_optional" in section:
        cfg.include_optional = bool(section["include_optional"])

    # [ignore] section
    ignore = section.get("ignore", {})
    if isinstance(ignore, dict):
        rules = ignore.get("rules", [])
        if isinstance(rules, list):
            cfg.ignore_rules = [str(r) for r in rules]
        fields = ignore.get("fields", [])
        if isinstance(fields, list):
            cfg.ignore_fields = [str(f) for f in fields]

    # [thresholds] section
    thresholds = section.get("thresholds", {})
    if isinstance(thresholds, dict):
        sev = thresholds.get("fail_severity")
        if isinstance(sev, str) and sev.lower() in ("low", "medium", "high", "critical"):
            cfg.fail_severity = sev.lower()

    # [domains] section
    domains = section.get("domains", {})
    if isinstance(domains, dict):
        allow = domains.get("allow", [])
        if isinstance(allow, list):
            cfg.allow_domains = [str(d) for d in allow]
        deny = domains.get("deny", [])
        if isinstance(deny, list):
            cfg.deny_domains = [str(d) for d in deny]

    return cfg


def load_config(path: str | Path | None = None) -> ToolScanConfig:
    """Load configuration from an explicit path or auto-discover.

    Search order when *path* is ``None``:

    1. ``.tool-scan.toml`` in cwd
    2. ``.tool-scan.json`` in cwd
    3. ``pyproject.toml`` under ``[tool.tool-scan]`` in cwd

    Returns a ``ToolScanConfig`` (always succeeds — falls back to defaults).
    """
    if path is not None:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Config file not found: {p}")
        if p.suffix == ".toml":
            raw = _load_toml(p)
            from_pyproject = p.name == "pyproject.toml"
        elif p.suffix == ".json":
            raw = _load_json(p)
            from_pyproject = False
        else:
            raise ValueError(f"Unsupported config format: {p.suffix} (use .toml or .json)")
        section = _extract_tool_scan_section(raw, from_pyproject=from_pyproject)
        return _resolve_config(section)

    # Auto-discover in cwd
    cwd = Path.cwd()

    toml_path = cwd / ".tool-scan.toml"
    if toml_path.exists() and tomllib is not None:
        raw = _load_toml(toml_path)
        return _resolve_config(_extract_tool_scan_section(raw))

    json_path = cwd / ".tool-scan.json"
    if json_path.exists():
        raw = _load_json(json_path)
        return _resolve_config(_extract_tool_scan_section(raw))

    pyproject = cwd / "pyproject.toml"
    if pyproject.exists() and tomllib is not None:
        raw = _load_toml(pyproject)
        section = _extract_tool_scan_section(raw, from_pyproject=True)
        if section:
            return _resolve_config(section)

    # No config found — return defaults
    return ToolScanConfig()
