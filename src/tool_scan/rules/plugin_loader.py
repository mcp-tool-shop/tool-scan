"""
Plugin Loader
=============

Loads custom rule plugins from a directory.

Each ``.py`` file in the directory must expose a ``get_rules()``
callable that returns a ``list[PluginRule]``.

Usage:
    loader = PluginLoader("path/to/rules")
    rules = loader.load()

    for rule in rules:
        findings = rule.check(tool)
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

from . import PluginRule


class PluginLoadError(Exception):
    """Raised when a plugin cannot be loaded."""


class PluginLoader:
    """Load plugin rules from a directory of ``.py`` files."""

    def __init__(self, rules_dir: str | Path) -> None:
        self.rules_dir = Path(rules_dir)
        if not self.rules_dir.is_dir():
            raise PluginLoadError(f"Rules directory not found: {self.rules_dir}")

    def load(self) -> list[PluginRule]:
        """Load all plugin rules from the directory.

        Returns:
            A flat list of all ``PluginRule`` objects from all plugins.

        Raises:
            PluginLoadError: If a plugin file cannot be loaded or
                does not expose ``get_rules()``.
        """
        all_rules: list[PluginRule] = []

        for py_file in sorted(self.rules_dir.glob("*.py")):
            if py_file.name.startswith("_"):
                continue  # Skip __init__.py etc.

            rules = self._load_plugin_file(py_file)
            all_rules.extend(rules)

        return all_rules

    def _load_plugin_file(self, path: Path) -> list[PluginRule]:
        """Load a single plugin file and call its ``get_rules()``."""
        module_name = f"tool_scan_plugin_{path.stem}"

        spec = importlib.util.spec_from_file_location(module_name, str(path))
        if spec is None or spec.loader is None:
            raise PluginLoadError(f"Cannot create module spec for {path}")

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module

        try:
            spec.loader.exec_module(module)
        except Exception as e:
            del sys.modules[module_name]
            raise PluginLoadError(f"Error loading plugin {path.name}: {e}") from e

        get_rules = getattr(module, "get_rules", None)
        if get_rules is None:
            del sys.modules[module_name]
            raise PluginLoadError(
                f"Plugin {path.name} does not expose get_rules() function"
            )

        try:
            rules: Any = get_rules()
        except Exception as e:
            raise PluginLoadError(f"Error calling get_rules() in {path.name}: {e}") from e

        if not isinstance(rules, list):
            raise PluginLoadError(
                f"get_rules() in {path.name} must return a list, got {type(rules).__name__}"
            )

        # Validate each rule
        validated: list[PluginRule] = []
        for rule in rules:
            if not isinstance(rule, PluginRule):
                raise PluginLoadError(
                    f"get_rules() in {path.name} returned non-PluginRule: {type(rule).__name__}"
                )
            validated.append(rule)

        return validated
