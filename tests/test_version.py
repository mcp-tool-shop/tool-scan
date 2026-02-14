"""Version consistency tests."""

from __future__ import annotations

import importlib.metadata


def test_version_matches_metadata() -> None:
    """Ensure __version__ matches pyproject.toml version."""
    from tool_scan import __version__

    pkg_version = importlib.metadata.version("tool-scan")
    assert __version__ == pkg_version, (
        f"__version__ ({__version__}) != pyproject.toml ({pkg_version})"
    )


def test_version_is_semver() -> None:
    """Ensure version follows semver pattern."""
    from tool_scan import __version__

    parts = __version__.split(".")
    assert len(parts) == 3, f"Expected 3-part semver, got {__version__}"
    for part in parts:
        assert part.isdigit(), f"Non-numeric version part: {part}"
