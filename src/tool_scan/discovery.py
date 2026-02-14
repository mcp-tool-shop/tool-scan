"""
File Discovery
==============

Recursive directory scanning with include/exclude glob patterns.

Usage:
    from tool_scan.discovery import discover_files

    files = discover_files(
        paths=["tools/", "extras/custom.json"],
        include=["*.json"],
        exclude=["node_modules/**", ".*"],
    )
"""

from __future__ import annotations

from pathlib import Path

# Default include pattern — only JSON files
DEFAULT_INCLUDE = ["*.json"]

# Default exclude patterns — common noise directories
DEFAULT_EXCLUDE = [
    "node_modules",
    ".git",
    "__pycache__",
    ".tox",
    ".venv",
    "venv",
]


def _matches_any(path: Path, patterns: list[str]) -> bool:
    """Check if a path matches any of the glob-style patterns.

    Supports simple name matching (e.g. ``node_modules``) and
    ``fnmatch``-style patterns (e.g. ``*.json``, ``test_*``).
    """
    name = path.name
    for pattern in patterns:
        if path.match(pattern):
            return True
        # Also check if the directory name itself matches (for excludes)
        if name == pattern:
            return True
    return False


def discover_files(
    paths: list[str],
    include: list[str] | None = None,
    exclude: list[str] | None = None,
) -> list[Path]:
    """Discover tool definition files from paths.

    Args:
        paths: List of file paths and/or directory paths.
               Directories are scanned recursively.
               Explicit files are always included (not filtered by include).
        include: Glob patterns for files to include (default: ``["*.json"]``).
                 Only applies to files discovered inside directories.
        exclude: Glob patterns for files/directories to skip.

    Returns:
        Sorted list of unique file paths.
    """
    include = include if include is not None else list(DEFAULT_INCLUDE)
    exclude = exclude if exclude is not None else list(DEFAULT_EXCLUDE)
    found: set[Path] = set()

    for raw in paths:
        # stdin marker — pass through
        if raw == "-":
            found.add(Path("-"))
            continue

        p = Path(raw)

        if p.is_file():
            # Explicit file — always include, no filtering
            found.add(p.resolve())
        elif p.is_dir():
            # Recurse into directory
            _scan_directory(p, include, exclude, found)
        else:
            # Could be a glob pattern like tools/*.json
            expanded = list(Path(".").glob(raw))
            if expanded:
                for ep in expanded:
                    if ep.is_file():
                        found.add(ep.resolve())
                    elif ep.is_dir():
                        _scan_directory(ep, include, exclude, found)
            else:
                # Pass through non-existent paths so load_tool raises
                # FileNotFoundError with a descriptive message
                found.add(p)

    # Return sorted for deterministic output
    result = sorted(found, key=lambda p: str(p))
    return result


def _scan_directory(
    directory: Path,
    include: list[str],
    exclude: list[str],
    found: set[Path],
) -> None:
    """Recursively scan a directory for matching files."""
    for child in sorted(directory.iterdir()):
        # Skip excluded directories/files
        if _matches_any(child, exclude):
            continue

        if child.is_dir():
            _scan_directory(child, include, exclude, found)
        elif child.is_file() and _matches_any(child, include):
            found.add(child.resolve())
