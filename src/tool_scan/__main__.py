"""
Tool-Scan CLI entry point.

Usage:
    python -m tool_scan my_tool.json
    tool-scan my_tool.json  # If installed via pip
"""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
