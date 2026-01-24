#!/usr/bin/env python3
"""
Tool-Scan CLI
=============

Security scanner for MCP tools.

Usage:
    # Scan a single tool
    tool-scan my_tool.json

    # Scan multiple tools
    tool-scan tool1.json tool2.json

    # JSON output for CI/CD
    tool-scan --json tool.json

    # Strict mode (fail on any security issues)
    tool-scan --strict tool.json

    # Scan from stdin
    cat tool.json | tool-scan -

Examples:
    # Quick security check
    tool-scan my_tool.json

    # CI/CD integration
    tool-scan --strict --min-score 80 --json tools/*.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .grader import Grade, GradeReport, MCPToolGrader


# ANSI color codes
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"

    @classmethod
    def disable(cls):
        """Disable colors for non-TTY output."""
        cls.RESET = ""
        cls.BOLD = ""
        cls.RED = ""
        cls.GREEN = ""
        cls.YELLOW = ""
        cls.BLUE = ""
        cls.MAGENTA = ""
        cls.CYAN = ""


def colorize_grade(grade: Grade) -> str:
    """Colorize grade based on letter."""
    if grade.letter.startswith("A"):
        return f"{Colors.GREEN}{Colors.BOLD}{grade.letter}{Colors.RESET}"
    elif grade.letter.startswith("B"):
        return f"{Colors.BLUE}{grade.letter}{Colors.RESET}"
    elif grade.letter.startswith("C"):
        return f"{Colors.YELLOW}{grade.letter}{Colors.RESET}"
    elif grade.letter.startswith("D"):
        return f"{Colors.MAGENTA}{grade.letter}{Colors.RESET}"
    else:
        return f"{Colors.RED}{Colors.BOLD}{grade.letter}{Colors.RESET}"


def colorize_score(score: float) -> str:
    """Colorize score based on value."""
    if score >= 90:
        return f"{Colors.GREEN}{score:.0f}{Colors.RESET}"
    elif score >= 80:
        return f"{Colors.BLUE}{score:.0f}{Colors.RESET}"
    elif score >= 70:
        return f"{Colors.YELLOW}{score:.0f}{Colors.RESET}"
    elif score >= 60:
        return f"{Colors.MAGENTA}{score:.0f}{Colors.RESET}"
    else:
        return f"{Colors.RED}{score:.0f}{Colors.RESET}"


def print_report(report: GradeReport, verbose: bool = False) -> None:
    """Print a formatted grade report."""
    print()
    print(f"{Colors.BOLD}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}Tool: {Colors.CYAN}{report.tool_name}{Colors.RESET}")
    print(f"{Colors.BOLD}{'=' * 60}{Colors.RESET}")
    print()

    # Score and grade
    print(f"  Score: {colorize_score(report.score)}/100")
    print(f"  Grade: {colorize_grade(report.grade)} ({report.grade.description})")
    print()

    # Status - use ASCII alternatives for Windows compatibility
    safe_icon = (
        f"{Colors.GREEN}[OK]{Colors.RESET}" if report.is_safe else f"{Colors.RED}[X]{Colors.RESET}"
    )
    compliant_icon = (
        f"{Colors.GREEN}[OK]{Colors.RESET}"
        if report.is_compliant
        else f"{Colors.RED}[X]{Colors.RESET}"
    )
    print(f"  Safe: {safe_icon} {'Yes' if report.is_safe else 'No - Security Issues Found'}")
    print(
        f"  Compliant: {compliant_icon} {'Yes' if report.is_compliant else 'No - MCP Spec Violations'}"
    )
    print()

    # Remarks
    if report.remarks:
        print(f"  {Colors.BOLD}Remarks ({len(report.remarks)}):{Colors.RESET}")
        displayed = 0
        max_display = 20 if verbose else 5

        for remark in report.remarks:
            if displayed >= max_display:
                remaining = len(report.remarks) - displayed
                print(f"    {Colors.CYAN}... and {remaining} more (use --verbose){Colors.RESET}")
                break

            # Color code by category
            if "Critical" in remark.category.value:
                color = Colors.RED
            elif "Security" in remark.category.value:
                color = Colors.MAGENTA
            elif "Compliance" in remark.category.value:
                color = Colors.YELLOW
            else:
                color = Colors.BLUE

            print(f"    {color}{remark.category.value}{Colors.RESET}: {remark.title}")
            if verbose and remark.action:
                print(f"      → {remark.action}")
            displayed += 1
    else:
        print(f"  {Colors.GREEN}No issues found - Tool is ready for production!{Colors.RESET}")

    print()


def print_summary_table(reports: dict[str, GradeReport]) -> None:
    """Print a summary table for multiple tools."""
    print()
    print(f"{Colors.BOLD}Summary{Colors.RESET}")
    print()

    # Header
    print(f"  {'Tool Name':<40} {'Score':>7} {'Grade':>7} {'Status':>10}")
    print(f"  {'-' * 40} {'-' * 7} {'-' * 7} {'-' * 10}")

    # Rows
    for name, report in sorted(reports.items(), key=lambda x: -x[1].score):
        status = (
            f"{Colors.GREEN}Safe{Colors.RESET}"
            if report.is_safe
            else f"{Colors.RED}Unsafe{Colors.RESET}"
        )
        print(
            f"  {name[:40]:<40} "
            f"{colorize_score(report.score):>7} "
            f"{colorize_grade(report.grade):>7} "
            f"{status:>10}"
        )

    print()

    # Overall stats
    total = len(reports)
    safe = sum(1 for r in reports.values() if r.is_safe)
    compliant = sum(1 for r in reports.values() if r.is_compliant)
    avg_score = sum(r.score for r in reports.values()) / total if total > 0 else 0

    print(f"  {Colors.BOLD}Total:{Colors.RESET} {total} tools")
    print(f"  {Colors.BOLD}Average Score:{Colors.RESET} {colorize_score(avg_score)}")
    print(f"  {Colors.BOLD}Safe:{Colors.RESET} {safe}/{total}")
    print(f"  {Colors.BOLD}Compliant:{Colors.RESET} {compliant}/{total}")
    print()


def load_tool(path: str) -> dict[str, Any]:
    """Load a tool definition from a file or stdin."""
    if path == "-":
        return json.load(sys.stdin)

    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    with open(file_path) as f:
        return json.load(f)


def main(args: list[str] | None = None) -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="tool-scan",
        description="Tool-Scan: Security scanner for MCP tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  tool-scan my_tool.json                Scan a single tool
  tool-scan --json tool.json            Output as JSON
  tool-scan --strict tools/*.json       Strict mode for CI/CD
  cat tool.json | tool-scan -           Read from stdin

Exit codes:
  0  All tools passed (grade C- or better, no security issues)
  1  One or more tools failed security scan
  2  Error loading or parsing files
        """,
    )

    parser.add_argument(
        "files",
        nargs="+",
        metavar="FILE",
        help="Tool definition JSON file(s), or - for stdin",
    )

    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="Output results as JSON",
    )

    parser.add_argument(
        "-s",
        "--strict",
        action="store_true",
        help="Strict mode: fail on any security issues",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show all remarks and details",
    )

    parser.add_argument(
        "--min-score",
        type=int,
        default=70,
        metavar="N",
        help="Minimum passing score (default: 70)",
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )

    parser.add_argument(
        "--include-optional",
        action="store_true",
        help="Include optional enterprise checks",
    )

    parsed = parser.parse_args(args)

    # Disable colors if requested or not a TTY
    if parsed.no_color or not sys.stdout.isatty():
        Colors.disable()

    # Initialize grader
    grader = MCPToolGrader(
        strict_security=parsed.strict,
        include_optional_checks=parsed.include_optional,
    )

    # Load and grade tools
    reports: dict[str, GradeReport] = {}
    errors: list[str] = []

    for file_path in parsed.files:
        try:
            tool = load_tool(file_path)

            # Handle arrays of tools
            if isinstance(tool, list):
                for i, t in enumerate(tool):
                    name = t.get("name", f"tool_{i}")
                    reports[name] = grader.grade(t)
            else:
                name = tool.get("name", Path(file_path).stem if file_path != "-" else "stdin")
                reports[name] = grader.grade(tool)

        except json.JSONDecodeError as e:
            errors.append(f"Invalid JSON in {file_path}: {e}")
        except FileNotFoundError as e:
            errors.append(str(e))
        except Exception as e:
            errors.append(f"Error processing {file_path}: {e}")

    # Output errors
    if errors:
        for error in errors:
            print(f"{Colors.RED}Error:{Colors.RESET} {error}", file=sys.stderr)
        if not reports:
            return 2

    # Output results
    if parsed.json:
        output = {
            "results": {name: report.json_report for name, report in reports.items()},
            "summary": {
                "total": len(reports),
                "passed": sum(
                    1 for r in reports.values() if r.score >= parsed.min_score and r.is_safe
                ),
                "failed": sum(
                    1 for r in reports.values() if r.score < parsed.min_score or not r.is_safe
                ),
                "average_score": sum(r.score for r in reports.values()) / len(reports)
                if reports
                else 0,
            },
            "errors": errors,
        }
        print(json.dumps(output, indent=2))
    else:
        # Print individual reports
        for report in reports.values():
            print_report(report, verbose=parsed.verbose)

        # Print summary if multiple tools
        if len(reports) > 1:
            print_summary_table(reports)

    # Determine exit code
    failed = any(
        r.score < parsed.min_score or (parsed.strict and not r.is_safe) for r in reports.values()
    )

    return 1 if failed or errors else 0


if __name__ == "__main__":
    sys.exit(main())
