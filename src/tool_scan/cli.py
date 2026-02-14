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

from .baseline import BaselineFile, compare_with_baseline, load_baseline, save_baseline
from .config import ToolScanConfig, load_config
from .discovery import discover_files
from .grader import Grade, GradeReport, MCPToolGrader, Remark
from .junit import grade_reports_to_junit
from .profile import ScanProfiler
from .sarif import reports_to_sarif


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
    def disable(cls) -> None:
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
        max_display = 20 if verbose else 5

        for displayed, remark in enumerate(report.remarks):
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


def load_tool(path: str | Path) -> dict[str, Any]:
    """Load a tool definition from a file or stdin."""
    path_str = str(path)
    if path_str == "-":
        data: Any = json.load(sys.stdin)
        return data  # type: ignore[no-any-return]

    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    with open(file_path) as f:
        data = json.load(f)
        return data  # type: ignore[no-any-return]


def _render_output(
    fmt: str,
    reports: dict[str, GradeReport],
    errors: list[str],
    parsed: argparse.Namespace,
) -> str:
    """Render reports in the requested format.

    Returns the formatted string.  For ``text`` format the output is
    printed directly (side-effect) and an empty string is returned so
    the caller doesn't double-print.
    """
    if fmt == "json":
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
        return json.dumps(output, indent=2)

    if fmt == "sarif":
        sarif = reports_to_sarif(reports)
        return json.dumps(sarif, indent=2)

    if fmt == "junit":
        return grade_reports_to_junit(
            reports,
            min_score=parsed.min_score,
            fail_on_unsafe=parsed.strict,
        )

    # Default: text
    # Text is printed directly for color support; return empty string.
    if not parsed.out:
        for report in reports.values():
            print_report(report, verbose=parsed.verbose)
        if len(reports) > 1:
            print_summary_table(reports)
        return ""

    # When writing text to file, build a plain-text version
    Colors.disable()
    lines: list[str] = []
    for report in reports.values():
        lines.append(report.summary)
    return "\n".join(lines)


def _apply_config(parsed: argparse.Namespace, cfg: ToolScanConfig) -> None:
    """Merge config-file defaults into the parsed CLI namespace.

    CLI flags take precedence: if the user passed ``--strict`` on the
    command line, the config-file ``strict = false`` is ignored.  We
    detect "user-provided" by checking argparse defaults.
    """
    # min_score: CLI default is 70 — only override if user didn't pass it
    if parsed.min_score == 70 and cfg.min_score != 70:
        parsed.min_score = cfg.min_score

    # strict: CLI default is False
    if not parsed.strict and cfg.strict:
        parsed.strict = True

    # include_optional: CLI default is False
    if not parsed.include_optional and cfg.include_optional:
        parsed.include_optional = True

    # Stash the full config on the namespace for downstream use
    parsed.cfg = cfg


def _apply_ignores(report: GradeReport, cfg: ToolScanConfig) -> GradeReport:
    """Remove findings matching the config's ignore lists.

    Returns the report with suppressed remarks stripped out.
    Suppressed count is stored in the report for audit trail.
    """
    if not cfg.has_ignores:
        return report

    kept: list[Remark] = []
    suppressed = 0
    for remark in report.remarks:
        # Check rule_id ignore
        if remark.rule_id and remark.rule_id in cfg.ignore_rules:
            suppressed += 1
            continue
        kept.append(remark)

    report.remarks = kept
    report.suppressed_count = suppressed
    return report


def main(args: list[str] | None = None) -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="tool-scan",
        description="Tool-Scan: Security scanner for MCP tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  tool-scan my_tool.json                    Scan a single tool
  tool-scan --format json tool.json         JSON output
  tool-scan --format sarif -o out.sarif .   SARIF for GitHub Code Scanning
  tool-scan --format junit -o report.xml .  JUnit XML for CI
  tool-scan --strict tools/*.json           Strict mode for CI/CD
  cat tool.json | tool-scan -               Read from stdin

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
        "-f",
        "--format",
        choices=["text", "json", "sarif", "junit"],
        default=None,
        metavar="FMT",
        help="Output format: text (default), json, sarif, junit",
    )

    parser.add_argument(
        "-o",
        "--out",
        metavar="FILE",
        default=None,
        help="Write output to FILE instead of stdout",
    )

    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="Output results as JSON (shorthand for --format json)",
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

    parser.add_argument(
        "-c",
        "--config",
        metavar="PATH",
        default=None,
        help="Config file (.tool-scan.toml, .tool-scan.json, or pyproject.toml)",
    )

    parser.add_argument(
        "--baseline",
        metavar="PATH",
        default=None,
        help="Baseline file for comparing against known findings",
    )

    parser.add_argument(
        "--save-baseline",
        metavar="PATH",
        default=None,
        help="Save current findings as a new baseline file",
    )

    parser.add_argument(
        "--fail-on-new",
        action="store_true",
        help="Exit 1 only for new findings (requires --baseline)",
    )

    parser.add_argument(
        "--rules-dir",
        metavar="DIR",
        default=None,
        help="Load custom rule plugins from DIR (*.py files with get_rules())",
    )

    parser.add_argument(
        "--profile",
        action="store_true",
        help="Print per-stage timing breakdown (for large-repo performance analysis)",
    )

    parser.add_argument(
        "--include",
        action="append",
        metavar="GLOB",
        default=None,
        help="Include files matching GLOB when scanning directories (default: *.json). Repeatable.",
    )

    parser.add_argument(
        "--exclude",
        action="append",
        metavar="GLOB",
        default=None,
        help="Exclude files/dirs matching GLOB when scanning directories. Repeatable.",
    )

    parsed = parser.parse_args(args)

    # Load config file (explicit path or auto-discover)
    try:
        cfg = load_config(parsed.config)
    except (FileNotFoundError, ValueError, RuntimeError) as e:
        print(f"Error loading config: {e}", file=sys.stderr)
        return 2

    # Apply config defaults — CLI flags take precedence
    _apply_config(parsed, cfg)

    # Disable colors if requested or not a TTY
    if parsed.no_color or not sys.stdout.isatty():
        Colors.disable()

    # Load plugin rules
    plugin_rules = None
    if parsed.rules_dir:
        from .rules.plugin_loader import PluginLoader, PluginLoadError

        try:
            loader = PluginLoader(parsed.rules_dir)
            plugin_rules = loader.load()
        except PluginLoadError as e:
            print(f"Error loading rules: {e}", file=sys.stderr)
            return 2

    # Initialize profiler
    profiler = ScanProfiler()
    if parsed.profile:
        profiler.start()

    # Initialize grader
    grader = MCPToolGrader(
        strict_security=parsed.strict,
        include_optional_checks=parsed.include_optional,
        plugin_rules=plugin_rules,
    )

    # Discover files (expand directories, apply include/exclude globs)
    resolved_files = discover_files(
        paths=parsed.files,
        include=parsed.include,
        exclude=parsed.exclude,
    )

    if not resolved_files:
        print("No tool files found. Use --include to change file patterns.", file=sys.stderr)
        return 2

    # Load and grade tools
    reports: dict[str, GradeReport] = {}
    errors: list[str] = []

    for file_path in resolved_files:
        try:
            with profiler.stage("load"):
                tool = load_tool(file_path)

            # Handle arrays of tools
            if isinstance(tool, list):
                for i, t in enumerate(tool):
                    name = t.get("name", f"tool_{i}")
                    with profiler.stage("grade"):
                        reports[name] = grader.grade(t)
            else:
                name = tool.get("name", file_path.stem if str(file_path) != "-" else "stdin")
                with profiler.stage("grade"):
                    reports[name] = grader.grade(tool)

        except json.JSONDecodeError as e:
            errors.append(f"Invalid JSON in {file_path}: {e}")
        except FileNotFoundError as e:
            errors.append(str(e))
        except Exception as e:
            errors.append(f"Error processing {file_path}: {e}")

    # Apply config ignore rules to each report
    for name in list(reports):
        reports[name] = _apply_ignores(reports[name], cfg)

    # Save baseline if requested
    if parsed.save_baseline and reports:
        count = save_baseline(reports, parsed.save_baseline)
        print(f"Saved baseline with {count} findings to {parsed.save_baseline}", file=sys.stderr)

    # Load and apply baseline comparison
    baseline: BaselineFile | None = None
    if parsed.baseline:
        try:
            baseline = load_baseline(parsed.baseline)
        except (FileNotFoundError, ValueError) as e:
            print(f"Error loading baseline: {e}", file=sys.stderr)
            return 2

    # Output errors
    if errors:
        for error in errors:
            print(f"{Colors.RED}Error:{Colors.RESET} {error}", file=sys.stderr)
        if not reports:
            return 2

    # Resolve output format (--json is shorthand for --format json)
    fmt = parsed.format or ("json" if parsed.json else "text")

    # Generate output string
    with profiler.stage("output"):
        output_text = _render_output(fmt, reports, errors, parsed)

    # Write to file or stdout
    if parsed.out:
        Path(parsed.out).write_text(output_text, encoding="utf-8")
    elif output_text:
        print(output_text)

    # Print profiling results
    if parsed.profile:
        profile_result = profiler.result(tool_count=len(reports))
        if fmt == "json":
            print(json.dumps({"profile": profile_result.json_report}, indent=2), file=sys.stderr)
        else:
            print(profile_result.summary(), file=sys.stderr)

    # Determine exit code
    if parsed.fail_on_new and baseline:
        # Only fail on NEW findings not in the baseline
        has_new = False
        for report in reports.values():
            comparison = compare_with_baseline(report, baseline)
            if comparison.has_new:
                has_new = True
                break
        return 1 if has_new else 0

    failed = any(
        r.score < parsed.min_score or (parsed.strict and not r.is_safe) for r in reports.values()
    )

    return 1 if failed or errors else 0


if __name__ == "__main__":
    sys.exit(main())
