# Changelog

All notable changes to Tool-Scan will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-02-14

### Added

- **Configuration files** — `.tool-scan.toml`, `.tool-scan.json`, or `pyproject.toml` support
  with auto-discovery and CLI override precedence
- **Baseline comparison** — `--baseline` / `--save-baseline` / `--fail-on-new` for incremental
  adoption in CI (only fail on new findings)
- **Inline suppressions** — `x-tool-scan-ignore` field in tool JSON for per-tool rule suppression
  with audit trail via `suppressed` count in reports
- **Plugin rule system** — `--rules-dir` loads custom `*.py` rules with `get_rules()` entry point
- **Directory scanning** — `tool-scan <dir>` recursively discovers `*.json` files with
  `--include` / `--exclude` glob patterns
- **Performance profiling** — `--profile` flag prints per-stage timing breakdown (load/grade/output)
- **Summary UX** — `--top N` shows worst-scoring tools; category counts (critical/security/
  compliance/quality) in text and JSON output
- **Output formats** — SARIF (`--format sarif`) and JUnit XML (`--format junit`) for CI/CD
- **GitLab CI recipe** in README

### Changed

- README fully rewritten with CLI reference, config docs, and CI recipes
- JSON output now includes `summary.findings` category breakdown
- Test count: 147 → 398

### Fixed

- Ruff lint violations across test suite
- Mypy strict mode clean on all 16 source files

## [1.0.1] - 2025-01-25

### Fixed

- Minor packaging and CI fixes

## [1.0.0] - 2025-01-24

### Added

- Initial release
- Security scanning for MCP tools
  - Prompt injection detection
  - Tool poisoning prevention
  - Command injection detection
  - SQL injection detection
  - XSS detection
  - SSRF detection
  - Path traversal detection
  - Data exfiltration detection
- MCP 2025-11-25 specification compliance checking
- Quality scoring system (1-100 with letter grades A+ to F)
- Actionable remediation remarks
- CLI tool (`tool-scan`) for CI/CD integration
- Python API for programmatic usage
- JSON output format for automation
- Batch scanning support
- Strict mode for security-critical environments

### Security Patterns

- 50+ patterns for prompt injection detection
- 15+ patterns for command injection
- 10+ patterns for SQL injection
- 10+ patterns for XSS
- 8+ patterns for SSRF
- 5+ patterns for path traversal
- Hidden unicode character detection
- Homoglyph attack detection
- Base64/hex encoded content scanning
