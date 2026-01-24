# Changelog

All notable changes to Tool-Scan will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
