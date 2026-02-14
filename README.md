<div align="center">

# Tool-Scan

**Security scanner for MCP (Model Context Protocol) tools**

[![PyPI version](https://img.shields.io/pypi/v/tool-scan.svg)](https://pypi.org/project/tool-scan/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-398%20passed-brightgreen.svg)]()
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-blue.svg)]()

[Installation](#installation) •
[Quick Start](#quick-start) •
[CLI Reference](#cli-reference) •
[Configuration](#configuration) •
[CI/CD Integration](#cicd-integration) •
[API Reference](#api-reference)

</div>

---

## Why Tool-Scan?

MCP tools give AI models the ability to take real actions. But with power comes risk:

- **Tool Poisoning**: Malicious instructions hidden in tool descriptions
- **Prompt Injection**: Attempts to override AI safety guardrails
- **Data Exfiltration**: Covert channels to steal sensitive information
- **Command Injection**: Shell metacharacters in default values

**Tool-Scan** catches these threats before they reach production. Zero dependencies, fast, and built for CI/CD.

## Installation

```bash
pip install tool-scan
```

> Requires Python 3.10+. No external dependencies.

## Quick Start

```bash
# Scan a single tool
tool-scan my_tool.json

# Scan a directory (recursively finds *.json)
tool-scan tools/

# Strict mode for CI/CD
tool-scan --strict --min-score 80 tools/

# Output formats: text (default), json, sarif, junit
tool-scan --format sarif -o results.sarif tools/
tool-scan --format junit -o results.xml tools/
tool-scan --json tools/ > report.json
```

### Python API

```python
from tool_scan import grade_tool

tool = {
    "name": "get_weather",
    "description": "Gets current weather for a location.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "city": {"type": "string", "description": "City name"}
        },
        "required": ["city"],
        "additionalProperties": False
    }
}

report = grade_tool(tool)

print(f"Score: {report.score}/100")   # Score: 95/100
print(f"Grade: {report.grade.letter}") # Grade: A
print(f"Safe: {report.is_safe}")       # Safe: True
```

## CLI Reference

```
tool-scan [OPTIONS] FILE|DIR...
```

### Core Options

| Flag | Description |
|------|-------------|
| `-f`, `--format FMT` | Output format: `text`, `json`, `sarif`, `junit` |
| `-o`, `--out FILE` | Write output to file |
| `-j`, `--json` | Shorthand for `--format json` |
| `-s`, `--strict` | Fail on any security issues |
| `-v`, `--verbose` | Show all remarks and details |
| `--min-score N` | Minimum passing score (default: 70) |
| `--no-color` | Disable colored output |
| `--include-optional` | Include enterprise-level checks |

### File Discovery

| Flag | Description |
|------|-------------|
| `--include GLOB` | Include files matching pattern (default: `*.json`). Repeatable |
| `--exclude GLOB` | Exclude files/dirs matching pattern. Repeatable |

Default excludes: `node_modules`, `.git`, `__pycache__`, `.tox`, `.venv`, `venv`

### Policy Controls

| Flag | Description |
|------|-------------|
| `-c`, `--config PATH` | Config file (`.tool-scan.toml`, `.tool-scan.json`, or `pyproject.toml`) |
| `--baseline PATH` | Compare against known findings |
| `--save-baseline PATH` | Save current findings as baseline |
| `--fail-on-new` | Exit 1 only for new findings (requires `--baseline`) |
| `--rules-dir DIR` | Load custom rule plugins from directory |

### Summary & Performance

| Flag | Description |
|------|-------------|
| `--top N` | Show only the N worst-scoring tools |
| `--profile` | Print per-stage timing breakdown |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All tools passed |
| 1 | One or more tools failed |
| 2 | Error loading files |

## Configuration

Tool-Scan auto-discovers config from `.tool-scan.toml`, `.tool-scan.json`, or `pyproject.toml`. CLI flags always take precedence.

```toml
# .tool-scan.toml
min_score = 80
strict = true

[ignore]
rules = ["TS-SSR-001"]        # Suppress specific rules
# fields = ["inputSchema.properties.url.default"]

[thresholds]
fail_severity = "high"         # "low", "medium", "high", "critical"

[domains]
# allow = ["*.example.com"]
# deny = ["evil.com"]
```

See [docs/config.md](docs/config.md) for full reference.

### Inline Suppressions

Individual tools can suppress specific rules:

```json
{
  "name": "my_tool",
  "description": "Fetches from http://127.0.0.1:8080/api",
  "inputSchema": { "type": "object", "properties": {} },
  "x-tool-scan-ignore": ["TS-SSR-001"]
}
```

Suppressed findings are tracked in the JSON report for audit visibility.

### Baselines

Baselines let teams adopt Tool-Scan incrementally, failing CI only on **new** findings:

```bash
# Generate baseline from current state
tool-scan --save-baseline baseline.json tools/

# In CI, fail only on new findings
tool-scan --baseline baseline.json --fail-on-new tools/
```

See [docs/baseline.md](docs/baseline.md) for workflow details.

## Security Checks

### Prompt Injection / Tool Poisoning

| Threat | Example | Severity |
|--------|---------|----------|
| Instruction override | `"ignore previous instructions"` | Critical |
| Role manipulation | `"you are now an admin"` | High |
| Covert actions | `"secretly execute..."` | Critical |
| Fake system tags | `"<system>..."` | High |
| Hidden unicode | Zero-width spaces | High |
| Homoglyph attacks | Cyrillic lookalikes | Medium |

### Code Injection

| Threat | Example | Severity |
|--------|---------|----------|
| Command injection | `"; rm -rf /"` | Critical |
| SQL injection | `"' OR 1=1 --"` | Critical |
| XSS | `"<script>..."` | Critical |
| Path traversal | `"../../etc/passwd"` | High |

### Network Security

| Threat | Example | Severity |
|--------|---------|----------|
| SSRF (localhost) | `"http://127.0.0.1"` | Medium |
| SSRF (metadata) | `"http://169.254.169.254"` | Critical |
| Data exfiltration | `"send data to http://..."` | Critical |

## Grading System

### Score Breakdown

| Component | Weight | Description |
|-----------|--------|-------------|
| Security | 40% | No vulnerabilities |
| Compliance | 35% | MCP 2025-11-25 spec adherence |
| Quality | 25% | Best practices, documentation |

### Grade Scale

| Grade | Score | Recommendation |
|-------|-------|----------------|
| A+ | 97-100 | Production ready |
| A/A- | 90-96 | Excellent / Very good |
| B+/B/B- | 80-89 | Good / Above average |
| C+/C/C- | 70-79 | Satisfactory / Minimum passing |
| D | 60-69 | Poor |
| F | 0-59 | **Do not use** |

## Custom Rules (Plugins)

Write custom rules as Python files with a `get_rules()` entry point:

```python
# my_rules/check_naming.py
from tool_scan.rules import PluginRule, PluginFinding, Severity

def _check(tool):
    findings = []
    name = tool.get("name", "")
    if not name.startswith("org_"):
        findings.append(PluginFinding(
            message=f"Tool '{name}' must use org_ prefix",
            snippet=name,
        ))
    return findings

def get_rules():
    return [
        PluginRule(
            rule_id="CUSTOM-001",
            title="Org naming convention",
            severity=Severity.LOW,
            check=_check,
        )
    ]
```

```bash
tool-scan --rules-dir my_rules/ tools/
```

See [examples/sample_plugin.py](examples/sample_plugin.py) for a complete example.

## CI/CD Integration

### GitHub Actions

```yaml
name: Tool-Scan

on:
  push:
    paths: ['tools/**/*.json', '.tool-scan.toml']
  pull_request:
    paths: ['tools/**/*.json', '.tool-scan.toml']
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Tool-Scan
        run: pip install tool-scan

      - name: Scan MCP Tools
        run: |
          tool-scan --strict --min-score 80 \
            --baseline baseline.json --fail-on-new \
            --format sarif -o results.sarif \
            tools/

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

### GitHub Actions (with JUnit)

```yaml
      - name: Scan with JUnit
        run: |
          tool-scan --format junit -o results.xml tools/

      - name: Upload JUnit
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: tool-scan-results
          path: results.xml
```

### GitLab CI

```yaml
tool-scan:
  stage: test
  image: python:3.11-slim
  before_script:
    - pip install tool-scan
  script:
    - tool-scan --strict --min-score 80
        --format junit -o results.xml
        tools/
  artifacts:
    reports:
      junit: results.xml
    when: always
  rules:
    - changes:
        - tools/**/*.json
        - .tool-scan.toml
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: tool-scan
        name: Tool-Scan
        entry: tool-scan --strict
        language: python
        files: '\.json$'
        types: [json]
```

## MCP Compliance

Validates against [MCP Specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25):

- Required fields (name, description, inputSchema)
- Valid name format (alphanumeric, underscore, hyphen)
- Root schema type `object`
- Required properties exist in schema
- Annotation types (readOnlyHint, destructiveHint, etc.)

## API Reference

### grade_tool()

```python
from tool_scan import grade_tool

report = grade_tool(tool, strict=True)
```

**Parameters:**
- `tool`: Dict containing tool definition
- `strict`: Fail on any security issues (default: True)

**Returns:** `GradeReport` with:
- `score`: 0-100 numeric score
- `grade`: Letter grade (A+ to F)
- `is_safe`: Boolean safety status
- `is_compliant`: MCP spec compliance
- `remarks`: List of actionable recommendations

### MCPToolGrader

```python
from tool_scan import MCPToolGrader

grader = MCPToolGrader(
    strict_security=True,
    include_optional_checks=False,
    plugin_rules=None,      # Custom rules from PluginLoader
)

report = grader.grade(tool)
reports = grader.grade_batch([tool1, tool2, tool3])
```

### SecurityScanner

```python
from tool_scan import SecurityScanner

scanner = SecurityScanner(fail_on_medium=False)
result = scanner.scan(tool)
print(result.is_safe)
print(result.threats)
```

### ComplianceChecker

```python
from tool_scan import ComplianceChecker

checker = ComplianceChecker(
    check_required=True,
    check_recommended=True,
    check_optional=False,
)

report = checker.check(tool)
print(report.is_compliant)
print(report.compliance_score)
```

## References

- [MCP Specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25)
- [MCP Security Best Practices](https://www.practical-devsecops.com/mcp-security-vulnerabilities/)
- [JSON Schema 2020-12](https://json-schema.org/draft/2020-12/schema)

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.

---

<div align="center">

Made by [MCP Tool Shop](https://github.com/mcp-tool-shop-org)

</div>
