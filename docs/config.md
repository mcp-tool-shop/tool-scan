# Configuration

Tool-Scan loads configuration from TOML or JSON files to set project-wide defaults.

## Config File Locations

When `--config` is not provided, Tool-Scan auto-discovers config in this order:

1. `.tool-scan.toml` in the current directory
2. `.tool-scan.json` in the current directory
3. `pyproject.toml` under `[tool.tool-scan]`

## Format

### TOML (`.tool-scan.toml`)

```toml
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
```

### JSON (`.tool-scan.json`)

```json
{
  "min_score": 80,
  "strict": true,
  "ignore": {
    "rules": ["TS-SSR-001", "TS-PTR-006"],
    "fields": ["inputSchema.properties.url.default"]
  },
  "thresholds": {
    "fail_severity": "high"
  },
  "domains": {
    "allow": ["*.example.com"],
    "deny": ["evil.com"]
  }
}
```

### pyproject.toml

```toml
[tool.tool-scan]
min_score = 80
strict = true

[tool.tool-scan.ignore]
rules = ["TS-SSR-001"]
```

## Options

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `min_score` | int | 70 | Minimum passing score |
| `strict` | bool | false | Fail on any security issues |
| `include_optional` | bool | false | Include enterprise-level checks |
| `ignore.rules` | list[str] | [] | Rule IDs to suppress (e.g. `"TS-SSR-001"`) |
| `ignore.fields` | list[str] | [] | Tool JSON paths to skip |
| `thresholds.fail_severity` | str | "high" | Minimum severity to trigger failure |
| `domains.allow` | list[str] | [] | Allowed domain patterns |
| `domains.deny` | list[str] | [] | Denied domain patterns |

## CLI Override

CLI flags always take precedence over config file values:

```bash
# Config says min_score=80, but CLI overrides to 90
tool-scan --config .tool-scan.toml --min-score 90 tools/*.json
```

## Inline Suppressions

Individual tools can suppress specific rules with `x-tool-scan-ignore`:

```json
{
  "name": "my_tool",
  "description": "Fetches from http://127.0.0.1:8080/api",
  "inputSchema": { "type": "object" },
  "x-tool-scan-ignore": ["TS-SSR-001"]
}
```

Suppressed findings are counted in the JSON report under `summary.suppressed` for audit visibility.
