# Baselines

Baselines let teams acknowledge existing findings and only fail CI on **new** issues.

## Quick Start

```bash
# 1. Generate a baseline from current state
tool-scan --save-baseline baseline.json tools/*.json

# 2. Commit baseline.json to your repo

# 3. In CI, fail only on new findings
tool-scan --baseline baseline.json --fail-on-new tools/*.json
```

## How It Works

Each finding is identified by a stable key:

```
(rule_id, location, snippet_hash)
```

- **rule_id**: The stable rule identifier (e.g. `TS-INJ-001`)
- **location**: Where the finding was detected (e.g. `description`)
- **snippet_hash**: SHA-256 hash (first 8 hex chars) of the context snippet

When `--fail-on-new` is used with `--baseline`, only findings **not** in the baseline trigger a non-zero exit code.

## Baseline File Format

```json
{
  "version": "1",
  "findings": [
    {
      "rule_id": "TS-SSR-001",
      "location": "Detected localhost access",
      "snippet_hash": "a1b2c3d4"
    }
  ]
}
```

## CLI Options

| Flag | Description |
|------|-------------|
| `--baseline <path>` | Load baseline for comparison |
| `--save-baseline <path>` | Save current findings as baseline |
| `--fail-on-new` | Exit 1 only for new findings (requires `--baseline`) |

## Workflow

### Initial Adoption

```bash
# Scan everything, save baseline
tool-scan --save-baseline baseline.json tools/*.json

# Commit
git add baseline.json
git commit -m "chore: add tool-scan baseline"
```

### CI Pipeline

```yaml
# GitHub Actions
- name: Scan MCP Tools
  run: |
    tool-scan --baseline baseline.json --fail-on-new \
      --format sarif -o results.sarif \
      tools/*.json
```

### Reducing the Baseline

As you fix findings, regenerate the baseline to remove resolved items:

```bash
tool-scan --save-baseline baseline.json tools/*.json
```
