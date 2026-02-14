# Tool-Scan JSON Report Schema

Machine-readable schema: [`report.schema.json`](report.schema.json)

## Envelope fields

| Field | Type | Description |
|-------|------|-------------|
| `report_version` | `string` | Semver of the report format (`1.0.0`). Bump on breaking changes. |
| `tool_scan_version` | `string` | Package version that produced this report. |
| `ruleset_version` | `string` | Rule-set identifier (e.g. `2026.1`). |
| `tool_name` | `string` | Name of the scanned MCP tool. |
| `score` | `number` | Composite score 0-100. |
| `grade` | `string` | Letter grade (`A+` through `F`). |
| `grade_description` | `string` | Human-readable grade label. |
| `is_safe` | `boolean` | `true` when no HIGH/CRITICAL threats found. |
| `is_compliant` | `boolean` | `true` when all required MCP spec checks pass. |
| `remarks` | `Remark[]` | Ordered list of findings (most critical first). |
| `summary` | `object` | Issue counts by category. |

## Remark object

| Field | Type | Description |
|-------|------|-------------|
| `category` | `string` | One of `CRITICAL`, `SECURITY`, `COMPLIANCE`, `QUALITY`, `BEST_PRACTICE`, `INFO`. |
| `title` | `string` | Short finding title. |
| `description` | `string` | Detailed explanation. |
| `action` | `string\|null` | Suggested fix. |
| `reference` | `string\|null` | External reference (CWE, OWASP, spec URL). |
| `rule_id` | `string\|null` | Stable rule ID (e.g. `TS-INJ-001`). |
| `cwe_id` | `string\|null` | CWE identifier. |
| `owasp_id` | `string\|null` | OWASP identifier. |
| `snippet` | `string\|null` | Context window around the match. |

## Versioning policy

- **`report_version`** follows semver. A major bump means the JSON shape changed in a backward-incompatible way.
- **`ruleset_version`** tracks rule additions or severity changes. Same report_version, different ruleset = new rules but same JSON shape.
- **`tool_scan_version`** is the Python package version.

## Example

```json
{
  "report_version": "1.0.0",
  "tool_scan_version": "1.0.1",
  "ruleset_version": "2026.1",
  "tool_name": "read_file",
  "score": 85.0,
  "grade": "B",
  "grade_description": "Good",
  "is_safe": true,
  "is_compliant": true,
  "remarks": [
    {
      "category": "QUALITY",
      "title": "STRING_NO_CONSTRAINTS",
      "description": "String property 'path' has no validation constraints",
      "action": "Consider adding maxLength, pattern, or format",
      "reference": null,
      "rule_id": null,
      "cwe_id": null,
      "owasp_id": null,
      "snippet": null
    }
  ],
  "summary": {
    "critical_issues": 0,
    "security_issues": 0,
    "compliance_issues": 0,
    "quality_issues": 1
  }
}
```
