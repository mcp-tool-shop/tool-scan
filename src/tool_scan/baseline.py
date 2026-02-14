"""
Baseline Support
================

Load and compare baseline findings so teams can acknowledge known noise
and only fail CI on *new* findings.

Baseline file format (JSON):

    {
        "version": "1",
        "findings": [
            {
                "rule_id": "TS-SSR-001",
                "location": "inputSchema.properties.url.default",
                "snippet_hash": "a1b2c3d4"
            }
        ]
    }

The stable key for each finding is ``(rule_id, location, snippet_hash)``.
``snippet_hash`` is the first 8 hex chars of a SHA-256 of the snippet text.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .grader import GradeReport, Remark


def _snippet_hash(snippet: str | None) -> str:
    """Deterministic short hash of a snippet for baseline matching."""
    text = snippet or ""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]


@dataclass
class BaselineFinding:
    """A single baseline entry."""

    rule_id: str
    location: str
    snippet_hash: str

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.rule_id, self.location, self.snippet_hash)


@dataclass
class BaselineFile:
    """Loaded baseline with efficient lookup."""

    findings: list[BaselineFinding] = field(default_factory=list)

    @property
    def keys(self) -> set[tuple[str, str, str]]:
        return {f.key for f in self.findings}


@dataclass
class BaselineComparison:
    """Result of comparing current findings against a baseline."""

    new_findings: list[Remark] = field(default_factory=list)
    known_findings: list[Remark] = field(default_factory=list)

    @property
    def has_new(self) -> bool:
        return len(self.new_findings) > 0


def load_baseline(path: str | Path) -> BaselineFile:
    """Load a baseline JSON file.

    Args:
        path: Path to the baseline file.

    Returns:
        A ``BaselineFile`` with indexed findings.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file is malformed.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Baseline file not found: {p}")

    with open(p) as f:
        data: Any = json.load(f)

    if not isinstance(data, dict):
        raise ValueError("Baseline must be a JSON object")

    findings: list[BaselineFinding] = []
    raw_findings = data.get("findings", [])
    if not isinstance(raw_findings, list):
        raise ValueError("Baseline 'findings' must be an array")

    for entry in raw_findings:
        if not isinstance(entry, dict):
            continue
        rule_id = entry.get("rule_id", "")
        location = entry.get("location", "")
        snippet_hash = entry.get("snippet_hash", "")
        if rule_id:
            findings.append(BaselineFinding(
                rule_id=str(rule_id),
                location=str(location),
                snippet_hash=str(snippet_hash),
            ))

    return BaselineFile(findings=findings)


def save_baseline(reports: dict[str, GradeReport], path: str | Path) -> int:
    """Generate and save a baseline file from current scan results.

    Args:
        reports: Scan results to baseline.
        path: Output path.

    Returns:
        Number of findings baselined.
    """
    findings: list[dict[str, str]] = []
    for report in reports.values():
        for remark in report.remarks:
            if remark.rule_id:
                findings.append({
                    "rule_id": remark.rule_id,
                    "location": remark.description,
                    "snippet_hash": _snippet_hash(remark.snippet),
                })

    baseline = {
        "version": "1",
        "findings": findings,
    }

    Path(path).write_text(json.dumps(baseline, indent=2), encoding="utf-8")
    return len(findings)


def compare_with_baseline(
    report: GradeReport,
    baseline: BaselineFile,
) -> BaselineComparison:
    """Compare a report's remarks against a baseline.

    Remarks whose ``(rule_id, location, snippet_hash)`` tuple appears
    in the baseline are classified as "known"; all others are "new".

    Remarks without a ``rule_id`` are always treated as new.
    """
    baseline_keys = baseline.keys
    new: list[Remark] = []
    known: list[Remark] = []

    for remark in report.remarks:
        if not remark.rule_id:
            new.append(remark)
            continue

        key = (
            remark.rule_id,
            remark.description,
            _snippet_hash(remark.snippet),
        )
        if key in baseline_keys:
            known.append(remark)
        else:
            new.append(remark)

    return BaselineComparison(new_findings=new, known_findings=known)
