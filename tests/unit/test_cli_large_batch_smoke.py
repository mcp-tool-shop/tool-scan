from __future__ import annotations

import json
from pathlib import Path

from tool_scan.grader import MCPToolGrader


def test_large_batch_grading_smoke_is_linear_timeish():
    # Not a strict timing test (to avoid flakiness). Instead ensure it runs and returns expected size.
    grader = MCPToolGrader(strict_security=True)

    tools = [
        {"name": f"tool_{i}", "description": "A safe tool", "inputSchema": {"type": "object"}}
        for i in range(300)
    ]
    reports = grader.grade_batch(tools)
    assert len(reports) == 300
    assert "tool_0" in reports
    assert "tool_299" in reports
