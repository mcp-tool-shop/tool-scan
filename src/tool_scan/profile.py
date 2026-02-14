"""
Profiling Support
=================

Per-stage timing for large-repo scans.

Usage:
    from tool_scan.profile import ScanProfiler

    profiler = ScanProfiler()
    with profiler.stage("load"):
        tool = load_tool(path)
    with profiler.stage("grade"):
        report = grader.grade(tool)

    print(profiler.summary())
"""

from __future__ import annotations

import time
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any


@dataclass
class StageResult:
    """Timing result for a single stage."""

    name: str
    elapsed_ms: float
    count: int = 1


@dataclass
class ProfileResult:
    """Complete profiling result for a scan run."""

    stages: list[StageResult] = field(default_factory=list)
    tool_count: int = 0
    total_ms: float = 0.0

    @property
    def json_report(self) -> dict[str, Any]:
        return {
            "tool_count": self.tool_count,
            "total_ms": round(self.total_ms, 2),
            "stages": [
                {
                    "name": s.name,
                    "elapsed_ms": round(s.elapsed_ms, 2),
                    "count": s.count,
                }
                for s in self.stages
            ],
        }

    def summary(self) -> str:
        lines = [
            "",
            "Profile:",
            f"  Tools scanned: {self.tool_count}",
            f"  Total time: {self.total_ms:.1f} ms",
            "",
        ]
        if self.stages:
            # Find widest name for alignment
            max_name = max(len(s.name) for s in self.stages)
            for s in self.stages:
                pct = (s.elapsed_ms / self.total_ms * 100) if self.total_ms > 0 else 0
                lines.append(
                    f"  {s.name:<{max_name}}  {s.elapsed_ms:8.1f} ms  ({pct:5.1f}%)"
                )
        lines.append("")
        return "\n".join(lines)


class ScanProfiler:
    """Lightweight profiler for scan stages."""

    def __init__(self) -> None:
        self._timings: dict[str, float] = {}
        self._counts: dict[str, int] = {}
        self._start_time: float = 0.0
        self.enabled = False

    def start(self) -> None:
        """Begin the overall timer."""
        self.enabled = True
        self._start_time = time.perf_counter()

    @contextmanager
    def stage(self, name: str) -> Generator[None, None, None]:
        """Time a named stage.

        Usage::

            with profiler.stage("security"):
                result = scanner.scan(tool)
        """
        if not self.enabled:
            yield
            return

        t0 = time.perf_counter()
        yield
        elapsed = (time.perf_counter() - t0) * 1000  # ms
        self._timings[name] = self._timings.get(name, 0.0) + elapsed
        self._counts[name] = self._counts.get(name, 0) + 1

    def result(self, tool_count: int) -> ProfileResult:
        """Finalize and return the profiling result."""
        total = (time.perf_counter() - self._start_time) * 1000 if self._start_time else 0.0
        stages = [
            StageResult(name=name, elapsed_ms=ms, count=self._counts.get(name, 1))
            for name, ms in self._timings.items()
        ]
        return ProfileResult(stages=stages, tool_count=tool_count, total_ms=total)
