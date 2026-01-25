# Tool Scan — GitHub Issues Punch List (Performance-Focused)

One issue per bullet. Each includes acceptance criteria inline.

## P0 — Must-fix (performance correctness)

### Issue: Avoid O(N * P) repeated regex passes by pre-normalizing tool text once
**Priority:** P0  
**Area:** SecurityScanner performance

**Problem:** `SecurityScanner.scan()` repeatedly calls regex searches across many fields and may repeatedly transform text (e.g., `.lower()`, decoding checks). For large tool corpora, this becomes expensive.

**Work:**
- Add a `_collect_text_blobs(tool)` helper that gathers all relevant strings (name, description, schema descriptions, examples, metadata) once.
- Pre-normalize once (e.g., lowercased copy, stripped copy) and scan against those prepared blobs.
- Ensure behavior remains identical to current detection (no regressions).

**Acceptance criteria:**
- Scanning a tool uses a single pre-normalization pass (no repeated `.lower()` inside inner loops).
- Unit test asserts `scan()` calls the collector once per tool (monkeypatchable hook).
- Existing security detection results remain unchanged for a representative set of tools.

---

### Issue: Ensure no regex compilation occurs during scans
**Priority:** P0  
**Area:** SecurityScanner performance

**Problem:** Regex compilation inside scan paths would cause severe slowdowns under batch loads.

**Work:**
- Keep all `re.compile` work confined to initialization and/or cached class-level state.
- Add a regression test that scanning many tools does not call `_compile_patterns` again.

**Acceptance criteria:**
- Test `test_security_scanner_compiles_patterns_once` passes.
- Code contains no `re.compile` calls in scan hot path.

---

## P1 — High leverage (throughput + memory)

### Issue: Add optional concurrency for grading multiple files/tools (`--jobs`)
**Priority:** P1  
**Area:** CLI throughput

**Problem:** CLI processes files sequentially. Large repos/registries can contain hundreds or thousands of tool files.

**Work:**
- Add `--jobs N` option to grade files concurrently (thread pool is fine; scanning is CPU-ish but some work is I/O).
- Preserve deterministic output order (sort by tool name) regardless of concurrency.

**Acceptance criteria:**
- `--jobs 1` matches existing behavior.
- `--jobs >1` produces identical JSON output (ordering + content) to `--jobs 1`.
- Unit test: given a deterministic set, outputs match across jobs=1 vs jobs=4.

---

### Issue: Add `--compact-json` mode to reduce JSON output overhead for huge batches
**Priority:** P1  
**Area:** CLI memory/perf

**Problem:** `json.dumps(..., indent=2)` is expensive and bloats output for large batches.

**Work:**
- Add `--compact-json` flag that prints compact JSON (`separators=(",", ":")`, no indent).
- Keep current indented output as default for humans.

**Acceptance criteria:**
- `--compact-json` emits valid JSON without indentation.
- Output is functionally identical (same fields/values).
- Unit test verifies JSON parses and contains expected keys.

---

### Issue: Reduce peak memory by streaming JSON results (optional)
**Priority:** P1  
**Area:** CLI memory

**Problem:** CLI builds a full `reports` dict and then serializes; for huge batches this increases memory.

**Work:**
- Add optional streaming mode (or incremental writing) for JSON output:
  - write `{ "results": { ... } }` incrementally
  - still compute summary at end (or do two-pass).
- Keep simple mode as default.

**Acceptance criteria:**
- Streaming mode can handle thousands of tools without unbounded memory growth.
- Output remains valid JSON.
- Integration test: streaming output parses and includes all expected results.

---

## P2 — Maintainability & regression-proofing

### Issue: Add lightweight perf regression test suite (call-count based, not timing)
**Priority:** P2  
**Area:** testing

**Problem:** Timing-based perf tests are flaky; call-count and compilation checks are stable.

**Work:**
- Maintain unit tests that enforce:
  - patterns compiled once
  - no expensive ops repeated in tight loops (e.g., schema walker called once per node)
- Add `-m perf` marker for optional extended tests (if desired).

**Acceptance criteria:**
- Perf regression tests pass consistently on CI.
- No strict wall-clock thresholds are required.

