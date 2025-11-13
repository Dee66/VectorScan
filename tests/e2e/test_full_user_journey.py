import os
import sys
import json
from pathlib import Path

import pytest


# Ensure repository root and tools/vectorscan are importable
_ROOT = Path(__file__).resolve().parents[2]
_TOOLS_VSCAN = _ROOT / "tools" / "vectorscan"
for p in (str(_ROOT), str(_TOOLS_VSCAN)):
    if p not in sys.path:
        sys.path.insert(0, p)


def _read_json(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


def test_end_to_end_happy_path(tmp_path, capsys):
    # Full flow: PASS plan -> PASS exit, optional local lead capture file is written
    import vectorscan

    plan = _ROOT / "examples" / "aws-pgvector-rag" / "tfplan-pass.json"

    # Pre-count capture files
    captures_dir = _TOOLS_VSCAN / "captures"
    before = set(captures_dir.glob("lead_*.json")) if captures_dir.exists() else set()

    code = vectorscan.main([str(plan), "--lead-capture", "--email", "e2e@example.com"])  # type: ignore[arg-type]
    out = capsys.readouterr().out

    # Asserts
    assert code == 0
    assert "PASS - tfplan.json - VectorScan checks" in out

    # A new capture file should exist and contain our email
    after = set(captures_dir.glob("lead_*.json")) if captures_dir.exists() else set()
    new_files = list(after - before)
    assert new_files, "Expected a new local lead capture file to be written"
    payload = _read_json(new_files[-1])
    assert payload.get("email") == "e2e@example.com"
    assert payload.get("result", {}).get("status") == "PASS"


def test_end_to_end_unhappy_path(capsys):
    # Full flow: FAIL plan -> FAIL exit, violations include both policy codes
    import vectorscan

    plan = _ROOT / "examples" / "aws-pgvector-rag" / "tfplan-fail.json"
    code = vectorscan.main([str(plan)])  # type: ignore[arg-type]
    out = capsys.readouterr().out

    assert code == 3
    assert "FAIL - tfplan.json - VectorScan checks" in out
    assert "P-SEC-001" in out  # encryption mandate
    assert "P-FIN-001" in out  # mandatory tags


def test_end_to_end_partial_failure(monkeypatch, capsys):
    # Partial failure: PASS plan but remote POST fails; CLI still succeeds and prints POST result
    import vectorscan
    from urllib import error
    import urllib.request as ur

    plan = _ROOT / "examples" / "aws-pgvector-rag" / "tfplan-pass.json"

    # Force urlopen to raise immediately (simulate endpoint outage) to keep test fast
    original = ur.urlopen
    def boom(*args, **kwargs):
        raise error.URLError("connection refused")
    ur.urlopen = boom  # type: ignore[assignment]

    try:
        os.environ["VSCAN_LEAD_ENDPOINT"] = "https://example.com/capture"
        code = vectorscan.main([str(plan), "--lead-capture", "--email", "e2e2@example.com"])  # type: ignore[arg-type]
    finally:
        ur.urlopen = original
        os.environ.pop("VSCAN_LEAD_ENDPOINT", None)

    out = capsys.readouterr().out
    assert code == 0
    assert "PASS - tfplan.json - VectorScan checks" in out
    assert "Lead POST =>" in out and "SKIP/FAIL" in out
