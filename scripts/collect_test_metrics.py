#!/usr/bin/env python3
"""
Collect basic test metrics and write docs/test_coverage_metrics.md.

Metrics:
 - Unit test run summary (opa test json parse)
 - Integration test run summary
 - Violation artifacts count
 - Fuzz configuration (if provided via env)
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from tools.vectorscan.time_utils import deterministic_isoformat

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "test_coverage_metrics.md"
JSON_OUT = ROOT / "coverage" / "test_metrics.json"


def opa_test_json(paths: list[str]) -> dict:
    cmd = ["opa", "test", "-f", "json"] + paths
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"opa test failed: {proc.stderr}")
    try:
        return json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return {}


def summarize(results: dict) -> tuple[int, int]:
    # Count tests and failures from json structure
    tests = 0
    fails = 0
    for pkg in results.get("packages", []):
        for t in pkg.get("tests", []):
            tests += 1
            if not t.get("pass", False):
                fails += 1
    return tests, fails


def main() -> int:
    ts = deterministic_isoformat()
    unit_json = opa_test_json(
        [
            str(ROOT / "policies"),
            str(ROOT / "tools" / "vectorscan"),
            str(ROOT / "tests" / "rego-tests"),
        ]
    )
    unit_total, unit_fail = summarize(unit_json)

    # Integration (same runner includes integration tests file)
    integ_json = opa_test_json([str(ROOT / "policies"), str(ROOT / "tests" / "integration")])
    integ_total, integ_fail = summarize(integ_json)

    # Violation artifact count
    vio_count = len(list((ROOT / "examples" / "aws-pgvector-rag" / "violations").glob("*.json")))

    # Corpus sizes (if present)
    consolidated_dir = ROOT / "corpora" / "consolidated_db"
    consolidated_count = (
        sum(1 for _ in consolidated_dir.rglob("*")) if consolidated_dir.exists() else 0
    )
    minimized_dir = ROOT / "corpora" / "minimized_db"
    minimized_count = sum(1 for _ in minimized_dir.rglob("*")) if minimized_dir.exists() else 0
    pruned_examples_dir = ROOT / "corpora" / "pruned"
    pruned_examples_count = (
        len(list(pruned_examples_dir.glob("*.json"))) if pruned_examples_dir.exists() else 0
    )

    # Previous metrics for deltas
    prev_metrics_path = ROOT / "coverage" / "prev_test_metrics.json"
    prev = None
    if prev_metrics_path.exists():
        try:
            prev = json.loads(prev_metrics_path.read_text(encoding="utf-8"))
        except Exception:
            prev = None

    def delta(key: str, current: int | float | None) -> str:
        if prev is None or current is None:
            return "(Δ n/a)"
        pv = prev.get(key)
        if pv is None:
            return "(Δ n/a)"
        try:
            return f"(Δ {current - pv})"
        except Exception:
            return "(Δ n/a)"

    # Mutation kill ratio (if present)
    mutation_json_path = ROOT / "coverage" / "mutation_summary.json"
    kill_ratio = None
    killed = survived = total_mutants = 0
    if mutation_json_path.exists():
        try:
            m = json.loads(mutation_json_path.read_text(encoding="utf-8"))
            kill_ratio = m.get("kill_ratio")
            killed = m.get("killed", 0)
            survived = m.get("survived", 0)
            total_mutants = m.get("total_mutants", 0)
        except Exception:
            pass

    shards = os.getenv("SHARDS")
    total_examples = os.getenv("TOTAL_EXAMPLES")

    md = [
        "# Test Coverage Metrics",
        "",
        f"Last updated: {ts}",
        "",
        "## Summary",
        "",
        f"- Unit tests: {unit_total} total, {unit_fail} failed",
        f"- Integration tests: {integ_total} total, {integ_fail} failed",
        f"- Violation artifacts: {vio_count}",
        f"- Consolidated corpus files: {consolidated_count} {delta('consolidated_count', consolidated_count)}",
        f"- Minimized corpus files: {minimized_count} {delta('minimized_count', minimized_count)}",
        f"- Pruned saved examples: {pruned_examples_count} {delta('pruned_examples_count', pruned_examples_count)}",
    ]
    if shards and total_examples:
        md.append(f"- Nightly fuzz config: shards={shards}, total_examples={total_examples}")
    if kill_ratio is not None:
        md.append(
            f"- Mutation kill ratio: {kill_ratio:.2%} ({killed}/{total_mutants}, survived={survived})"
        )
    md.append("")
    DOC.write_text("\n".join(md) + "\n")
    print("Wrote", DOC)

    # Write JSON metrics for easy delta computations
    JSON_OUT.parent.mkdir(parents=True, exist_ok=True)
    metrics = {
        "timestamp": ts,
        "unit_total": unit_total,
        "unit_fail": unit_fail,
        "integration_total": integ_total,
        "integration_fail": integ_fail,
        "violation_artifacts": vio_count,
        "consolidated_count": consolidated_count,
        "minimized_count": minimized_count,
        "pruned_examples_count": pruned_examples_count,
        "kill_ratio": kill_ratio,
        "killed": killed,
        "survived": survived,
        "total_mutants": total_mutants,
        "shards": int(shards) if shards else None,
        "total_examples": int(total_examples) if total_examples else None,
    }
    JSON_OUT.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print("Wrote", JSON_OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
