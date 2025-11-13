#!/usr/bin/env python3
"""
Aggregate anonymized VectorScan metrics across JSON outputs.

Inputs (auto-detected if not provided):
- vectorscan-*.json in current working directory
- tools/vectorscan/captures/*.json (lead capture payloads)

Usage:
  python3 tools/vectorscan/aggregate_metrics.py [--glob "vectorscan-*.json"] [--out metrics.json]

Output:
- Prints a summary table to stdout
- Optionally writes JSON with --out
"""
from __future__ import annotations
import argparse, glob, json, sys
from pathlib import Path
from typing import Any, Dict, List

DEFAULT_GLOBS = [
    "vectorscan-*.json",
    str(Path("tools")/"vectorscan"/"captures"/"*.json"),
]


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def extract_result(obj: Any) -> Dict[str, Any] | None:
    # If this is a lead payload, the result is under 'result'
    if isinstance(obj, dict) and "result" in obj and isinstance(obj["result"], dict):
        return obj["result"]
    # Else assume it's already a VectorScan result
    if isinstance(obj, dict) and "status" in obj and "violations" in obj:
        return obj
    return None


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--glob", dest="globs", action="append", help="Glob pattern(s) for inputs")
    ap.add_argument("--out", dest="out", help="Write metrics JSON to this path")
    ns = ap.parse_args(argv or sys.argv[1:])

    globs = ns.globs or DEFAULT_GLOBS
    files: List[Path] = []
    for g in globs:
        for m in glob.glob(g):
            files.append(Path(m))

    total_runs = 0
    total_pass = 0
    total_fail = 0
    counts_by_policy: Dict[str, int] = {}

    for f in files:
        obj = load_json(f)
        res = extract_result(obj)
        if not res:
            continue
        total_runs += 1
        status = (res.get("status") or "").upper()
        if status == "PASS":
            total_pass += 1
        elif status == "FAIL":
            total_fail += 1
        for v in res.get("violations", []) or []:
            # Expect violation strings like "P-SEC-001: ..."; count by policy id prefix
            if isinstance(v, str) and len(v) >= 10 and v[0] == "P" and ":" in v:
                policy = v.split(":", 1)[0].strip()
                counts_by_policy[policy] = counts_by_policy.get(policy, 0) + 1

    # Print summary
    print("VectorScan Metrics Summary")
    print(f"Runs: {total_runs}")
    print(f"PASS: {total_pass}")
    print(f"FAIL: {total_fail}")
    print("Violations by Policy:")
    for k in sorted(counts_by_policy.keys()):
        print(f" - {k}: {counts_by_policy[k]}")

    if ns.out:
        outp = {
            "runs": total_runs,
            "pass": total_pass,
            "fail": total_fail,
            "violations_by_policy": counts_by_policy,
        }
        Path(ns.out).write_text(json.dumps(outp, indent=2), encoding="utf-8")
        print(f"\nWrote metrics JSON to {ns.out}")

    # Return non-zero if any failures to enable gating behavior if desired
    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
