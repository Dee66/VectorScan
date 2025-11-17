#!/usr/bin/env python3
"""Detect unexpected compliance score drift between VectorScan summary snapshots."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Tuple


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare two VectorScan telemetry summaries and detect compliance score drift beyond a threshold."
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        required=True,
        help="Path to the baseline summary JSON (typically previous release or weekly snapshot)",
    )
    parser.add_argument(
        "--current",
        type=Path,
        required=True,
        help="Path to the newly generated summary JSON",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=5.0,
        help="Maximum allowed delta (absolute) between baseline and current compliance score averages",
    )
    return parser.parse_args()


def load_summary(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Summary file not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Summary payload is not a JSON object: {path}")
    return data


def _coerce_float(value: Any) -> float:
    if value is None:
        raise ValueError("compliance score missing")
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(value)
    except (TypeError, ValueError) as exc:  # pragma: no cover - defensive
        raise ValueError(f"Unable to coerce compliance score to float: {value}") from exc


def extract_compliance_score(summary: Dict[str, Any]) -> float:
    score = summary.get("compliance_score")
    if isinstance(score, dict) and score.get("avg") is not None:
        return _coerce_float(score["avg"])
    last_entry = summary.get("last_entry")
    if isinstance(last_entry, dict) and last_entry.get("compliance_score") is not None:
        return _coerce_float(last_entry["compliance_score"])
    raise ValueError("Summary missing compliance_score data")


def evaluate_drift(baseline: Dict[str, Any], current: Dict[str, Any], threshold: float) -> Tuple[bool, float, float, float]:
    base_score = extract_compliance_score(baseline)
    curr_score = extract_compliance_score(current)
    delta = curr_score - base_score
    return abs(delta) <= threshold, delta, base_score, curr_score


def main() -> int:
    args = parse_args()
    baseline = load_summary(args.baseline)
    current = load_summary(args.current)
    ok, delta, base_score, curr_score = evaluate_drift(baseline, current, args.threshold)
    if ok:
        print(
            f"Compliance score drift OK: baseline={base_score:.2f}, current={curr_score:.2f}, "
            f"delta={delta:+.2f}, threshold={args.threshold:.2f}"
        )
        return 0
    print(
        f"Drift detected: baseline={base_score:.2f}, current={curr_score:.2f}, "
        f"delta={delta:+.2f} exceeds threshold={args.threshold:.2f}"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
