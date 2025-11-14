#!/usr/bin/env python3
"""Summarize VectorScan telemetry for Phase 5 monitoring."""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any, Dict, Iterable, List, Optional


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Summarize VectorScan metrics log.")
    parser.add_argument(
        "--log-file",
        type=Path,
        default=Path("metrics/vector_scan_metrics.log"),
        help="Path to the metrics log produced by scripts/collect_metrics.py",
    )
    parser.add_argument(
        "--summary-file",
        type=Path,
        default=Path("metrics/vector_scan_metrics_summary.json"),
        help="Destination path for the summary JSON output",
    )
    return parser.parse_args()


def safe_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def summarize(values: Iterable[Optional[float]]) -> Dict[str, Optional[float]]:
    filtered = [v for v in values if v is not None]
    if not filtered:
        return {"count": 0, "min": None, "max": None, "avg": None}
    return {
        "count": len(filtered),
        "min": min(filtered),
        "max": max(filtered),
        "avg": round(mean(filtered), 2),
    }


def load_log_entries(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        print(f"Info: metrics log not found at {path}; skipping summary")
        return []
    entries: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def status_counts(entries: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for entry in entries:
        status = (entry.get("status") or "").upper()
        if not status:
            status = "UNKNOWN"
        counts[status] = counts.get(status, 0) + 1
    return counts


def build_summary(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not entries:
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "entries": 0,
            "note": "No metrics entries collected yet.",
        }
    compliance_scores = [safe_float(entry.get("compliance_score")) for entry in entries]
    network_scores = [safe_float(entry.get("network_exposure_score")) for entry in entries]
    open_sgs = [safe_float(entry.get("open_sg_count")) for entry in entries]
    iam_risky = [safe_float(entry.get("iam_risky_actions")) for entry in entries]
    drift_counts = [safe_float(entry.get("iam_drift_risky_change_count")) for entry in entries]

    last_entry = entries[-1]
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "entries": len(entries),
        "status_counts": status_counts(entries),
        "compliance_score": summarize(compliance_scores),
        "network_exposure_score": summarize(network_scores),
        "open_sg_count": summarize(open_sgs),
        "iam_risky_actions": summarize(iam_risky),
        "iam_drift_risky_change_count": summarize(drift_counts),
        "last_entry": {
            "timestamp": last_entry.get("timestamp"),
            "plan": last_entry.get("plan"),
            "status": last_entry.get("status"),
            "compliance_score": safe_float(last_entry.get("compliance_score")),
            "network_exposure_score": safe_float(last_entry.get("network_exposure_score")),
        },
    }
    drift_failures = status_counts(entries).get("FAIL", 0)
    summary["drift_failure_rate"] = round(drift_failures / len(entries), 2)
    return summary


def persist_summary(summary: Dict[str, Any], target: Path) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
        fh.write("\n")
    return target


def main() -> int:
    args = parse_args()
    entries = load_log_entries(args.log_file)
    summary = build_summary(entries)
    if entries:
        target = persist_summary(summary, args.summary_file)
        print(f"Summary written to {target}")
    else:
        print("No entries found, skipping summary file creation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
