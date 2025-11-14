#!/usr/bin/env python3
"""Consume VectorScan telemetry artifacts and push them into downstream systems."""
from __future__ import annotations

import argparse
import csv
import json
import socket
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Consume VectorScan telemetry summaries for dashboards or alerts.")
    parser.add_argument(
        "--summary-file",
        type=Path,
        default=Path("metrics/vector_scan_metrics_summary.json"),
        help="Path to the JSON summary produced by scripts/metrics_summary.py",
    )
    parser.add_argument(
        "--csv",
        type=Path,
        default=Path("metrics/vector_scan_metrics_summary.csv"),
        help="CSV target that downstream ETL tools can ingest",
    )
    parser.add_argument(
        "--mode",
        choices=["append", "overwrite"],
        default="append",
        help="Write mode for CSV: append (idempotent - skips duplicate by generated_at) or overwrite",
    )
    parser.add_argument(
        "--statsd-host",
        type=str,
        help="Optional StatsD/Datadog host to fire gauge metrics to",
    )
    parser.add_argument(
        "--statsd-port",
        type=int,
        default=8125,
        help="StatsD port when pushing to an aggregator",
    )
    parser.add_argument(
        "--statsd-prefix",
        type=str,
        default="vectorscan.telemetry",
        help="Prefix for each gauge sent to StatsD",
    )
    return parser.parse_args()


def load_summary(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Summary file not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _extract_metrics(summary: Dict[str, Any]) -> Dict[str, Optional[float]]:
    def avg_block(section: Dict[str, Any]) -> Optional[float]:
        return section.get("avg") if isinstance(section, dict) else None

    return {
        "compliance_score_avg": avg_block(summary.get("compliance_score", {})),
        "network_exposure_score_avg": avg_block(summary.get("network_exposure_score", {})),
        "open_sg_count_avg": avg_block(summary.get("open_sg_count", {})),
        "iam_risky_actions_avg": avg_block(summary.get("iam_risky_actions", {})),
        "iam_drift_risky_change_count_avg": avg_block(summary.get("iam_drift_risky_change_count", {})),
        "drift_failure_rate": summary.get("drift_failure_rate"),
    }

def _last_generated_at_from_csv(target: Path) -> Optional[str]:
    """Return the last data row's generated_at from an existing CSV, or None if not available."""
    if not target.exists():
        return None
    try:
        with target.open("r", encoding="utf-8", newline="") as fh:
            reader = csv.reader(fh)
            rows = list(reader)
            if len(rows) <= 1:
                return None
            # Find the last non-empty row with at least one column
            for row in reversed(rows):
                if row and row[0] != "generated_at":
                    return row[0]
            return None
    except Exception:
        # Fail-open: if CSV cannot be parsed, behave as if no previous row exists
        return None


def write_csv(target: Path, summary: Dict[str, Any], metrics: Dict[str, Optional[float]], mode: str = "append") -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    header = [
        "generated_at",
        "entries",
        "pass_count",
        "fail_count",
        "compliance_score_avg",
        "network_exposure_score_avg",
        "drift_failure_rate",
    ]
    entry = [
        summary.get("generated_at"),
        summary.get("entries"),
        summary.get("status_counts", {}).get("PASS", 0),
        summary.get("status_counts", {}).get("FAIL", 0),
        metrics.get("compliance_score_avg"),
        metrics.get("network_exposure_score_avg"),
        metrics.get("drift_failure_rate"),
    ]

    if mode == "overwrite":
        with target.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(header)
            writer.writerow(entry)
        return

    # Default: append mode, but idempotent (skip duplicate by generated_at)
    last_gen = _last_generated_at_from_csv(target)
    if last_gen is not None and str(last_gen) == str(summary.get("generated_at")):
        # No-op if same snapshot already recorded
        return

    exists = target.exists()
    with target.open("a", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        if not exists:
            writer.writerow(header)
        writer.writerow(entry)


def send_statsd(host: str, port: int, prefix: str, metrics: Dict[str, Optional[float]]) -> None:
    if not metrics:
        return
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for key, value in metrics.items():
        if value is None:
            continue
        stat = f"{prefix}.{key}:{value}|g"
        sock.sendto(stat.encode("utf-8"), (host, port))
    sock.close()


def main() -> int:
    args = parse_args()
    try:
        summary = load_summary(args.summary_file)
    except FileNotFoundError as exc:
        print(f"Warning: {exc}")
        return 0
    metrics = _extract_metrics(summary)
    write_csv(args.csv, summary, metrics, mode=args.mode)
    print(f"Telemetry consumer wrote {args.csv}")
    if args.statsd_host:
        send_statsd(args.statsd_host, args.statsd_port, args.statsd_prefix, metrics)
        print(f"Telemetry consumer sent metrics to {args.statsd_host}:{args.statsd_port}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
