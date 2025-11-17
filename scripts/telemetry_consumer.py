#!/usr/bin/env python3
"""Consume VectorScan telemetry artifacts and push them into downstream systems."""
from __future__ import annotations

import argparse
import csv
import json
import socket
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

SEVERITY_LEVELS = ("critical", "high", "medium", "low")


try:
    from tools.vectorscan.secret_scrubber import scrub_structure
    from tools.vectorscan.env_flags import is_offline, is_statsd_disabled
except ModuleNotFoundError:  # pragma: no cover
    import sys

    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    from tools.vectorscan.secret_scrubber import scrub_structure
    from tools.vectorscan.env_flags import is_offline, is_statsd_disabled

def _schema_header_wrapper(target: str) -> Dict[str, str]:
    try:
        from tools.vectorscan.telemetry_schema import schema_header as _schema_header  # type: ignore

        return _schema_header(target)
    except (ModuleNotFoundError, ImportError):  # pragma: no cover - executed in tests
        import importlib
        import sys

        repo_root = Path(__file__).resolve().parents[1]
        if str(repo_root) not in sys.path:
            sys.path.insert(0, str(repo_root))
        module = importlib.import_module("tools.vectorscan.telemetry_schema")
        return module.schema_header(target)


def schema_header(target: str) -> Dict[str, str]:
    return _schema_header_wrapper(target)


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
    parser.add_argument(
        "--disable-statsd",
        action="store_true",
        help="When set, skip StatsD emission even if a host is configured",
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


def _normalize_stat_component(component: str) -> str:
    cleaned = []
    for ch in component:
        if ch.isalnum() or ch in {".", "_"}:
            cleaned.append(ch.lower())
        else:
            cleaned.append("_")
    normalized = "".join(cleaned).strip(".")
    while ".." in normalized:
        normalized = normalized.replace("..", ".")
    return normalized


def _stat_key(prefix: str, key: str) -> str:
    parts = [part for part in (_normalize_stat_component(prefix), _normalize_stat_component(key)) if part]
    return ".".join(parts)


def build_statsd_packets(summary: Dict[str, Any], metrics: Dict[str, Optional[float]], prefix: str) -> List[str]:
    packets: List[str] = []

    def add(metric_key: str, value: Optional[float], metric_type: str) -> None:
        if value is None:
            return
        packets.append(f"{_stat_key(prefix, metric_key)}:{value}|{metric_type}")

    for key in sorted(metrics):
        add(key, metrics[key], "g")

    scan_duration_block = summary.get("scan_duration_ms")
    if isinstance(scan_duration_block, dict):
        add("scan_duration_ms.avg", scan_duration_block.get("avg"), "ms")
        add("scan_duration_ms.p95", scan_duration_block.get("p95"), "ms")
        add("scan_duration_ms.max", scan_duration_block.get("max"), "ms")
    elif isinstance(scan_duration_block, (int, float)):
        add("scan_duration_ms.latest", float(scan_duration_block), "ms")

    last_entry = summary.get("last_entry")
    if isinstance(last_entry, dict):
        latest_duration = last_entry.get("scan_duration_ms")
        if isinstance(latest_duration, (int, float)):
            add("scan_duration_ms.latest", float(latest_duration), "ms")

    add("entries", summary.get("entries"), "g")

    status_counts = summary.get("status_counts") or {}
    add("status.pass", status_counts.get("PASS"), "c")
    add("status.fail", status_counts.get("FAIL"), "c")

    severity_totals = summary.get("violation_severity_totals") or {}
    for level in SEVERITY_LEVELS:
        value = severity_totals.get(level)
        add(f"violations.{level}_total", value, "g")
        add(f"violations.{level}_sample", value, "h")

    add("policy_error_events", summary.get("policy_error_events"), "c")
    latest_errors = summary.get("policy_errors_latest")
    if isinstance(latest_errors, list):
        add("policy_errors_latest.count", len(latest_errors), "g")

    iam_risky_block = summary.get("iam_risky_actions")
    if isinstance(iam_risky_block, dict):
        add("iam_risky_actions.max", iam_risky_block.get("max"), "g")
        add("iam_risky_actions.p95", iam_risky_block.get("p95"), "g")

    iam_drift_block = summary.get("iam_drift_risky_change_count")
    if isinstance(iam_drift_block, dict):
        add("iam_drift_risky_change_count.max", iam_drift_block.get("max"), "g")

    open_sg_block = summary.get("open_sg_count")
    if isinstance(open_sg_block, dict):
        add("open_sg_count.max", open_sg_block.get("max"), "g")

    return packets


def _statsd_disable_reason(args: argparse.Namespace) -> Optional[str]:
    if getattr(args, "disable_statsd", False):
        return "--disable-statsd flag"
    if is_statsd_disabled():
        return "VSCAN_DISABLE_STATSD flag"
    return None

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
    default_header = schema_header("summary")
    summary.setdefault("telemetry_schema_version", default_header["schema_version"])
    summary.setdefault("telemetry_schema_kind", default_header["schema_kind"])
    header = [
        "generated_at",
        "entries",
        "pass_count",
        "fail_count",
        "compliance_score_avg",
        "network_exposure_score_avg",
        "drift_failure_rate",
        "scan_duration_ms_avg",
        "policy_version",
        "schema_version",
        "policy_pack_hash",
        "policy_error_events",
        "policy_errors_latest",
    ]
    severity_totals = summary.get("violation_severity_totals") or {}
    latest_errors = summary.get("policy_errors_latest") or []
    try:
        latest_errors_serialized = json.dumps(latest_errors, ensure_ascii=False)
    except TypeError:
        latest_errors_serialized = json.dumps([], ensure_ascii=False)
    entry = [
        summary.get("generated_at"),
        summary.get("entries"),
        summary.get("status_counts", {}).get("PASS", 0),
        summary.get("status_counts", {}).get("FAIL", 0),
        metrics.get("compliance_score_avg"),
        metrics.get("network_exposure_score_avg"),
        metrics.get("drift_failure_rate"),
        summary.get("scan_duration_ms", {}).get("avg") if isinstance(summary.get("scan_duration_ms"), dict) else None,
        summary.get("policy_version"),
        summary.get("schema_version"),
        summary.get("policy_pack_hash"),
        summary.get("policy_error_events"),
        latest_errors_serialized,
    ]
    for level in SEVERITY_LEVELS:
        header.append(f"{level}_violations_total")
        entry.append(severity_totals.get(level, 0))
    header += ["telemetry_schema_version", "telemetry_schema_kind"]
    entry += [summary.get("telemetry_schema_version"), summary.get("telemetry_schema_kind")]

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


def send_statsd(host: str, port: int, packets: Iterable[str]) -> None:
    packets = list(packets)
    if not packets:
        return
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for packet in packets:
            sock.sendto(packet.encode("utf-8"), (host, port))
    finally:
        sock.close()


def main() -> int:
    args = parse_args()
    if is_offline():
        print("Offline mode enabled; skipping telemetry consumer.")
        return 0
    try:
        summary = scrub_structure(load_summary(args.summary_file))
    except FileNotFoundError as exc:
        print(f"Warning: {exc}")
        return 0
    metrics = _extract_metrics(summary)
    default_header = schema_header("summary")
    summary.setdefault("telemetry_schema_version", default_header["schema_version"])
    summary.setdefault("telemetry_schema_kind", default_header["schema_kind"])
    write_csv(args.csv, summary, metrics, mode=args.mode)
    print(f"Telemetry consumer wrote {args.csv}")
    if args.statsd_host:
        disable_reason = _statsd_disable_reason(args)
        if disable_reason:
            print(f"StatsD disabled ({disable_reason}); skipping emission despite configured host.")
        else:
            packets = build_statsd_packets(summary, metrics, args.statsd_prefix)
            if not packets:
                print("StatsD had no metrics to emit; skipping.")
            else:
                try:
                    send_statsd(args.statsd_host, args.statsd_port, packets)
                except OSError as exc:
                    print(
                        f"Warning: StatsD endpoint {args.statsd_host}:{args.statsd_port} unreachable; "
                        f"metrics not sent ({exc})"
                    )
                else:
                    print(f"Telemetry consumer sent metrics to {args.statsd_host}:{args.statsd_port}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
