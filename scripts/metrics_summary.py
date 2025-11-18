#!/usr/bin/env python3
"""Summarize VectorScan telemetry for Phase 5 monitoring."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from statistics import mean
from typing import Any, Dict, Iterable, List, Optional, Tuple

from tools.vectorscan.time_utils import deterministic_isoformat
from tools.vectorscan.telemetry_schema import schema_header
from tools.vectorscan.env_flags import is_offline

try:
    from tools.vectorscan.secret_scrubber import scrub_structure
except ModuleNotFoundError:  # pragma: no cover
    import sys

    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    from tools.vectorscan.secret_scrubber import scrub_structure


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


def _normalize_parser_mode(value: Any) -> str:
    if isinstance(value, str):
        token = value.strip().lower()
        if token:
            return token
    return "unknown"


def _parser_mode_counts(entries: List[Dict[str, Any]]) -> Tuple[Dict[str, int], str]:
    counts: Dict[str, int] = {}
    latest_mode = "unknown"
    for entry in entries:
        mode = _normalize_parser_mode(entry.get("parser_mode"))
        counts[mode] = counts.get(mode, 0) + 1
    if entries:
        latest_mode = _normalize_parser_mode(entries[-1].get("parser_mode"))
    return counts, latest_mode


def _aggregate_policy_errors(entries: List[Dict[str, Any]]) -> Tuple[Dict[str, int], int]:
    counts: Dict[str, int] = {}
    total = 0
    for entry in entries:
        for err in entry.get("policy_errors") or []:
            policy = (err.get("policy") or "unknown").strip() or "unknown"
            counts[policy] = counts.get(policy, 0) + 1
            total += 1
    return counts, total


SEVERITY_LEVELS = ("critical", "high", "medium", "low")


def _aggregate_severity(entries: List[Dict[str, Any]]) -> Tuple[Dict[str, int], Dict[str, int]]:
    totals: Dict[str, int] = {level: 0 for level in SEVERITY_LEVELS}
    last: Dict[str, int] = {level: 0 for level in SEVERITY_LEVELS}
    for entry in entries:
        summary = entry.get("violation_severity_summary") or {}
        for level in SEVERITY_LEVELS:
            value = summary.get(level, 0) or 0
            try:
                ivalue = int(value)
            except (TypeError, ValueError):
                ivalue = 0
            totals[level] += ivalue
        last = {level: int((summary.get(level, 0) or 0)) for level in SEVERITY_LEVELS}
    return totals, last


def build_summary(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not entries:
        summary = {
            "generated_at": deterministic_isoformat(),
            "entries": 0,
            "note": "No metrics entries collected yet.",
            "source_schema_versions": [],
            "source_policy_versions": [],
            "source_policy_pack_hashes": [],
            "policy_error_counts": {},
            "policy_error_events": 0,
            "policy_errors_latest": [],
            "violation_severity_totals": {level: 0 for level in SEVERITY_LEVELS},
            "violation_severity_last": {level: 0 for level in SEVERITY_LEVELS},
            "scan_duration_ms": summarize([]),
            "resource_count": summarize([]),
            "parser_mode_counts": {},
            "parser_mode_latest": None,
        }
        header = schema_header("summary")
        summary["telemetry_schema_version"] = header["schema_version"]
        summary["telemetry_schema_kind"] = header["schema_kind"]
        return summary
    compliance_scores = [safe_float(entry.get("compliance_score")) for entry in entries]
    network_scores = [safe_float(entry.get("network_exposure_score")) for entry in entries]
    open_sgs = [safe_float(entry.get("open_sg_count")) for entry in entries]
    iam_risky = [safe_float(entry.get("iam_risky_actions")) for entry in entries]
    drift_counts = [safe_float(entry.get("iam_drift_risky_change_count")) for entry in entries]
    scan_durations = [safe_float(entry.get("scan_duration_ms")) for entry in entries]
    resource_counts = [safe_float(entry.get("resource_count")) for entry in entries]
    policy_error_counts, total_policy_errors = _aggregate_policy_errors(entries)
    parser_mode_counts, parser_mode_latest = _parser_mode_counts(entries)

    last_entry = entries[-1]
    latest_policy_errors = last_entry.get("policy_errors") or []
    severity_totals, severity_last = _aggregate_severity(entries)
    summary = {
        "generated_at": deterministic_isoformat(),
        "entries": len(entries),
        "status_counts": status_counts(entries),
        "compliance_score": summarize(compliance_scores),
        "network_exposure_score": summarize(network_scores),
        "open_sg_count": summarize(open_sgs),
        "iam_risky_actions": summarize(iam_risky),
        "iam_drift_risky_change_count": summarize(drift_counts),
        "scan_duration_ms": summarize(scan_durations),
        "resource_count": summarize(resource_counts),
        "last_entry": {
            "timestamp": last_entry.get("timestamp"),
            "plan": last_entry.get("plan"),
            "status": last_entry.get("status"),
            "compliance_score": safe_float(last_entry.get("compliance_score")),
            "network_exposure_score": safe_float(last_entry.get("network_exposure_score")),
            "policy_version": last_entry.get("policy_version"),
            "schema_version": last_entry.get("schema_version"),
            "policy_pack_hash": last_entry.get("policy_pack_hash"),
            "policy_errors": latest_policy_errors,
            "policy_error_count": len(latest_policy_errors),
            "violation_severity_summary": severity_last,
            "scan_duration_ms": safe_float(last_entry.get("scan_duration_ms")),
            "resource_count": safe_float(last_entry.get("resource_count")),
            "parser_mode": parser_mode_latest,
        },
        "policy_error_counts": policy_error_counts,
        "policy_error_events": total_policy_errors,
        "policy_errors_latest": latest_policy_errors,
        "violation_severity_totals": severity_totals,
        "violation_severity_last": severity_last,
        "parser_mode_counts": parser_mode_counts,
        "parser_mode_latest": parser_mode_latest,
    }
    summary["policy_version"] = last_entry.get("policy_version")
    summary["schema_version"] = last_entry.get("schema_version")
    summary["policy_pack_hash"] = last_entry.get("policy_pack_hash")
    drift_failures = status_counts(entries).get("FAIL", 0)
    summary["drift_failure_rate"] = round(drift_failures / len(entries), 2)
    summary["source_schema_versions"] = sorted({entry.get("schema_version", "unknown") for entry in entries})
    summary["source_policy_versions"] = sorted({entry.get("policy_version", "unknown") for entry in entries})
    summary["source_policy_pack_hashes"] = sorted({entry.get("policy_pack_hash", "unknown") for entry in entries})
    header = schema_header("summary")
    summary["telemetry_schema_version"] = header["schema_version"]
    summary["telemetry_schema_kind"] = header["schema_kind"]
    return summary
def persist_summary(summary: Dict[str, Any], target: Path) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
        fh.write("\n")
    return target
def main() -> int:
    if is_offline():
        print("Offline mode enabled; skipping metrics summary generation.")
        return 0
    args = parse_args()
    entries = load_log_entries(args.log_file)
    summary = scrub_structure(build_summary(entries))
    if entries:
        target = persist_summary(summary, args.summary_file)
        print(f"Summary written to {target}")
    else:
        print("No entries found, skipping summary file creation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
