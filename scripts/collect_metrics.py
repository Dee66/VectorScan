#!/usr/bin/env python3
"""Collect VectorScan telemetry from CLI JSON output and append it to a metrics log."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict

from tools.vectorscan.env_flags import is_offline
from tools.vectorscan.telemetry_schema import schema_header
from tools.vectorscan.time_utils import deterministic_isoformat

try:
    from tools.vectorscan.secret_scrubber import scrub_structure
except (
    ModuleNotFoundError
):  # pragma: no cover - happens when script run standalone outside repo root
    import sys

    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    from tools.vectorscan.secret_scrubber import scrub_structure

LOG_NAME = "vector_scan_metrics.log"


def build_summary(payload: Dict[str, Any]) -> Dict[str, Any]:
    metrics = payload.get("metrics") or {}
    iam_drift = metrics.get("iam_drift") or {}
    terraform = payload.get("terraform_tests") or {}

    policy_errors = payload.get("policy_errors") or []
    severity_summary = payload.get("violation_severity_summary") or {}

    summary: Dict[str, Any] = {
        "timestamp": deterministic_isoformat(),
        "plan": payload.get("file"),
        "status": payload.get("status"),
        "vectorscan_version": payload.get("vectorscan_version"),
        "policy_version": payload.get("policy_version"),
        "schema_version": payload.get("schema_version"),
        "policy_pack_hash": payload.get("policy_pack_hash"),
        "violations_count": len(payload.get("violations") or []),
        "policy_errors": policy_errors,
        "policy_error_count": len(policy_errors),
        "violation_severity_summary": severity_summary,
        "compliance_score": metrics.get("compliance_score"),
        "network_exposure_score": metrics.get("network_exposure_score"),
        "open_sg_count": metrics.get("open_sg_count"),
        "iam_risky_actions": metrics.get("iam_risky_actions"),
        "scan_duration_ms": metrics.get("scan_duration_ms"),
        "parser_mode": metrics.get("parser_mode"),
        "resource_count": metrics.get("resource_count"),
        "iam_drift_status": iam_drift.get("status"),
        "iam_drift_risky_change_count": iam_drift.get("risky_change_count"),
        "terraform_tests_status": terraform.get("status"),
        "terraform_tests_source": terraform.get("source"),
    }
    header = schema_header("log_entry")
    summary["telemetry_schema_version"] = header["schema_version"]
    summary["telemetry_schema_kind"] = header["schema_kind"]
    return summary


def write_summary(summary: Dict[str, Any], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / LOG_NAME
    with target.open("a", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False)
        fh.write("\n")
    return target


def load_payload(path: Path) -> Dict[str, Any]:
    content = path.read_text(encoding="utf-8").strip()
    if not content:
        raise ValueError(f"VectorScan output is empty: {path}")
    return json.loads(content)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect VectorScan metrics from JSON output.")
    parser.add_argument("json_file", type=Path, help="Path to the VectorScan JSON output file")
    parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        default=Path("metrics"),
        help="Directory that hosts the metrics log",
    )
    return parser.parse_args()


def main() -> int:
    if is_offline():
        print("Offline mode enabled; skipping telemetry collection.")
        return 0
    args = parse_args()
    try:
        payload = load_payload(args.json_file)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"Warning: could not parse VectorScan JSON: {exc}")
        return 0

    summary = scrub_structure(build_summary(payload))
    target = write_summary(summary, args.output_dir)
    print(f"Telemetry recorded to {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
