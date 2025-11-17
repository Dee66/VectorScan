import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = _ROOT / "tools" / "vectorscan"
for path in (str(_ROOT), str(TOOLS_DIR)):
    if path not in sys.path:
        sys.path.insert(0, path)

from tools.vectorscan.time_utils import deterministic_isoformat

_PLAN_PASS = _ROOT / "examples" / "aws-pgvector-rag" / "tfplan-pass.json"
_ITERATIONS = 120


def _run_vectorscan_json(base_env: dict[str, str]) -> str:
    env = base_env.copy()
    existing = env.get("PYTHONPATH")
    inject = os.pathsep.join(p for p in (str(_ROOT), str(TOOLS_DIR)) if p)
    env["PYTHONPATH"] = f"{inject}{os.pathsep}{existing}" if existing else inject
    cmd = [sys.executable, "tools/vectorscan/vectorscan.py", str(_PLAN_PASS), "--json"]
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=_ROOT, env=env)
    assert result.returncode == 0, result.stderr
    return result.stdout


def _policy_status(violations: list[str], prefix: str) -> str:
    return "FAIL" if any(isinstance(v, str) and v.startswith(prefix) for v in violations) else "PASS"


def _build_audit_ledger(json_payload: str, environment: str) -> str:
    data = json.loads(json_payload)
    violations = data.get("violations") or []
    metrics = data.get("metrics") or {}
    drift = data.get("iam_drift_report") or {}

    encryption = _policy_status(violations, "P-SEC-001")
    tagging = _policy_status(violations, "P-FIN-001")
    network_score = int(metrics.get("network_exposure_score", 100) or 0)
    network = "PASS" if network_score == 100 else "FAIL"
    iam_risky = int(metrics.get("iam_risky_actions", 0) or 0)
    iam = "FAIL" if iam_risky > 0 else "PASS"
    iam_drift_status = (drift.get("status") or "PASS").upper()
    overall = int(metrics.get("compliance_score", 100) or 0)

    statuses = (encryption, iam, iam_drift_status, network, tagging)
    audit_status = "COMPLIANT" if all(s == "PASS" for s in statuses) else "NON_COMPLIANT"

    items = drift.get("items") or []
    evidence_lines: list[str] = []
    for item in items:
        rtype = item.get("resource_type", "")
        rname = item.get("resource_name", "")
        adds = item.get("risky_additions") or []
        evidence_lines.append(f"  - resource: {rtype}.{rname}")
        if adds:
            evidence_lines.append("    risky_additions:")
            for addition in adds:
                evidence_lines.append(f"      - {addition}")
        else:
            evidence_lines.append("    risky_additions: []")

    timestamp = deterministic_isoformat()
    header = [
        "VectorScan_Audit_Ledger:",
        f"  timestamp: {timestamp}",
        f"  environment: {environment}",
        f"  encryption: {encryption}",
        f"  iam: {iam}",
        f"  iam_drift: {iam_drift_status}",
        f"  network: {network}",
        f"  tagging: {tagging}",
        f"  audit_status: {audit_status}",
        f"  overall_score: {overall}/100",
        "  iam_drift_evidence:",
    ]
    body = header + (evidence_lines if evidence_lines else [])
    return "\n".join(body) + "\n"


def test_vectorscan_stress_runs_are_deterministic(monkeypatch):
    epoch = 1_700_000_123
    monkeypatch.setenv("VSCAN_CLOCK_EPOCH", str(epoch))
    monkeypatch.setenv("SOURCE_DATE_EPOCH", str(epoch))

    env = os.environ.copy()
    env["VSCAN_CLOCK_EPOCH"] = str(epoch)
    env["SOURCE_DATE_EPOCH"] = str(epoch)

    json_outputs = [_run_vectorscan_json(env) for _ in range(_ITERATIONS)]
    assert len(set(json_outputs)) == 1, "JSON output diverged across stress runs"

    ledgers = [_build_audit_ledger(payload, "stress-e2e") for payload in json_outputs]
    assert len(set(ledgers)) == 1, "Audit ledger YAML diverged across stress runs"
