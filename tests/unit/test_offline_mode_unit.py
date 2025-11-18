import importlib.util
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace

from tools.vectorscan.env_flags import is_offline


def load_module_from_path(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, str(path))
    assert spec is not None, "Failed to create module spec"
    module = importlib.util.module_from_spec(spec)
    loader = spec.loader
    assert loader is not None, "Spec has no loader"
    loader.exec_module(module)
    return module


def test_is_offline_defaults_true(monkeypatch):
    monkeypatch.delenv("VSCAN_OFFLINE", raising=False)
    monkeypatch.delenv("VSCAN_ALLOW_NETWORK", raising=False)
    assert is_offline() is True


def test_is_offline_respects_overrides(monkeypatch):
    monkeypatch.delenv("VSCAN_OFFLINE", raising=False)
    monkeypatch.setenv("VSCAN_ALLOW_NETWORK", "1")
    assert is_offline() is False

    monkeypatch.setenv("VSCAN_ALLOW_NETWORK", "0")
    assert is_offline() is True

    monkeypatch.setenv("VSCAN_OFFLINE", "0")
    assert is_offline() is False

    monkeypatch.setenv("VSCAN_OFFLINE", "1")
    assert is_offline() is True

    monkeypatch.delenv("VSCAN_ALLOW_NETWORK", raising=False)
    monkeypatch.delenv("VSCAN_OFFLINE", raising=False)


def test_collect_metrics_skips_when_offline(tmp_path, monkeypatch):
    repo_root = Path(__file__).resolve().parents[2]
    collect_path = repo_root / "scripts" / "collect_metrics.py"
    collect_mod = load_module_from_path("collect_metrics", collect_path)

    payload = {
        "file": "examples/tfplan.json",
        "status": "PASS",
        "vectorscan_version": "0.1.0",
        "policy_version": "1.0.0",
        "schema_version": "1.0.0",
        "policy_pack_hash": "deadbeef",
        "violations": [],
        "violation_severity_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "policy_errors": [],
        "metrics": {
            "compliance_score": 100,
            "network_exposure_score": 100,
            "iam_risky_actions": 0,
            "scan_duration_ms": 1,
            "iam_drift": {"status": "PASS", "risky_change_count": 0},
        },
    }
    json_path = tmp_path / "vectorscan.json"
    json_path.write_text(json.dumps(payload), encoding="utf-8")

    args = SimpleNamespace(json_file=json_path, output_dir=tmp_path / "metrics")
    monkeypatch.setattr(collect_mod, "parse_args", lambda: args)
    monkeypatch.setenv("VSCAN_OFFLINE", "1")

    rc = collect_mod.main()
    assert rc == 0
    log_path = args.output_dir / getattr(collect_mod, "LOG_NAME", "vector_scan_metrics.log")
    assert not log_path.exists()
    monkeypatch.delenv("VSCAN_OFFLINE", raising=False)


def test_metrics_summary_skips_when_offline(tmp_path, monkeypatch):
    repo_root = Path(__file__).resolve().parents[2]
    summary_path = repo_root / "scripts" / "metrics_summary.py"
    summary_mod = load_module_from_path("metrics_summary", summary_path)

    log_file = tmp_path / "metrics" / "vector_scan_metrics.log"
    log_file.parent.mkdir(parents=True)
    log_file.write_text(json.dumps({"status": "PASS"}) + "\n", encoding="utf-8")

    args = SimpleNamespace(
        log_file=log_file,
        summary_file=tmp_path / "metrics" / "vector_scan_metrics_summary.json",
    )
    monkeypatch.setattr(summary_mod, "parse_args", lambda: args)
    monkeypatch.setenv("VSCAN_OFFLINE", "1")

    rc = summary_mod.main()
    assert rc == 0
    assert not args.summary_file.exists()
    monkeypatch.delenv("VSCAN_OFFLINE", raising=False)


def test_telemetry_consumer_skips_when_offline(tmp_path, monkeypatch):
    repo_root = Path(__file__).resolve().parents[2]
    consumer_path = repo_root / "scripts" / "telemetry_consumer.py"
    consumer_mod = load_module_from_path("telemetry_consumer", consumer_path)

    summary = {
        "generated_at": "2025-01-01T00:00:00Z",
        "entries": 1,
        "status_counts": {"PASS": 1, "FAIL": 0},
        "compliance_score": {"avg": 100},
        "network_exposure_score": {"avg": 100},
        "iam_risky_actions": {"avg": 0},
        "iam_drift_risky_change_count": {"avg": 0},
        "scan_duration_ms": {"avg": 1},
        "drift_failure_rate": 0,
        "policy_version": "1.0.0",
        "schema_version": "1.0.0",
        "policy_pack_hash": "deadbeef",
        "policy_error_events": 0,
        "policy_errors_latest": [],
        "violation_severity_totals": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "telemetry_schema_version": "1.0.0",
        "telemetry_schema_kind": "vectorscan.telemetry.summary",
    }
    summary_file = tmp_path / "metrics" / "vector_scan_metrics_summary.json"
    summary_file.parent.mkdir(parents=True)
    summary_file.write_text(json.dumps(summary), encoding="utf-8")

    args = SimpleNamespace(
        summary_file=summary_file,
        csv=tmp_path / "metrics" / "vector_scan_metrics_summary.csv",
        mode="append",
        statsd_host="127.0.0.1",
        statsd_port=8125,
        statsd_prefix="vectorscan.telemetry",
        disable_statsd=False,
    )
    monkeypatch.setattr(consumer_mod, "parse_args", lambda: args)
    monkeypatch.setenv("VSCAN_OFFLINE", "1")

    called = {"statsd": 0}

    def fail_statsd(host, port, prefix, metrics):
        called["statsd"] += 1
        raise AssertionError("StatsD should be disabled in offline mode")

    monkeypatch.setattr(consumer_mod, "send_statsd", fail_statsd)

    rc = consumer_mod.main()
    assert rc == 0
    assert not args.csv.exists()
    assert called["statsd"] == 0
    monkeypatch.delenv("VSCAN_OFFLINE", raising=False)
