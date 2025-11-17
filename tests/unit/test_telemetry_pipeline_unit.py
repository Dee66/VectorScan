import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import List, Tuple, cast

import importlib.util
from importlib.machinery import ModuleSpec


def load_module_from_path(name: str, path: Path):
    spec_opt = importlib.util.spec_from_file_location(name, str(path))
    assert spec_opt is not None, "Failed to create spec for module"
    spec = cast(ModuleSpec, spec_opt)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    assert spec.loader is not None, "Spec has no loader"
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


class FakeSocket:
    def __init__(self):
        self.sent: List[Tuple[bytes, Tuple[str, int]]] = []
        self.closed = False

    def sendto(self, data: bytes, addr: Tuple[str, int]):
        self.sent.append((data, addr))

    def close(self):
        self.closed = True


class FakeSocketFactory:
    def __init__(self):
        self.instances: List[FakeSocket] = []

    def __call__(self, *args, **kwargs):
        sock = FakeSocket()
        self.instances.append(sock)
        return sock


def test_full_telemetry_pipeline_statsd_toggle(monkeypatch):
    repo_root = Path(__file__).resolve().parents[2]
    collect_path = repo_root / "scripts" / "collect_metrics.py"
    summary_path = repo_root / "scripts" / "metrics_summary.py"
    consumer_path = repo_root / "scripts" / "telemetry_consumer.py"

    collect_mod = load_module_from_path("collect_metrics", collect_path)
    summary_mod = load_module_from_path("metrics_summary", summary_path)
    consumer_mod = load_module_from_path("telemetry_consumer", consumer_path)

    payload = {
        "file": "examples/aws-pgvector-rag/tfplan-pass.json",
        "status": "PASS",
        "vectorscan_version": "0.9.0",
        "policy_version": "1.0.0",
        "schema_version": "1.2.0",
        "policy_pack_hash": "deadbeef",
        "violations": [],
        "violation_severity_summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "policy_errors": [
            {"policy": "P-SEC-001", "error": "RuntimeError: encryption blew up"},
        ],
        "metrics": {
            "compliance_score": 97.0,
            "network_exposure_score": 90.0,
            "open_sg_count": 0,
            "iam_risky_actions": 0,
            "scan_duration_ms": 123,
            "iam_drift": {"status": "PASS", "risky_change_count": 0},
        },
        "terraform_tests": {"status": "PASS", "source": "tests/tf-tests"},
    }

    secret_value = "super-secret-value"
    monkeypatch.setenv("VSCAN_API_TOKEN", secret_value)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        metrics_dir = tmp / "metrics"
        json_path = tmp / "vectorscan.json"
        json_path.write_text(json.dumps(payload), encoding="utf-8")

        summary_entry = collect_mod.build_summary(payload)
        log_file = collect_mod.write_summary(summary_entry, metrics_dir)
        assert log_file.exists()
        assert summary_entry["policy_errors"]

        entries = summary_mod.load_log_entries(log_file)
        assert len(entries) == 1
        summary_obj = summary_mod.build_summary(entries)
        summary_file = metrics_dir / "vector_scan_metrics_summary.json"
        summary_mod.persist_summary(summary_obj, summary_file)
        assert summary_file.exists()
        assert summary_obj.get("schema_version")
        assert summary_obj["policy_errors_latest"]
        assert summary_obj["policy_error_counts"].get("P-SEC-001") == 1
        assert summary_obj["policy_error_events"] == 1
        assert summary_obj["scan_duration_ms"]["avg"] >= 0
        assert summary_obj["last_entry"]["scan_duration_ms"] == 123
        assert summary_obj["violation_severity_totals"] == {"critical": 0, "high": 0, "medium": 0, "low": 0}
        assert summary_obj["violation_severity_last"] == {"critical": 0, "high": 0, "medium": 0, "low": 0}

        csv_path = metrics_dir / "vector_scan_metrics_summary.csv"

        factory = FakeSocketFactory()
        monkeypatch.setattr(consumer_mod.socket, "socket", lambda *args, **kwargs: factory())

        args_statsd = SimpleNamespace(
            summary_file=summary_file,
            csv=csv_path,
            mode="append",
            statsd_host="127.0.0.1",
            statsd_port=8125,
            statsd_prefix="vectorscan.telemetry",
            disable_statsd=False,
        )
        monkeypatch.setattr(consumer_mod, "parse_args", lambda: args_statsd)
        rc = consumer_mod.main()
        assert rc == 0

        lines = csv_path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2
        assert "schema_version" in lines[0]
        assert "policy_errors_latest" in lines[0]
        assert factory.instances and factory.instances[0].sent

        args_no_statsd = SimpleNamespace(
            summary_file=summary_file,
            csv=csv_path,
            mode="append",
            statsd_host=None,
            statsd_port=8125,
            statsd_prefix="vectorscan.telemetry",
            disable_statsd=False,
        )
        monkeypatch.setattr(consumer_mod, "parse_args", lambda: args_no_statsd)
        rc2 = consumer_mod.main()
        assert rc2 == 0

        lines2 = csv_path.read_text(encoding="utf-8").splitlines()
        assert len(lines2) == 2
        assert len(factory.instances) == 1  # No new sockets when statsd disabled

        log_content = log_file.read_text(encoding="utf-8")
        summary_content = summary_file.read_text(encoding="utf-8")
        csv_content = csv_path.read_text(encoding="utf-8")
        assert secret_value not in log_content
        assert secret_value not in summary_content
        assert secret_value not in csv_content
