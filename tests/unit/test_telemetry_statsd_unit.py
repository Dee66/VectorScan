import importlib.util
import json
import tempfile
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import List, Tuple


def load_module_from_path(name: str, path: Path) -> ModuleType:
    spec_opt = importlib.util.spec_from_file_location(name, str(path))
    assert spec_opt is not None, "Failed to create spec for module"
    spec = spec_opt
    module = importlib.util.module_from_spec(spec)
    loader = spec.loader
    assert loader is not None, "Spec has no loader"
    loader.exec_module(module)
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


def test_build_statsd_packets_includes_rich_metrics(monkeypatch):
    repo_root = Path(__file__).resolve().parents[2]
    mod_path = repo_root / "scripts" / "telemetry_consumer.py"
    tc = load_module_from_path("telemetry_consumer", mod_path)

    summary = {
        "entries": 5,
        "status_counts": {"PASS": 4, "FAIL": 1},
        "scan_duration_ms": {"avg": 120.0, "p95": 200.0, "max": 300.0},
        "last_entry": {"scan_duration_ms": 150.0},
        "violation_severity_totals": {"critical": 1, "high": 2, "medium": 0, "low": 0},
        "policy_error_events": 2,
        "policy_errors_latest": [{"policy": "P-SEC-001", "error": "boom"}],
        "iam_risky_actions": {"avg": 2.0, "max": 4.0, "p95": 3.5},
        "iam_drift_risky_change_count": {"avg": 0.2, "max": 1.0},
        "open_sg_count": {"avg": 0.0, "max": 1.0},
    }
    metrics = {
        "compliance_score_avg": 95.0,
        "network_exposure_score_avg": 80.0,
        "open_sg_count_avg": None,
        "iam_risky_actions_avg": 2.0,
        "iam_drift_risky_change_count_avg": None,
        "drift_failure_rate": 0.0,
    }

    packets = tc.build_statsd_packets(summary, metrics, "VectorScan.Telemetry")
    assert "vectorscan.telemetry.compliance_score_avg:95.0|g" in packets
    assert "vectorscan.telemetry.network_exposure_score_avg:80.0|g" in packets
    assert any(pkt.endswith("|ms") and "scan_duration_ms.avg" in pkt for pkt in packets)
    assert any(pkt.endswith("|c") and "status.pass" in pkt for pkt in packets)
    assert any(pkt.endswith("|h") and "violations.critical_sample" in pkt for pkt in packets)
    assert any(pkt.endswith("|g") and "policy_errors_latest.count" in pkt for pkt in packets)
    # Ensure None metrics skipped
    assert not any("open_sg_count_avg" in pkt for pkt in packets)

    factory = FakeSocketFactory()
    monkeypatch.setattr(tc.socket, "socket", lambda *args, **kwargs: factory())
    tc.send_statsd("127.0.0.1", 8125, packets)
    assert len(factory.instances) == 1
    sock = factory.instances[0]
    assert sock.closed is True
    payloads = [data.decode("utf-8") for data, _ in sock.sent]
    assert payloads == packets


def test_main_statsd_toggle_and_csv_idempotency(monkeypatch):
    repo_root = Path(__file__).resolve().parents[2]
    mod_path = repo_root / "scripts" / "telemetry_consumer.py"
    tc = load_module_from_path("telemetry_consumer", mod_path)

    monkeypatch.setenv("VSCAN_OFFLINE", "0")
    monkeypatch.setenv("VSCAN_ALLOW_NETWORK", "1")

    # Create a minimal summary file
    summary = {
        "generated_at": "2025-11-14T08:00:00+00:00",
        "entries": 3,
        "status_counts": {"PASS": 2, "FAIL": 1},
        "compliance_score": {"avg": 90.0},
        "network_exposure_score": {"avg": 70.0},
        "open_sg_count": {"avg": 0.0},
        "iam_risky_actions": {"avg": 1.0},
        "iam_drift_risky_change_count": {"avg": 0.0},
        "drift_failure_rate": 0.0,
    }

    factory = FakeSocketFactory()
    monkeypatch.setattr(tc.socket, "socket", lambda *args, **kwargs: factory())

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        summary_path = tmp / "summary.json"
        csv_path = tmp / "out.csv"
        summary_path.write_text(json.dumps(summary), encoding="utf-8")

        # Patch args: enable statsd
        args_statsd = SimpleNamespace(
            summary_file=summary_path,
            csv=csv_path,
            mode="append",
            statsd_host="127.0.0.1",
            statsd_port=8125,
            statsd_prefix="vectorscan.telemetry",
            disable_statsd=False,
        )
        monkeypatch.setattr(tc, "parse_args", lambda: args_statsd)
        rc = tc.main()
        assert rc == 0
        # CSV should have header + 1 data row
        lines = csv_path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2
        # StatsD should have sent some packets
        assert len(factory.instances) == 1
        assert len(factory.instances[0].sent) >= 1

        # Run main again with same generated_at; CSV should be idempotent (still 2 lines)
        rc2 = tc.main()
        assert rc2 == 0
        lines2 = csv_path.read_text(encoding="utf-8").splitlines()
        assert len(lines2) == 2
        sockets_before_disable = len(factory.instances)

        # Disable via CLI flag while host present
        args_disabled_flag = SimpleNamespace(
            summary_file=summary_path,
            csv=csv_path,
            mode="append",
            statsd_host="127.0.0.1",
            statsd_port=8125,
            statsd_prefix="vectorscan.telemetry",
            disable_statsd=True,
        )
        monkeypatch.setattr(tc, "parse_args", lambda: args_disabled_flag)
        rc_disabled = tc.main()
        assert rc_disabled == 0
        assert (
            len(factory.instances) == sockets_before_disable
        )  # no additional sockets when disabled flag set

        # Now run with statsd host unset (legacy behavior)
        args_no_statsd = SimpleNamespace(
            summary_file=summary_path,
            csv=csv_path,
            mode="append",
            statsd_host=None,
            statsd_port=8125,
            statsd_prefix="vectorscan.telemetry",
            disable_statsd=False,
        )
        monkeypatch.setattr(tc, "parse_args", lambda: args_no_statsd)
        rc3 = tc.main()
        assert rc3 == 0
        # Still idempotent: no extra CSV lines
        lines3 = csv_path.read_text(encoding="utf-8").splitlines()
        assert len(lines3) == 2


def test_main_warns_when_statsd_unreachable(monkeypatch, capsys):
    repo_root = Path(__file__).resolve().parents[2]
    mod_path = repo_root / "scripts" / "telemetry_consumer.py"
    tc = load_module_from_path("telemetry_consumer", mod_path)

    monkeypatch.setenv("VSCAN_OFFLINE", "0")
    monkeypatch.setenv("VSCAN_ALLOW_NETWORK", "1")

    summary = {
        "generated_at": "2025-11-14T08:00:00+00:00",
        "entries": 1,
        "status_counts": {"PASS": 1, "FAIL": 0},
        "compliance_score": {"avg": 95.0},
        "network_exposure_score": {"avg": 88.0},
        "open_sg_count": {"avg": 0.0},
        "iam_risky_actions": {"avg": 0.0},
        "iam_drift_risky_change_count": {"avg": 0.0},
        "drift_failure_rate": 0.0,
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        summary_path = tmp / "summary.json"
        csv_path = tmp / "out.csv"
        summary_path.write_text(json.dumps(summary), encoding="utf-8")

        args = SimpleNamespace(
            summary_file=summary_path,
            csv=csv_path,
            mode="append",
            statsd_host="statsd.invalid",
            statsd_port=8125,
            statsd_prefix="vectorscan.telemetry",
            disable_statsd=False,
        )
        monkeypatch.setattr(tc, "parse_args", lambda: args)

        def boom(*_args, **_kwargs):
            raise OSError("simulated network failure")

        monkeypatch.setattr(tc, "send_statsd", boom)

        rc = tc.main()
        assert rc == 0
        out = capsys.readouterr().out
        assert "Warning: StatsD endpoint statsd.invalid:8125 unreachable" in out
        assert "metrics not sent" in out


def test_statsd_disable_env_flag(monkeypatch, capsys):
    repo_root = Path(__file__).resolve().parents[2]
    mod_path = repo_root / "scripts" / "telemetry_consumer.py"
    tc = load_module_from_path("telemetry_consumer", mod_path)

    monkeypatch.setenv("VSCAN_OFFLINE", "0")
    monkeypatch.setenv("VSCAN_ALLOW_NETWORK", "1")

    summary = {
        "generated_at": "2025-11-14T08:00:00+00:00",
        "entries": 1,
        "status_counts": {"PASS": 1, "FAIL": 0},
        "compliance_score": {"avg": 95.0},
        "network_exposure_score": {"avg": 88.0},
        "open_sg_count": {"avg": 0.0},
        "iam_risky_actions": {"avg": 0.0},
        "iam_drift_risky_change_count": {"avg": 0.0},
        "drift_failure_rate": 0.0,
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        summary_path = tmp / "summary.json"
        csv_path = tmp / "out.csv"
        summary_path.write_text(json.dumps(summary), encoding="utf-8")

        args = SimpleNamespace(
            summary_file=summary_path,
            csv=csv_path,
            mode="append",
            statsd_host="127.0.0.1",
            statsd_port=8125,
            statsd_prefix="vectorscan.telemetry",
            disable_statsd=False,
        )
        monkeypatch.setattr(tc, "parse_args", lambda: args)

        called = {"count": 0}

        def fail_send(*_args, **_kwargs):
            called["count"] += 1
            raise AssertionError("statsd should be disabled")

        monkeypatch.setattr(tc, "send_statsd", fail_send)
        monkeypatch.setenv("VSCAN_DISABLE_STATSD", "1")

        rc = tc.main()
        assert rc == 0
        assert called["count"] == 0
        out = capsys.readouterr().out
        assert "StatsD disabled (VSCAN_DISABLE_STATSD flag)" in out

        monkeypatch.delenv("VSCAN_DISABLE_STATSD", raising=False)
