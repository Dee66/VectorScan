import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

os.environ.setdefault("VSCAN_ALLOW_NETWORK", "1")

from tests.helpers.plan_helpers import enable_strict_mode, set_deterministic_clock, write_plan
from tools.vectorscan import vectorscan as vs
from tools.vectorscan.policies import get_policy


def _empty_plan():
    return {"planned_values": {"root_module": {"resources": []}}}


def test_strict_mode_requires_deterministic_clock(monkeypatch, tmp_path, capsys):
    plan_path = write_plan(tmp_path, _empty_plan())
    enable_strict_mode(monkeypatch)
    monkeypatch.setenv("VSCAN_OFFLINE", "1")
    for key in ("VSCAN_CLOCK_EPOCH", "VSCAN_CLOCK_ISO", "SOURCE_DATE_EPOCH"):
        monkeypatch.delenv(key, raising=False)

    capsys.readouterr()
    code = vs.main([str(plan_path), "--json"])
    captured = capsys.readouterr()

    assert code == vs.EXIT_CONFIG_ERROR
    assert "[Strict Mode]" in captured.err
    assert "deterministic clock overrides" in captured.err


def test_strict_mode_enforces_clean_policy_execution(monkeypatch, tmp_path, capsys):
    plan_path = write_plan(tmp_path, _empty_plan())
    enable_strict_mode(monkeypatch)
    set_deterministic_clock(monkeypatch)

    encryption_policy = get_policy("P-SEC-001")

    def explode(_resources):  # pragma: no cover - exercised via strict error path
        raise RuntimeError("test-triggered policy failure")

    monkeypatch.setattr(encryption_policy, "evaluate", explode)

    capsys.readouterr()
    code = vs.main([str(plan_path), "--json"])
    captured = capsys.readouterr()

    assert code == vs.EXIT_CONFIG_ERROR
    assert "Strict mode prohibits policy_errors" in captured.err


def test_strict_mode_clean_run_is_deterministic(monkeypatch, tmp_path, capsys):
    plan_path = write_plan(tmp_path, _empty_plan())
    enable_strict_mode(monkeypatch)
    set_deterministic_clock(monkeypatch)
    monkeypatch.setenv("VSCAN_FORCE_DURATION_MS", "7")

    capsys.readouterr()
    first_code = vs.main([str(plan_path), "--json"])
    first_capture = capsys.readouterr()

    second_code = vs.main([str(plan_path), "--json"])
    second_capture = capsys.readouterr()

    assert first_code == second_code == vs.EXIT_SUCCESS
    assert first_capture.out == second_capture.out

    payload = json.loads(first_capture.out)
    assert payload["policy_errors"] == []
    assert payload["environment"]["strict_mode"] is True
    assert payload["metrics"]["scan_duration_ms"] == 7
