import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

os.environ.setdefault("VSCAN_ALLOW_NETWORK", "1")

from tests.helpers.plan_helpers import set_deterministic_clock, write_plan  # noqa: E402
from tools.vectorscan import lead_capture as lead_mod  # noqa: E402
from tools.vectorscan import vectorscan as vs  # noqa: E402


def _basic_plan():
    return {"planned_values": {"root_module": {"resources": []}}}


def test_local_capture_writes_file_with_timestamp(monkeypatch, tmp_path, capsys):
    plan_path = write_plan(tmp_path, _basic_plan())
    set_deterministic_clock(monkeypatch)
    monkeypatch.setenv("VSCAN_OFFLINE", "0")
    monkeypatch.setenv("VSCAN_ALLOW_NETWORK", "1")
    monkeypatch.delenv("VSCAN_LEAD_ENDPOINT", raising=False)

    created = {}

    def spy_local(payload):
        path = lead_mod.write_local_capture(payload)
        created["payload"] = payload
        created["path"] = path
        return path

    def fail_remote(*_args, **_kwargs):  # pragma: no cover - ensures no remote call
        raise AssertionError("Remote capture should not trigger without endpoint")

    monkeypatch.setattr(vs, "_write_local_capture", spy_local)
    monkeypatch.setattr(vs, "_maybe_post", fail_remote)

    capsys.readouterr()
    code = vs.main([str(plan_path), "--email", "unit@example.com"])
    captured = capsys.readouterr()

    assert code == 0, captured.err
    path = created["path"]
    local_path = Path(path)
    directory = local_path.parent
    assert directory.exists()
    assert directory.name in {"captures", "vectorscan-captures"}
    # Symbolic links on some platforms keep parents under .tmp directories. Resolve for safety.
    resolved_parent = directory.resolve()
    assert resolved_parent.name in {"captures", "vectorscan-captures"}

    assert local_path.exists()

    data = json.loads(local_path.read_text())
    assert data["email"] == "unit@example.com"
    assert data["result"]["status"] == "PASS"
    assert isinstance(data["timestamp"], int)
    assert data["source"] == "vectorscan-cli"
    path.unlink()


def test_remote_capture_posts_payload_when_endpoint_set(monkeypatch, tmp_path):
    plan_path = write_plan(tmp_path, _basic_plan())
    set_deterministic_clock(monkeypatch)

    local_paths = []

    def fake_local(payload):
        target = tmp_path / "lead-local.json"
        target.write_text(json.dumps(payload))
        local_paths.append(target)
        return target

    recorded = {}

    def fake_remote(endpoint, payload):
        recorded["endpoint"] = endpoint
        recorded["payload"] = payload
        return True, "HTTP 201"

    monkeypatch.setattr(vs, "_write_local_capture", fake_local)
    monkeypatch.setattr(vs, "_maybe_post", fake_remote)
    monkeypatch.setenv("VSCAN_OFFLINE", "0")
    monkeypatch.setenv("VSCAN_ALLOW_NETWORK", "1")
    monkeypatch.setenv("VSCAN_LEAD_ENDPOINT", "https://example.com/capture")

    code = vs.main([str(plan_path), "--email", "remote@example.com"])

    assert code == 0
    assert recorded["endpoint"] == "https://example.com/capture"
    payload = recorded["payload"]
    assert payload["email"] == "remote@example.com"
    assert payload["result"]["status"] == "PASS"
    assert isinstance(payload["timestamp"], int)
    assert local_paths[0].exists()


def test_remote_capture_errors_are_graceful(monkeypatch, tmp_path, capsys):
    plan_path = write_plan(tmp_path, _basic_plan())
    set_deterministic_clock(monkeypatch)

    def fake_local(payload):
        target = tmp_path / "lead-error.json"
        target.write_text(json.dumps(payload))
        return target

    calls = {"count": 0}

    def failing_remote(_endpoint, _payload):
        calls["count"] += 1
        return False, "HTTP 500"

    monkeypatch.setattr(vs, "_write_local_capture", fake_local)
    monkeypatch.setattr(vs, "_maybe_post", failing_remote)
    monkeypatch.setenv("VSCAN_OFFLINE", "0")
    monkeypatch.setenv("VSCAN_ALLOW_NETWORK", "1")
    monkeypatch.setenv("VSCAN_LEAD_ENDPOINT", "https://example.com/capture")

    capsys.readouterr()
    code = vs.main([str(plan_path), "--email", "error@example.com"])
    captured = capsys.readouterr()

    assert code == 0, captured.err
    assert calls["count"] == 1
    assert "Lead POST" in captured.out or "Lead POST" in captured.err
