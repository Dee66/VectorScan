import json


def write_plan(tmp_path, payload):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(payload))
    return path


def set_deterministic_clock(monkeypatch):
    monkeypatch.setenv("VSCAN_CLOCK_EPOCH", "1700000000")
    monkeypatch.setenv("VSCAN_CLOCK_ISO", "2024-01-02T00:00:00Z")


def enable_strict_mode(monkeypatch):
    monkeypatch.setenv("VSCAN_STRICT", "1")
