from tools.vectorscan import time_utils


def test_deterministic_epoch_prefers_vscan(monkeypatch):
    monkeypatch.setenv("VSCAN_CLOCK_EPOCH", "1234")
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "5678")
    assert time_utils.deterministic_epoch() == 1234


def test_deterministic_epoch_fallback(monkeypatch):
    monkeypatch.delenv("VSCAN_CLOCK_EPOCH", raising=False)
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "5678")
    assert time_utils.deterministic_epoch() == 5678


def test_deterministic_iso_override(monkeypatch):
    monkeypatch.setenv("VSCAN_CLOCK_ISO", "2024-01-02T00:00:00Z")
    assert time_utils.deterministic_isoformat() == "2024-01-02T00:00:00Z"


def test_deterministic_iso_from_epoch(monkeypatch):
    monkeypatch.delenv("VSCAN_CLOCK_ISO", raising=False)
    monkeypatch.setenv("VSCAN_CLOCK_EPOCH", "1700000000")
    assert time_utils.deterministic_isoformat() == "2023-11-14T22:13:20Z"


def test_deterministic_timestamp_prefix(monkeypatch):
    monkeypatch.setenv("VSCAN_CLOCK_ISO", "2025-05-01T10:11:12Z")
    stamp = time_utils.deterministic_timestamp(prefix="vs-")
    assert stamp.startswith("vs-")
    assert "20250501" in stamp
