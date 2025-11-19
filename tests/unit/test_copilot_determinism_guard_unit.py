"""Tests for the Copilot determinism guard helper."""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

import pytest

from tools.vectorscan import copilot_determinism_guard as guard

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path("tests/fixtures/tfplan_pass.json")


def test_verify_fixtures_reports_matches() -> None:
    results = guard.verify_fixtures([FIXTURE], base_path=REPO_ROOT)
    assert results
    assert results[0].matches
    assert len(results[0].hash_one) == 64


def test_verify_fixtures_detects_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    payloads: Iterator[str] = iter(["payload-one", "payload-two"])

    def fake_run_cli(_cli_path: Path, _fixture: Path) -> tuple[str, int]:
        try:
            payload = next(payloads)
        except StopIteration:  # pragma: no cover - safety
            payload = "payload"
        return (payload, 0)

    monkeypatch.setattr(guard, "_run_cli", fake_run_cli)
    results = guard.verify_fixtures([FIXTURE], base_path=REPO_ROOT)
    assert not results[0].matches
