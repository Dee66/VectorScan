"""Unit tests for the Copilot API stub generator."""
from __future__ import annotations

from pathlib import Path

from tools.vectorscan import copilot_api_stubber as stubber


def test_api_stub_generator_creates_expected_files(tmp_path: Path) -> None:
    report = stubber.ensure_stubs(tmp_path, apply_changes=True)

    assert report.created
    init_file = tmp_path / "tools/vectorscan/api_stubs/__init__.py"
    assert init_file.exists()
    assert "LeadCaptureClient" in init_file.read_text()

    rerun = stubber.ensure_stubs(tmp_path, apply_changes=True)
    assert not rerun.created
    assert not rerun.updated


def test_api_stub_generator_reports_missing_when_checking(tmp_path: Path) -> None:
    report = stubber.ensure_stubs(tmp_path, apply_changes=False)
    assert report.missing
    assert any("api_stubs" in str(path) for path in report.missing)
