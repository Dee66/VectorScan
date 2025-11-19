"""Unit tests for the Copilot suite generator."""
from __future__ import annotations

from pathlib import Path

from tools.vectorscan import copilot_suite_generator as suite_generator


def test_suite_generator_creates_expected_file(tmp_path: Path) -> None:
    report = suite_generator.ensure_suites(tmp_path, apply_changes=True)

    assert report.created
    generated = tmp_path / "tests/copilot_generated/test_cli_smoke.py"
    assert generated.read_text() == suite_generator.CLI_SMOKE_TEMPLATE

    second = suite_generator.ensure_suites(tmp_path, apply_changes=True)
    assert not second.created
    assert not second.updated


def test_suite_generator_detects_drift(tmp_path: Path) -> None:
    suite_generator.ensure_suites(tmp_path, apply_changes=True)
    target = tmp_path / "tests/copilot_generated/test_cli_smoke.py"
    target.write_text("mutated", encoding="utf-8")

    report = suite_generator.ensure_suites(tmp_path, apply_changes=False)
    assert target in report.mismatched