"""Unit tests for the Copilot workflow generator."""
from __future__ import annotations

from pathlib import Path

import pytest

from tools.vectorscan import copilot_workflow_generator as workflow


@pytest.fixture
def temp_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    return repo


def read_workflow(repo: Path) -> str:
    return (repo / ".github/workflows/copilot-regression.yml").read_text(encoding="utf-8")


def test_creates_workflow_when_missing(temp_repo: Path) -> None:
    report = workflow.ensure_workflow(temp_repo)

    assert report.created == [temp_repo / ".github/workflows/copilot-regression.yml"]
    assert not report.updated
    assert not report.missing
    assert read_workflow(temp_repo) == workflow._WORKFLOW_TEMPLATE


def test_detects_drift_in_check_mode(temp_repo: Path) -> None:
    workflow.ensure_workflow(temp_repo)

    target = temp_repo / ".github/workflows/copilot-regression.yml"
    target.write_text("drift", encoding="utf-8")

    report = workflow.ensure_workflow(temp_repo, apply_changes=False)

    assert report.missing == [target]
    assert not report.created
    assert not report.updated


def test_noop_when_workflow_current(temp_repo: Path) -> None:
    workflow.ensure_workflow(temp_repo)

    report = workflow.ensure_workflow(temp_repo)

    assert not report.created
    assert not report.updated
    assert not report.missing
