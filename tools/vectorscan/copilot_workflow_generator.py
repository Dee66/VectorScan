"""Generate the Copilot regression GitHub Actions workflow."""

from __future__ import annotations

import argparse
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import List, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOW_PATH = Path(".github/workflows/copilot-regression.yml")

_WORKFLOW_TEMPLATE = textwrap.dedent(
    """
    name: Copilot Regression

    on:
      push:
        branches: [main]
      workflow_dispatch:

    permissions:
      contents: read

    jobs:
      copilot-regression:
        runs-on: ubuntu-latest
        timeout-minutes: 20
        steps:
          - name: Checkout repository
            uses: actions/checkout@v4

          - name: Set up Python
            uses: actions/setup-python@v5
            with:
              python-version: "3.11"

          - name: Install dependencies
            run: |
              python -m pip install --upgrade pip
              python -m pip install -r requirements-dev.txt

          - name: Copilot scaffolding audit
            run: |
              python tools/vectorscan/copilot_scaffolder.py --dry-run
              python tools/vectorscan/copilot_suite_generator.py --check
              python tools/vectorscan/copilot_api_stubber.py --check
              python tools/vectorscan/copilot_determinism_guard.py --fixtures tests/fixtures/tfplan_pass.json tests/fixtures/tfplan_fail.json

          - name: Static checks
            run: bash scripts/run_static_checks.sh

          - name: Copilot smoke tests
            run: python -m pytest tests/copilot_generated/test_cli_smoke.py
    """
)


@dataclass
class WorkflowReport:
    created: List[Path]
    updated: List[Path]
    missing: List[Path]


def ensure_workflow(base_path: Path, apply_changes: bool = True) -> WorkflowReport:
    target = base_path / _WORKFLOW_PATH
    created: List[Path] = []
    updated: List[Path] = []
    missing: List[Path] = []

    if not target.exists():
        if apply_changes:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(_WORKFLOW_TEMPLATE, encoding="utf-8")
            created.append(target)
        else:
            missing.append(target)
        return WorkflowReport(created, updated, missing)

    current = target.read_text(encoding="utf-8")
    if current == _WORKFLOW_TEMPLATE:
        return WorkflowReport(created, updated, missing)

    if apply_changes:
        target.write_text(_WORKFLOW_TEMPLATE, encoding="utf-8")
        updated.append(target)
    else:
        missing.append(target)
    return WorkflowReport(created, updated, missing)


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ensure Copilot workflow exists.")
    parser.add_argument(
        "--base-path",
        type=Path,
        default=_REPO_ROOT,
        help="Repository root. Defaults to project root detected from this file.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify workflow without writing.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    report = ensure_workflow(args.base_path.resolve(), apply_changes=not args.check)
    if args.check:
        if report.missing:
            print("Copilot workflow missing or drifted:")
            for path in report.missing:
                print(f" - {path.relative_to(args.base_path)}")
            return 1
        print("Copilot workflow is up to date.")
        return 0

    if not report.created and not report.updated:
        print("Copilot workflow already satisfied.")
        return 0

    if report.created:
        print("Created workflow:")
        for path in report.created:
            print(f" - {path.relative_to(args.base_path)}")
    if report.updated:
        print("Updated workflow:")
        for path in report.updated:
            print(f" - {path.relative_to(args.base_path)}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
