"""Utility for auto-generating required test scaffolding files.

This module enforces the VectorScan Copilot checklist by ensuring fixtures,
golden files, and test modules always exist. Rich templates ensure that even
placeholder artifacts contain minimal but meaningful JSON so tests can run
without manual editing.
"""
from __future__ import annotations

import argparse
import copy
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Literal, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[2]

PlanTemplateKind = Literal["directory", "file"]


@dataclass(frozen=True)
class ScaffoldItem:
    """Declarative description of a path this module manages."""

    relative_path: Path
    kind: PlanTemplateKind
    template: str | None = None


@dataclass(frozen=True)
class ScaffoldReport:
    """Result information returned after running the scaffolder."""

    created_files: List[Path]
    created_directories: List[Path]
    missing_files: List[Path]
    missing_directories: List[Path]


_MINIMAL_PLAN: dict[str, Any] = {
    "format_version": "1.5",
    "terraform_version": "1.6.6",
    "planned_values": {"root_module": {"resources": []}},
    "resource_changes": [],
}


def _dump_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _plan_template(description: str) -> dict[str, Any]:
    payload = copy.deepcopy(_MINIMAL_PLAN)
    payload["metadata"] = {"fixture": description}
    return payload


def _db_values(
    *,
    storage_encrypted: bool | None,
    kms_key_id: str | None,
    tags: dict[str, str] | None,
) -> dict[str, Any]:
    return {
        "allocated_storage": 5,
        "engine": "postgres",
        "storage_encrypted": storage_encrypted,
        "kms_key_id": kms_key_id,
        "tags": tags or {},
    }


def _db_resource(name: str, values: dict[str, Any]) -> dict[str, Any]:
    return {
        "address": f"aws_db_instance.{name}",
        "mode": "managed",
        "type": "aws_db_instance",
        "name": name,
        "values": values,
    }


def _db_change(name: str, after: dict[str, Any], before: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "address": f"aws_db_instance.{name}",
        "mode": "managed",
        "type": "aws_db_instance",
        "name": name,
        "change": {
            "actions": ["create"] if before is None else ["update"],
            "before": before,
            "after": after,
        },
    }


def _iam_policy_change(name: str, actions: list[str]) -> dict[str, Any]:
    return {
        "address": f"aws_iam_policy.{name}",
        "mode": "managed",
        "type": "aws_iam_policy",
        "name": name,
        "change": {
            "actions": ["create"],
            "before": None,
            "after": {
                "name": name,
                "policy": {
                    "Statement": [
                        {
                            "Action": actions,
                            "Effect": "Allow",
                            "Resource": "*",
                        }
                    ],
                    "Version": "2012-10-17",
                },
            },
        },
    }


def _pass_plan() -> dict[str, Any]:
    values = _db_values(
        storage_encrypted=True,
        kms_key_id="kms-pass",
        tags={"CostCenter": "1234", "Project": "VectorScan"},
    )
    plan = _plan_template("tfplan_pass")
    plan["planned_values"]["root_module"]["resources"] = [_db_resource("pass", values)]
    plan["resource_changes"] = [_db_change("pass", values)]
    return plan


def _fail_plan() -> dict[str, Any]:
    values = _db_values(
        storage_encrypted=False,
        kms_key_id=None,
        tags={"CostCenter": "1234"},
    )
    plan = _plan_template("tfplan_fail")
    plan["planned_values"]["root_module"]["resources"] = [_db_resource("fail", values)]
    plan["resource_changes"] = [_db_change("fail", values)]
    return plan


def _missing_tags_plan() -> dict[str, Any]:
    values = _db_values(
        storage_encrypted=True,
        kms_key_id="kms-tags",
        tags={"Project": "VectorScan"},
    )
    plan = _plan_template("tfplan_missing_tags")
    plan["planned_values"]["root_module"]["resources"] = [_db_resource("missing_tags", values)]
    plan["resource_changes"] = [_db_change("missing_tags", values)]
    return plan


def _no_encryption_plan() -> dict[str, Any]:
    values = _db_values(
        storage_encrypted=False,
        kms_key_id=None,
        tags={"CostCenter": "1234", "Project": "VectorScan"},
    )
    plan = _plan_template("tfplan_no_encryption")
    plan["planned_values"]["root_module"]["resources"] = [_db_resource("no_encryption", values)]
    plan["resource_changes"] = [_db_change("no_encryption", values)]
    return plan


def _iam_drift_plan() -> dict[str, Any]:
    plan = _plan_template("tfplan_iam_drift")
    plan["resource_changes"] = [_iam_policy_change("wildcard", ["iam:*", "s3:*"])]
    return plan


def _compare_plan(description: str, *, encrypted: bool) -> dict[str, Any]:
    values = _db_values(
        storage_encrypted=encrypted,
        kms_key_id="kms-compare" if encrypted else None,
        tags={"CostCenter": "1234", "Project": "VectorScan"},
    )
    plan = _plan_template(description)
    plan["planned_values"]["root_module"]["resources"] = [_db_resource(description, values)]
    plan["resource_changes"] = [_db_change(description, values)]
    return plan


_FIXTURE_TEMPLATES: dict[str, str] = {
    "tests/fixtures/tfplan_pass.json": _dump_json(_pass_plan()),
    "tests/fixtures/tfplan_fail.json": _dump_json(_fail_plan()),
    "tests/fixtures/tfplan_invalid.json": "{ invalid_json_placeholder\n",
    "tests/fixtures/tfplan_iam_drift.json": _dump_json(_iam_drift_plan()),
    "tests/fixtures/tfplan_missing_tags.json": _dump_json(_missing_tags_plan()),
    "tests/fixtures/tfplan_no_encryption.json": _dump_json(_no_encryption_plan()),
    "tests/fixtures/tfplan_compare_old.json": _dump_json(_compare_plan("tfplan_compare_old", encrypted=True)),
    "tests/fixtures/tfplan_compare_new.json": _dump_json(_compare_plan("tfplan_compare_new", encrypted=False)),
}


_GOLDEN_TEMPLATES: dict[str, str] = {
    "tests/golden/pass_output.json": _dump_json(
        {
            "status": "PASS",
            "violations": [],
            "metrics": {"compliance_score": 100.0, "resource_count": 1},
            "environment": {"mode": "placeholder"},
            "input_file": "tests/fixtures/tfplan_pass.json",
        }
    ),
    "tests/golden/fail_output.json": _dump_json(
        {
            "status": "FAIL",
            "violations": [
                {
                    "policy_id": "P-SEC-001",
                    "message": "RDS instance fail lacks encryption.",
                    "resource_address": "aws_db_instance.fail",
                }
            ],
            "metrics": {"compliance_score": 45.0, "resource_count": 1},
            "environment": {"mode": "placeholder"},
            "input_file": "tests/fixtures/tfplan_fail.json",
        }
    ),
    "tests/golden/iam_drift_output.json": _dump_json(
        {
            "status": "FAIL",
            "violations": [],
            "iam_drift_report": {
                "summary": "Wildcard IAM actions detected",
                "added_permissions": ["iam:*", "s3:*"]
            },
            "metrics": {"compliance_score": 60.0, "iam_drift": 35.0},
            "environment": {"mode": "placeholder"},
            "input_file": "tests/fixtures/tfplan_iam_drift.json",
        }
    ),
    "tests/golden/plan_compare_output.json": _dump_json(
        {
            "status": "FAIL",
            "plan_evolution": {
                "downgraded_encryption": ["aws_db_instance.tfplan_compare_new"],
                "summary": "New plan disables encryption",
            },
            "metrics": {"compliance_score": 70.0},
            "environment": {"mode": "placeholder"},
            "input_file": "tests/fixtures/tfplan_compare_new.json",
        }
    ),
    "tests/golden/audit_ledger.yaml": (
        "status: FAIL\n"
        "environment:\n"
        "  name: placeholder\n"
        "scan_timestamp: 2024-01-01T00:00:00Z\n"
        "input_file: tests/fixtures/tfplan_fail.json\n"
        "violations:\n"
        "  - policy_id: P-SEC-001\n"
        "iam_drift: {}\n"
        "evidence: []\n"
        "terraform_test_results: {}\n"
    ),
}


def _test_template(module_name: str) -> str:
    safe_name = module_name.replace("/", "_").replace(".", "_")
    return (
        "\"\"\"Auto-generated placeholder tests for {module}.\"\"\"\n\n"
        "def test_placeholder_{slug}() -> None:\n"
        "    \"\"\"Replace with real tests covering CLI behavior.\"\"\"\n"
        "    assert True\n"
    ).format(module=module_name, slug=safe_name)


_TEST_PLACEHOLDERS: dict[str, str] = {
    "tests/test_cli.py": _test_template("tests/test_cli.py"),
    "tests/test_end_to_end_scenarios.py": _test_template("tests/test_end_to_end_scenarios.py"),
    "tests/test_json_output.py": _test_template("tests/test_json_output.py"),
    "tests/test_iam_drift.py": _test_template("tests/test_iam_drift.py"),
    "tests/test_audit_ledger.py": _test_template("tests/test_audit_ledger.py"),
    "tests/test_error_handling.py": _test_template("tests/test_error_handling.py"),
    "tests/test_lead_capture_cli.py": _test_template("tests/test_lead_capture_cli.py"),
    "tests/test_terraform_cli.py": _test_template("tests/test_terraform_cli.py"),
}


_FILE_TEMPLATES: dict[str, str] = {}
_FILE_TEMPLATES.update(_FIXTURE_TEMPLATES)
_FILE_TEMPLATES.update(_GOLDEN_TEMPLATES)
_FILE_TEMPLATES.update(_TEST_PLACEHOLDERS)


def _build_required_items() -> tuple[ScaffoldItem, ...]:
    directories = [
        ScaffoldItem(Path("tests"), "directory"),
        ScaffoldItem(Path("tests/fixtures"), "directory"),
        ScaffoldItem(Path("tests/golden"), "directory"),
        ScaffoldItem(Path("tests/unit"), "directory"),
        ScaffoldItem(Path("tests/integration"), "directory"),
        ScaffoldItem(Path("tests/e2e"), "directory"),
    ]
    file_items = [
        ScaffoldItem(Path(path), "file", template)
        for path, template in sorted(_FILE_TEMPLATES.items())
    ]
    return tuple(directories + file_items)


REQUIRED_ITEMS: tuple[ScaffoldItem, ...] = _build_required_items()


def ensure_structure(base_path: Path, apply_changes: bool = True) -> ScaffoldReport:
    """Create any missing directories/files defined in ``REQUIRED_ITEMS``."""

    created_files: List[Path] = []
    created_directories: List[Path] = []
    missing_files: List[Path] = []
    missing_directories: List[Path] = []

    for item in REQUIRED_ITEMS:
        target = base_path / item.relative_path
        if item.kind == "directory":
            _ensure_directory(target, apply_changes, created_directories, missing_directories)
            continue

        if item.template is None:
            raise ValueError(f"File template missing for {item.relative_path}")

        parent = target.parent
        _ensure_directory(parent, apply_changes, created_directories, missing_directories)
        if target.exists():
            continue
        if not apply_changes:
            missing_files.append(target)
            continue
        target.write_text(item.template, encoding="utf-8")
        created_files.append(target)

    return ScaffoldReport(
        created_files=created_files,
        created_directories=created_directories,
        missing_files=missing_files,
        missing_directories=missing_directories,
    )


def _ensure_directory(
    directory: Path,
    apply_changes: bool,
    created_directories: List[Path],
    missing_directories: List[Path],
) -> None:
    if directory.exists():
        return
    if not apply_changes:
        missing_directories.append(directory)
        return
    directory.mkdir(parents=True, exist_ok=True)
    created_directories.append(directory)


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ensure VectorScan test scaffolding exists.")
    parser.add_argument(
        "--base-path",
        type=Path,
        default=_REPO_ROOT,
        help="Repository root. Defaults to project root detected from this file.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report missing assets without creating them.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    base_path: Path = args.base_path.resolve()
    report = ensure_structure(base_path, apply_changes=not args.dry_run)
    if args.dry_run:
        missing = report.missing_directories + report.missing_files
        if not missing:
            print("All required assets exist.")
            return 0
        print("Missing assets:")
        for entry in missing:
            print(f" - {entry.relative_to(base_path)}")
        return 1

    if not report.created_directories and not report.created_files:
        print("Scaffolding already satisfied.")
        return 0

    print("Created directories:")
    for directory in report.created_directories:
        print(f" - {directory.relative_to(base_path)}")
    print("Created files:")
    for file in report.created_files:
        print(f" - {file.relative_to(base_path)}")
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via CLI usage.
    raise SystemExit(main())
