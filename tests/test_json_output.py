import json
import os
import subprocess
from pathlib import Path

from src.pillar import constants as pillar_constants
from src.pillar.evaluator import evaluate_scan
from tests import canonicalize_snapshot

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI = Path("tools") / "vectorscan" / "vectorscan.py"
FIX = Path("tests") / "fixtures"
GOLD = Path("tests") / "golden"

ENV = os.environ.copy()
env_pythonpath = ENV.get("PYTHONPATH")
env_segments = [str(REPO_ROOT)]
if env_pythonpath:
    env_segments.append(env_pythonpath)
ENV["PYTHONPATH"] = os.pathsep.join(env_segments)
ENV.pop("VSCAN_ALLOW_NETWORK", None)
ENV["VSCAN_ALLOW_NETWORK"] = "0"
ENV["VSCAN_OFFLINE"] = "0"
ENV["VSCAN_CLOCK_EPOCH"] = "1700000000"
ENV["VSCAN_CLOCK_ISO"] = "2024-01-02T00:00:00Z"
ENV["VSCAN_FORCE_DURATION_MS"] = "123"
ENV["VSCAN_FORCE_PLAN_PARSE_MS"] = "123"
ENV["VSCAN_ENV_PLATFORM"] = "linux"
ENV["VSCAN_ENV_PLATFORM_RELEASE"] = "unit-kernel"
ENV["VSCAN_ENV_PYTHON_VERSION"] = "3.11.test"
ENV["VSCAN_ENV_PYTHON_IMPL"] = "CPython"
ENV["VSCAN_ENV_TERRAFORM_VERSION"] = "not-run"
ENV["VSCAN_ENV_TERRAFORM_SOURCE"] = "not-run"


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _relativize(path_value: str) -> str:
    candidate = Path(path_value)
    if candidate.is_absolute():
        try:
            return str(candidate.resolve().relative_to(REPO_ROOT))
        except ValueError:
            return candidate.as_posix()
    return candidate.as_posix()


def _normalize(payload: dict) -> dict:
    clone = json.loads(json.dumps(payload))
    if "file" in clone:
        clone["file"] = _relativize(clone["file"])
    metrics = clone.get("metrics")
    if isinstance(metrics, dict):
        notes = metrics.get("notes")
        if isinstance(notes, dict):
            notes.pop("violation_count", None)
    if clone.get("mode") == "compare":
        clone.pop("remediation_ledger", None)
        clone.pop("issues", None)
    return clone


def run_json(plan: Path, *, extra_args: list[str] | None = None):
    plan = Path(plan)
    if plan.is_absolute():
        try:
            plan = plan.relative_to(REPO_ROOT)
        except ValueError:
            pass
    cmd = ["python3", str(CLI), plan.as_posix(), "--json"]
    if extra_args:
        cmd.extend(extra_args)
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=ENV,
        check=False,
    )


def run_compare(old_plan: Path, new_plan: Path):
    old_plan = Path(old_plan)
    new_plan = Path(new_plan)
    try:
        old_plan = old_plan.relative_to(REPO_ROOT)
    except ValueError:
        pass
    try:
        new_plan = new_plan.relative_to(REPO_ROOT)
    except ValueError:
        pass
    cmd = [
        "python3",
        str(CLI),
        "--json",
        "--compare",
        old_plan.as_posix(),
        new_plan.as_posix(),
    ]
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=ENV,
        check=False,
    )


def _assert_matches(
    plan_name: str,
    golden_name: str,
    expected_code: int,
    extra_args: list[str] | None = None,
) -> dict:
    res = run_json(FIX / plan_name, extra_args=extra_args)
    assert res.returncode == expected_code, res.stderr
    got = _normalize(json.loads(res.stdout))
    golden_path = GOLD / golden_name
    if golden_path.exists():
        exp = _normalize(_load(golden_path))
    else:
        exp = got
    assert canonicalize_snapshot(got) == canonicalize_snapshot(exp)
    return got


def _assert_matches_explain(plan_name: str, golden_name: str, expected_code: int) -> dict:
    res = run_json(FIX / plan_name, extra_args=["--explain"])
    assert res.returncode == expected_code, res.stderr
    got = _normalize(json.loads(res.stdout))
    golden_path = GOLD / golden_name
    if golden_path.exists():
        exp = _normalize(_load(golden_path))
    else:
        exp = got
    assert canonicalize_snapshot(got) == canonicalize_snapshot(exp)
    return got


def test_pass_matches_golden(snapshot_updater):
    payload = _assert_matches("tfplan_pass.json", "pass_output.json", expected_code=0)
    snapshot_updater.maybe_write(GOLD / "pass_output.json", canonicalize_snapshot(payload))


def test_fail_matches_golden(snapshot_updater):
    payload = _assert_matches("tfplan_fail.json", "fail_output.json", expected_code=3)
    snapshot_updater.maybe_write(GOLD / "fail_output.json", canonicalize_snapshot(payload))


def test_scan_version_in_payload():
    res = run_json(FIX / "tfplan_pass.json")
    assert res.returncode == 0, res.stderr
    payload = json.loads(res.stdout)
    assert payload.get("scan_version") == pillar_constants.SCAN_VERSION


def test_payload_includes_canonical_schema_fields():
    res = run_json(FIX / "tfplan_pass.json")
    assert res.returncode == 0, res.stderr
    payload = json.loads(res.stdout)

    assert payload.get("pillar") == pillar_constants.PILLAR_NAME
    assert payload.get("guardscore_rules_version") == pillar_constants.GUARDSCORE_RULES_VERSION
    assert payload.get("canonical_schema_version") == pillar_constants.CANONICAL_SCHEMA_VERSION
    assert payload.get("badge_eligible") is True
    assert isinstance(payload.get("quick_score_mode"), bool)
    assert isinstance(payload.get("latency_ms"), int)

    metadata = payload.get("metadata")
    assert isinstance(metadata, dict)
    assert metadata.get("environment") == payload.get("environment")
    assert metadata.get("plan") == payload.get("plan_metadata")

    severity_totals = payload.get("severity_totals")
    assert severity_totals == payload.get("violation_severity_summary")

    assert payload.get("schema_validation_error") is None


def test_canonical_issues_include_remediation_metadata():
    res = run_json(FIX / "tfplan_fail.json")
    assert res.returncode == 3, res.stderr
    payload = json.loads(res.stdout)

    issues = payload.get("issues")
    assert isinstance(issues, list) and issues, "Canonical issues must be present"

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    assert issues == sorted(
        issues,
        key=lambda item: (
            severity_rank.get(item.get("severity"), 99),
            item.get("id"),
        ),
    )

    for issue in issues:
        assert issue.get("remediation_hint") == ""
        assert issue.get("remediation_difficulty") in {"low", "medium", "high"}
        metadata = issue.get("remediation_metadata")
        assert isinstance(metadata, dict)
        assert metadata == {}
        attributes = issue.get("attributes")
        assert isinstance(attributes, dict)
        assert attributes.get("rule_id") == issue["id"]

    ledger = payload.get("remediation_ledger")
    assert isinstance(ledger, dict)
    assert ledger.get("remediation_summary") == ledger.get("per_severity")
    assert ledger.get("remediation_rule_index") == ledger.get("rule_ids")
    aggregate = ledger.get("remediation_metadata_aggregate")
    assert isinstance(aggregate, dict)
    for rule_id in ledger.get("remediation_rule_index", []):
        assert rule_id in aggregate
        assert aggregate[rule_id] == {}


def test_remediation_ledger_structure():
    res = run_json(FIX / "tfplan_fail.json")
    assert res.returncode == 3, res.stderr
    payload = json.loads(res.stdout)

    ledger = payload.get("remediation_ledger")
    assert isinstance(ledger, dict) and ledger, "Missing remediation ledger"

    per_severity = ledger.get("per_severity")
    assert isinstance(per_severity, dict)
    assert list(per_severity.keys()) == ["critical", "high", "medium", "low"]
    assert all(isinstance(per_severity[level], int) and per_severity[level] >= 0 for level in per_severity)

    rule_ids = ledger.get("rule_ids")
    assert isinstance(rule_ids, list)

    paths = ledger.get("paths")
    assert isinstance(paths, list) and len(paths) == len(rule_ids)
    assert [entry.get("id") for entry in paths] == rule_ids
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    observed_ranks = [severity_rank.get(entry.get("severity"), 99) for entry in paths]
    assert observed_ranks == sorted(observed_ranks), "Paths must be ordered by severity"
    for entry in paths:
        metadata = entry.get("remediation_metadata")
        assert isinstance(metadata, dict), "Expected remediation metadata dict"
        assert metadata == {}


def test_tfplan_no_encryption_enforces_p_sec_001():
    res = run_json(FIX / "tfplan_no_encryption.json")
    assert res.returncode == 3, res.stderr
    payload = json.loads(res.stdout)

    assert any("P-SEC-001" in item for item in payload["violations"])
    assert payload["metrics"]["compliance_score"] == 50

    encryption_structs = [
        entry for entry in payload["violations_struct"] if entry["policy_id"] == "P-SEC-001"
    ]
    assert encryption_structs, "Expected structured violation details for P-SEC-001"
    violation_entry = encryption_structs[0]
    assert "storage_encrypted != true" in violation_entry["message"]
    assert violation_entry["resource"] == "aws_rds_cluster.vector_db"
    assert violation_entry["resource_details"]["address"] == "aws_rds_cluster.vector_db"

    remediation = violation_entry.get("remediation") or {}
    assert remediation.get("summary", "").startswith("Enable encryption and configure kms_key_id")
    assert remediation.get("docs")
    assert remediation.get("hcl_examples")

    suspicious_defaults = payload.get("suspicious_defaults") or []
    assert any(
        entry.get("address") == "aws_rds_cluster.vector_db"
        and "storage_encrypted" in entry.get("reason", "")
        for entry in suspicious_defaults
    )


def test_tfplan_missing_tags_enforces_p_fin_001():
    res = run_json(FIX / "tfplan_missing_tags.json")
    assert res.returncode == 2, res.stderr
    payload = json.loads(res.stdout)

    assert payload["counts"]["violations"] == 2
    assert payload["metrics"]["compliance_score"] == 50

    messages = payload["violations"]
    assert any("CostCenter" in msg for msg in messages)
    assert any("Project" in msg for msg in messages)

    tagging_structs = [
        entry for entry in payload["violations_struct"] if entry["policy_id"] == "P-FIN-001"
    ]
    assert len(tagging_structs) == 2
    assert {entry["resource"] for entry in tagging_structs} == {"aws_rds_cluster.vector_db"}

    for entry in tagging_structs:
        details = entry.get("resource_details") or {}
        assert details.get("address") == "aws_rds_cluster.vector_db"
        remediation = entry.get("remediation") or {}
        assert remediation.get("summary", "").startswith("Populate CostCenter and Project tags")
        assert remediation.get("docs")
        assert remediation.get("hcl_examples")


def test_evaluation_reuses_payload_issue_list_reference():
    plan_payload = _load(FIX / "tfplan_fail.json")
    result = evaluate_scan(plan_payload)
    assert isinstance(result.evaluation, dict)
    assert result.evaluation.get("issues") is result.payload.get("issues")


def test_badge_eligibility_tracks_violations():
    res_pass = run_json(FIX / "tfplan_pass.json")
    assert res_pass.returncode == 0, res_pass.stderr
    payload_pass = json.loads(res_pass.stdout)

    res_fail = run_json(FIX / "tfplan_fail.json")
    assert res_fail.returncode == 3, res_fail.stderr
    payload_fail = json.loads(res_fail.stdout)

    assert payload_pass["badge_eligible"] is True
    assert payload_fail["badge_eligible"] is False


def test_iam_drift_matches_golden_and_penalty(snapshot_updater):
    got = _assert_matches("tfplan_iam_drift.json", "iam_drift_output.json", expected_code=0)
    assert got["iam_drift_report"]["status"] == "FAIL"
    assert got["iam_drift_report"]["counts"]["risky_changes"] == 1
    # Penalty applied to compliance_score (default 20) and captured in golden snapshot
    assert got["metrics"]["compliance_score"] == 80
    snapshot_updater.maybe_write(GOLD / "iam_drift_output.json", canonicalize_snapshot(got))


def test_explain_mode_snapshots(snapshot_updater):
    payload_pass = _assert_matches_explain("tfplan_pass.json", "pass_explain_output.json", expected_code=0)
    payload_fail = _assert_matches_explain("tfplan_fail.json", "fail_explain_output.json", expected_code=3)
    explain = _assert_matches_explain(
        "tfplan_iam_drift.json", "iam_drift_explain_output.json", expected_code=0
    )
    assert "explanation" in explain
    assert explain["explanation"]["iam_drift"]["status"] == "FAIL"
    snapshot_updater.maybe_write(GOLD / "pass_explain_output.json", canonicalize_snapshot(payload_pass))
    snapshot_updater.maybe_write(GOLD / "fail_explain_output.json", canonicalize_snapshot(payload_fail))
    snapshot_updater.maybe_write(GOLD / "iam_drift_explain_output.json", canonicalize_snapshot(explain))


def test_diff_mode_snapshots(snapshot_updater):
    diff_pass = _assert_matches(
        "tfplan_pass.json",
        "pass_diff_output.json",
        expected_code=0,
        extra_args=["--diff"],
    )
    assert "plan_diff" in diff_pass
    diff_fail = _assert_matches(
        "tfplan_fail.json",
        "fail_diff_output.json",
        expected_code=3,
        extra_args=["--diff"],
    )
    diff_iam = _assert_matches(
        "tfplan_iam_drift.json",
        "iam_drift_diff_output.json",
        expected_code=0,
        extra_args=["--diff"],
    )
    assert diff_iam["plan_diff"]["summary"]["adds"] >= 0
    snapshot_updater.maybe_write(GOLD / "pass_diff_output.json", canonicalize_snapshot(diff_pass))
    snapshot_updater.maybe_write(GOLD / "fail_diff_output.json", canonicalize_snapshot(diff_fail))
    snapshot_updater.maybe_write(GOLD / "iam_drift_diff_output.json", canonicalize_snapshot(diff_iam))


def test_resource_mode_snapshots(snapshot_updater):
    scoped = _assert_matches(
        "tfplan_fail.json",
        "fail_resource_output.json",
        expected_code=3,
        extra_args=["--resource", "aws_rds_cluster.vector_db"],
    )
    assert scoped["resource_filter"]["address"] == "aws_rds_cluster.vector_db"

    module_scope = _assert_matches(
        "tfplan_module_fail.json",
        "module_resource_output.json",
        expected_code=3,
        extra_args=["--resource", "aws_rds_cluster.vector_db"],
    )
    assert module_scope["resource_filter"]["match"] == "suffix"
    snapshot_updater.maybe_write(GOLD / "fail_resource_output.json", canonicalize_snapshot(scoped))
    snapshot_updater.maybe_write(GOLD / "module_resource_output.json", canonicalize_snapshot(module_scope))


def test_resource_scope_missing_errors():
    res = run_json(FIX / "tfplan_fail.json", extra_args=["--resource", "does_not_exist"])
    assert res.returncode == 2
    assert "not found" in res.stderr.lower()


def test_preview_mode_snapshot(snapshot_updater):
    preview = _assert_matches(
        "tfplan_fail.json",
        "fail_preview_output.json",
        expected_code=10,
        extra_args=["--preview-vectorguard"],
    )
    assert preview["preview_generated"] is True
    assert len(preview["preview_policies"]) >= 1
    snapshot_updater.maybe_write(GOLD / "fail_preview_output.json", canonicalize_snapshot(preview))


def test_compare_mode_snapshot(snapshot_updater):
    res = run_compare(
        FIX / "tfplan_compare_old.json",
        FIX / "tfplan_compare_new.json",
    )
    assert res.returncode == 0, res.stderr
    raw = json.loads(res.stdout)
    assert "remediation_ledger" in raw
    assert "issues" in raw
    got = _normalize(raw)
    golden_path = GOLD / "plan_compare_output.json"
    if golden_path.exists():
        exp = _normalize(_load(golden_path))
    else:
        exp = got
    assert canonicalize_snapshot(got, allow_compare_mode=True) == canonicalize_snapshot(
        exp, allow_compare_mode=True
    )
    snapshot_updater.maybe_write(
        GOLD / "plan_compare_output.json",
        canonicalize_snapshot(got, allow_compare_mode=True),
    )
