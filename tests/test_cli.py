import hashlib
import json
import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI = REPO_ROOT / "tools" / "vectorscan" / "vectorscan.py"
FIXTURES = REPO_ROOT / "tests" / "fixtures"


def _write_preview_manifest(tmp_path: Path, *, signature: str | None = None) -> Path:
    policies = [{"id": "P-SEC-999", "summary": "Paid zero-trust guardrail"}]
    canonical = json.dumps(policies, sort_keys=True, separators=(",", ":")).encode()
    sig = signature or f"sha256:{hashlib.sha256(canonical).hexdigest()}"
    payload = {
        "version": "test",
        "generated_at": "2025-11-18T00:00:00Z",
        "policies": policies,
        "signature": sig,
    }
    manifest_path = tmp_path / "preview_manifest.json"
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    return manifest_path


def _run_cli(args: list[str], *, env: dict[str, str] | None = None):
    base_env = os.environ.copy()
    existing = base_env.get("PYTHONPATH")
    parts = [str(REPO_ROOT)]
    if existing:
        parts.append(existing)
    base_env["PYTHONPATH"] = os.pathsep.join(parts)
    if env:
        base_env.update(env)
    cmd = ["python3", str(CLI), *args]
    return subprocess.run(cmd, capture_output=True, text=True, env=base_env)


def run_cli(plan_path: Path):
    return _run_cli([str(plan_path), "--json"])


def test_cli_exit_codes_pass_fail():
    # PASS plan -> exit code 0
    res_pass = run_cli(FIXTURES / "tfplan_pass.json")
    assert res_pass.returncode == 0, res_pass.stderr
    pass_payload = json.loads(res_pass.stdout)
    assert pass_payload["status"] == "PASS"
    summary = pass_payload.get("violation_severity_summary")
    assert summary == {"critical": 0, "high": 0, "medium": 0, "low": 0}
    assert isinstance(pass_payload["metrics"].get("scan_duration_ms"), int)
    assert pass_payload["metrics"]["scan_duration_ms"] >= 0
    assert pass_payload["badge_eligible"] is True

    # FAIL plan -> exit code 3
    res_fail = run_cli(FIXTURES / "tfplan_fail.json")
    assert res_fail.returncode == 3, res_fail.stdout + "\n" + res_fail.stderr
    payload = json.loads(res_fail.stdout)
    assert payload["status"] == "FAIL"
    assert isinstance(payload.get("violations"), list)
    fail_summary = payload.get("violation_severity_summary")
    assert fail_summary == {"critical": 1, "high": 1, "medium": 0, "low": 0}
    assert isinstance(payload["metrics"].get("scan_duration_ms"), int)
    assert payload["metrics"]["scan_duration_ms"] >= 0
    assert payload["badge_eligible"] is False
    issue = payload["issues"][0]
    required_fields = {
        "id",
        "severity",
        "title",
        "description",
        "resource_address",
        "attributes",
        "remediation_hint",
        "remediation_difficulty",
        "remediation_metadata",
    }
    assert required_fields.issubset(issue.keys())
    assert isinstance(issue["remediation_metadata"], dict)
    ledger = payload.get("remediation_ledger")
    assert isinstance(ledger, dict)
    assert ledger.get("remediation_rule_index") == ledger.get("rule_ids")
    assert ledger.get("remediation_summary") == ledger.get("per_severity")


def test_cli_invalid_json_exit_code():
    res_bad = run_cli(FIXTURES / "tfplan_invalid.json")
    assert res_bad.returncode == 2, res_bad.stdout + "\n" + res_bad.stderr


def test_cli_color_output_forced_and_disabled():
    plan = FIXTURES / "tfplan_pass.json"
    env = {"VSCAN_FORCE_COLOR": "1"}

    colored = _run_cli([str(plan)], env=env)
    assert colored.returncode == 0, colored.stderr
    assert "\x1b[" in colored.stdout

    no_color = _run_cli([str(plan), "--no-color"], env=env)
    assert no_color.returncode == 0, no_color.stderr
    assert "\x1b[" not in no_color.stdout


def test_cli_includes_policy_pack_hash():
    res = run_cli(FIXTURES / "tfplan_pass.json")
    assert res.returncode == 0, res.stderr
    payload = json.loads(res.stdout)
    hash_value = payload.get("policy_pack_hash")
    assert isinstance(hash_value, str)
    assert len(hash_value) == 64


def test_cli_includes_policy_manifest_metadata():
    res = run_cli(FIXTURES / "tfplan_pass.json")
    payload = json.loads(res.stdout)
    assert "policy_source_url" in payload
    manifest = payload.get("policy_manifest")
    assert isinstance(manifest, dict)
    assert manifest.get("policy_version") == payload.get("policy_version")
    assert manifest.get("policy_pack_hash") == payload.get("policy_pack_hash")
    assert manifest.get("signature", "").startswith("sha256:")


def test_cli_policy_manifest_print_command():
    res = _run_cli(["--policy-manifest"])
    assert res.returncode == 0, res.stderr
    manifest = json.loads(res.stdout)
    assert manifest.get("policy_version")
    assert manifest.get("policy_pack_hash")
    assert manifest.get("signature", "").startswith("sha256:")


def test_cli_policy_filter_limits_checks():
    res = _run_cli(
        [
            str(FIXTURES / "tfplan_fail.json"),
            "--json",
            "--policy",
            "P-FIN-001",
        ]
    )
    assert res.returncode == 2, res.stdout + "\n" + res.stderr
    payload = json.loads(res.stdout)
    assert payload["checks"] == ["P-FIN-001"]
    assert all(v.startswith("P-FIN-001") for v in payload["violations"])


def test_cli_policy_preset_works():
    res = _run_cli(
        [
            str(FIXTURES / "tfplan_pass.json"),
            "--json",
            "--policies",
            "finops",
        ]
    )
    assert res.returncode == 0, res.stderr
    payload = json.loads(res.stdout)
    assert payload["checks"] == ["P-FIN-001"]


def test_cli_policy_selection_invalid_option():
    res = _run_cli(
        [
            str(FIXTURES / "tfplan_pass.json"),
            "--json",
            "--policies",
            "unknown-pack",
        ]
    )
    assert res.returncode == 2
    assert "unknown-pack" in res.stderr.lower()


def test_cli_github_action_mode_forces_json_sorted_output():
    plan = FIXTURES / "tfplan_fail.json"
    res = _run_cli(
        [
            str(plan),
            "--gha",
        ]
    )
    assert res.returncode == 3, res.stderr
    assert "\x1b" not in res.stdout
    assert not res.stderr.strip()
    raw = res.stdout.rstrip("\n")
    payload = json.loads(raw)
    assert payload["status"] == "FAIL"
    expected = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True)
    assert raw == expected


def test_cli_preview_manifest_override_requires_valid_signature(tmp_path):
    manifest = _write_preview_manifest(tmp_path, signature="sha256:deadbeef")
    env = {"VSCAN_PREVIEW_MANIFEST": str(manifest)}
    res = _run_cli(
        [
            str(FIXTURES / "tfplan_pass.json"),
            "--json",
            "--preview-vectorguard",
        ],
        env=env,
    )
    assert res.returncode == 6
    assert "signature mismatch" in res.stderr.lower()


def test_cli_preview_manifest_skip_verify_allows_override(tmp_path):
    manifest = _write_preview_manifest(tmp_path, signature="sha256:deadbeef")
    env = {
        "VSCAN_PREVIEW_MANIFEST": str(manifest),
        "VSCAN_PREVIEW_SKIP_VERIFY": "1",
    }
    res = _run_cli(
        [
            str(FIXTURES / "tfplan_pass.json"),
            "--json",
            "--preview-vectorguard",
        ],
        env=env,
    )
    assert res.returncode == 10, res.stderr
    payload = json.loads(res.stdout)
    assert payload["preview_generated"] is True
    assert payload["preview_manifest"]["signature"] == "sha256:deadbeef"
    assert payload["preview_manifest"]["verified"] is True
    assert payload["preview_policies"][0]["id"] == "P-SEC-999"


def test_cli_remediation_ledger_consistent_across_modes():
    plan = FIXTURES / "tfplan_fail.json"
    compare_path = plan  # reuse the same plan to isolate ledger deltas
    commands = {
        "json": ([str(plan), "--json"], 3),
        "explain": ([str(plan), "--json", "--explain"], 3),
        "diff": ([str(plan), "--json", "--diff"], 3),
        "preview": ([str(plan), "--json", "--preview-vectorguard"], 10),
        "compare": (["--json", "--compare", str(compare_path), str(compare_path)], 0),
    }

    ledgers: dict[str, dict] = {}
    for label, (args, expected_code) in commands.items():
        result = _run_cli(args)
        assert result.returncode == expected_code, f"{label} stderr: {result.stderr}"
        payload = json.loads(result.stdout)
        ledger = payload.get("remediation_ledger")
        assert isinstance(ledger, dict), f"{label} missing remediation ledger"
        ledgers[label] = ledger

    baseline = ledgers["json"]
    for label, ledger in ledgers.items():
        assert ledger == baseline, f"ledger drift detected for {label}"
