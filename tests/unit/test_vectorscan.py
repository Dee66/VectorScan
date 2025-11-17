from hypothesis import given, strategies as st, settings

# Property-based test: random plan with required structure

@settings(deadline=None)
@given(
    encrypted=st.booleans(),
    costcenter=st.one_of(st.none(), st.text()),
    project=st.one_of(st.none(), st.text())
)
def test_vectorscan_property(encrypted, costcenter, project):
    import tempfile
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {"type": "aws_db_instance", "name": "db1", "values": {
                        "storage_encrypted": encrypted,
                        "kms_key_id": "abc" if encrypted else None,
                        "tags": {"CostCenter": costcenter, "Project": project}
                    }}
                ]
            }
        }
    }
    with tempfile.NamedTemporaryFile("w+", delete=True, suffix=".json") as f:
        f.write(json.dumps(plan))
        f.flush()
        code, out, err = run([sys.executable, str(CLI), f.name, "--json"])
    assert code in (0, 3)
    data = json.loads(out)
    assert data["status"] in ("PASS", "FAIL")

# Combinatorial test: multiple resources with mixed states
def test_vectorscan_combinatorial_resources(tmp_path):
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {"type": "aws_db_instance", "name": "db1", "values": {"storage_encrypted": True, "kms_key_id": "abc", "tags": {"CostCenter": "A", "Project": "B"}}},
                    {"type": "aws_db_instance", "name": "db2", "values": {"storage_encrypted": False, "tags": {"CostCenter": "", "Project": "B"}}},
                    {"type": "aws_s3_bucket", "name": "b1", "values": {"tags": {}}},
                ]
            }
        }
    }
    p = tmp_path / "combo-plan.json"
    p.write_text(json.dumps(plan))
    code, out, err = run([sys.executable, str(CLI), str(p), "--json"])
    assert code == 3
    data = json.loads(out)
    assert data["status"] == "FAIL"
    assert len(data["violations"]) >= 1

# Negative test: malformed resource structure
def test_vectorscan_malformed_resource(tmp_path):
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {"type": "aws_db_instance", "name": "db1"}  # missing 'values'
                ]
            }
        }
    }
    p = tmp_path / "malformed-plan.json"
    p.write_text(json.dumps(plan))
    code, out, err = run([sys.executable, str(CLI), str(p), "--json"])
    assert code == 3
    data = json.loads(out)
    assert data["status"] == "FAIL"

# CLI flag test: --lead-capture and --email
def test_vectorscan_lead_capture_flags(tmp_path):
    plan = {
        "planned_values": {
            "root_module": {
                "resources": []
            }
        }
    }
    p = tmp_path / "lead-capture-plan.json"
    p.write_text(json.dumps(plan))
    code, out, err = run([sys.executable, str(CLI), str(p), "--lead-capture", "--email", "test@example.com", "--json"])
    assert code == 0
    data = json.loads(out)
    assert data["status"] == "PASS"

# Large plan file test
def test_vectorscan_large_plan(tmp_path):
    resources = [
        {"type": "aws_db_instance", "name": f"db{i}", "values": {"storage_encrypted": True, "kms_key_id": "abc", "tags": {"CostCenter": "A", "Project": "B"}}}
        for i in range(100)
    ]
    plan = {
        "planned_values": {
            "root_module": {
                "resources": resources
            }
        }
    }
    p = tmp_path / "large-plan.json"
    p.write_text(json.dumps(plan))
    code, out, err = run([sys.executable, str(CLI), str(p), "--json"])
    assert code == 0
    data = json.loads(out)
    assert data["status"] == "PASS"
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PASS = ROOT / "examples/aws-pgvector-rag/tfplan-pass.json"
FAIL = ROOT / "examples/aws-pgvector-rag/tfplan-fail.json"
CLI = ROOT / "tools/vectorscan/vectorscan.py"

ENV = os.environ.copy()
env_pythonpath = ENV.get("PYTHONPATH")
segments = [str(ROOT)]
if env_pythonpath:
    segments.append(env_pythonpath)
ENV["PYTHONPATH"] = os.pathsep.join(segments)


def run(cmd):
    p = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        cwd=str(ROOT),
        env=ENV,
    )
    return p.returncode, p.stdout.strip(), p.stderr.strip()



import pytest

@pytest.mark.parametrize("plan_path,expected_code,expected_status,violation_count", [
    (PASS, 0, "PASS", 0),
    (FAIL, 3, "FAIL", 1),
    (PASS, 0, "PASS", 0),
    (FAIL, 3, "FAIL", 1),
])
def test_vectorscan_json_param(plan_path, expected_code, expected_status, violation_count):
    code, out, err = run([sys.executable, str(CLI), str(plan_path), "--json"])
    assert code == expected_code, f"expected {expected_code}, got {code}\nstdout={out}\nstderr={err}"
    data = json.loads(out)
    assert data["status"] == expected_status
    assert data["counts"]["violations"] >= violation_count
    if expected_status == "PASS":
        assert data["violations"] == []
    else:
        assert isinstance(data["violations"], list) and data["violations"]



# Edge/unhappy path: missing plan file
def test_vectorscan_missing_plan():
    import tempfile
    missing = tempfile.gettempdir() + "/no-such-plan.json"
    code, out, err = run([sys.executable, str(CLI), missing, "--json"])
    assert code == 2
    assert "file not found" in err

# Edge/unhappy path: invalid JSON
def test_vectorscan_invalid_json(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    code, out, err = run([sys.executable, str(CLI), str(bad), "--json"])
    assert code == 2
    assert "invalid JSON" in err

# Edge: plan with missing tags
def test_vectorscan_missing_tags(tmp_path):
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {"type": "aws_db_instance", "name": "db1", "values": {"storage_encrypted": True, "kms_key_id": "abc", "tags": {"CostCenter": "", "Project": "B"}}}
                ]
            }
        }
    }
    p = tmp_path / "missing-tags.json"
    p.write_text(json.dumps(plan))
    code, out, err = run([sys.executable, str(CLI), str(p), "--json"])
    assert code == 3
    data = json.loads(out)
    assert data["status"] == "FAIL"
    assert any("missing/empty tag" in v for v in data["violations"])


def test_vectorscan_json_plan_metadata_block(tmp_path):
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "type": "aws_db_instance",
                        "name": "db-meta",
                        "values": {
                            "storage_encrypted": True,
                            "kms_key_id": "kms",
                            "tags": {"CostCenter": "Meta", "Project": "Plan"},
                        },
                    }
                ],
                "child_modules": [
                    {
                        "address": "module.child",
                        "resources": [
                            {
                                "type": "aws_s3_bucket",
                                "name": "bucket",
                                "values": {"tags": {"CostCenter": "Meta", "Project": "Plan"}},
                            }
                        ],
                        "child_modules": [],
                    }
                ],
            }
        }
    }
    plan_path = tmp_path / "plan-meta.json"
    plan_path.write_text(json.dumps(plan))

    code, out, err = run([sys.executable, str(CLI), str(plan_path), "--json"])
    assert code == 0
    payload = json.loads(out)
    metadata = payload.get("plan_metadata") or {}
    assert metadata["resource_count"] == 2
    assert metadata["resource_types"] == {"aws_db_instance": 1, "aws_s3_bucket": 1}
    assert metadata["providers"] == ["aws"]
    assert metadata["module_count"] == 2
    assert metadata["modules"]["has_child_modules"] is True
    assert metadata["exceeds_threshold"] is False
    assert metadata["file_size_bytes"] == plan_path.stat().st_size
    assert isinstance(metadata["parse_duration_ms"], int)
    assert metadata["parse_duration_ms"] >= 0
    assert "plan_slo" in metadata
    observed = metadata["plan_slo"]["observed"]
    assert observed["resource_count"] == metadata["resource_count"]
    assert "resources_by_type" in metadata
    assert metadata["change_summary"]["adds"] == 0
    assert metadata.get("file_size_mb") is not None
    assert payload.get("security_grade")
    assert payload.get("violation_count_by_severity")


def test_vectorscan_json_explain_block(tmp_path):
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "type": "aws_db_instance",
                        "name": "db-explain",
                        "values": {
                            "storage_encrypted": True,
                            "kms_key_id": "kms",
                            "tags": {"CostCenter": "A", "Project": "B"},
                        },
                    }
                ]
            }
        }
    }
    plan_path = tmp_path / "plan-explain.json"
    plan_path.write_text(json.dumps(plan))

    code, out, err = run([sys.executable, str(CLI), str(plan_path), "--json", "--explain"])
    assert code == 0
    payload = json.loads(out)
    explanation = payload.get("explanation") or {}
    assert explanation["plan_overview"]["resource_count"] == 1
    assert "summary" in explanation


def test_vectorscan_human_explain_block(tmp_path):
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "type": "aws_db_instance",
                        "name": "db-risk",
                        "values": {
                            "storage_encrypted": False,
                            "tags": {"CostCenter": "", "Project": "B"},
                        },
                    }
                ]
            }
        }
    }
    plan_path = tmp_path / "plan-explain-human.json"
    plan_path.write_text(json.dumps(plan))

    code, out, err = run([sys.executable, str(CLI), str(plan_path), "--explain"])
    assert code == 3
    assert "VectorScan Explain Report" in out
    assert "High-risk resources" in out

# Edge: human-readable output
def test_vectorscan_human_output(tmp_path):
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {"type": "aws_db_instance", "name": "db1", "values": {"storage_encrypted": True, "kms_key_id": "abc", "tags": {"CostCenter": "A", "Project": "B"}}}
                ]
            }
        }
    }
    p = tmp_path / "pass-human.json"
    p.write_text(json.dumps(plan))
    code, out, err = run([sys.executable, str(CLI), str(p)])
    assert code == 0
    assert "PASS" in out


