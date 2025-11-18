import json
import sys
from pathlib import Path

import pytest
from hypothesis import given, strategies as st

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from tools.vectorscan import vectorscan as vs
from tools.vectorscan.policies import get_policy

# Property-based test: iter_resources with random nested modules
@given(
    resources=st.lists(st.dictionaries(st.text(), st.integers() | st.text() | st.none() | st.dictionaries(st.text(), st.integers() | st.text() | st.none())), max_size=5),
    child_modules=st.lists(st.dictionaries(keys=st.just("resources"), values=st.lists(st.dictionaries(st.text(), st.integers() | st.text() | st.none()), max_size=3)), max_size=3)
)
def test_iter_resources_property(resources, child_modules):
    plan = {"planned_values": {"root_module": {"resources": resources, "child_modules": child_modules}}}
    res = vs.iter_resources(plan)
    assert isinstance(res, list)


normalized_resource_strategy = st.fixed_dictionaries(
    {
        "type": st.text(max_size=6),
        "name": st.text(max_size=6),
        "values": st.dictionaries(st.text(max_size=5), st.text(max_size=5) | st.integers() | st.none(), max_size=2),
    }
)

normalized_module_strategy = st.recursive(
    st.fixed_dictionaries(
        {
            "resources": st.lists(normalized_resource_strategy, max_size=3),
            "child_modules": st.one_of(st.none(), st.just([])),
        }
    ),
    lambda children: st.fixed_dictionaries(
        {
            "resources": st.lists(normalized_resource_strategy, max_size=3),
            "child_modules": st.one_of(st.none(), st.just([]), st.lists(children, max_size=2)),
        }
    ),
    max_leaves=8,
)


def _flatten_module(module: dict) -> list:
    collected = list(module.get("resources", []) or [])
    for child in module.get("child_modules", []) or []:
        collected.extend(_flatten_module(child))
    return collected


@given(normalized_module_strategy)
def test_iter_resources_plan_normalization(module):
    plan = {"planned_values": {"root_module": module}}
    expected = _flatten_module(module)
    assert vs.iter_resources(plan) == expected

# Property-based test: check_encryption with random resource dicts
@given(
    resources=st.lists(st.dictionaries(st.text(), st.integers() | st.text() | st.none() | st.dictionaries(st.text(), st.integers() | st.text() | st.none())), max_size=5)
)
def test_check_encryption_property(resources):
    out = vs.check_encryption(resources)
    assert isinstance(out, list)

# Property-based test: check_tags with random resource dicts
@given(
    resources=st.lists(st.dictionaries(st.text(), st.integers() | st.text() | st.none() | st.dictionaries(st.text(), st.integers() | st.text() | st.none())), max_size=5)
)
def test_check_tags_property(resources):
    out = vs.check_tags(resources)
    assert isinstance(out, list)


tag_values_strategy = st.dictionaries(
    keys=st.sampled_from(["CostCenter", "Project", "Team"]),
    values=st.one_of(st.none(), st.text(max_size=8)),
    max_size=3,
)

resource_strategy = st.fixed_dictionaries(
    {
        "type": st.sampled_from(sorted(list(vs.TAGGABLE_TYPES)) + ["aws_custom_app", "random_type"]),
        "values": st.fixed_dictionaries(
            {
                "storage_encrypted": st.one_of(st.none(), st.booleans()),
                "kms_key_id": st.one_of(st.none(), st.text(max_size=8)),
                "tags": st.one_of(st.none(), tag_values_strategy),
            }
        ),
    }
)

@given(st.lists(resource_strategy, max_size=5))
def test_compute_metrics_compliance_score_bounds(resources):
    metrics = vs.compute_metrics(resources, violations=[])
    assert 0 <= metrics["compliance_score"] <= 100


def test_compute_violation_severity_summary_counts():
    violations = [
        "P-SEC-001: missing encryption",
        "P-FIN-001: missing CostCenter",
        "P-SEC-001: missing kms",
    ]
    summary = vs.compute_violation_severity_summary(violations)
    assert summary == {"critical": 2, "high": 1, "medium": 0, "low": 0}


def test_compute_violation_severity_summary_defaults_to_medium():
    summary = vs.compute_violation_severity_summary([
        "P-UNKNOWN-123: something else",
        "not even a policy prefix",
    ])
    assert summary["medium"] == 2


def test_structured_remediation_blocks(tmp_path, capsys):
    plan_path = ROOT / "tests/fixtures/tfplan_fail.json"
    code = vs.main([str(plan_path), "--json"])
    assert code == 3
    payload = json.loads(capsys.readouterr().out)
    metrics_block = payload.get("metrics") or {}
    plan_meta = payload.get("plan_metadata") or {}
    assert metrics_block.get("parser_mode") in {"legacy", "streaming"}
    assert metrics_block.get("parser_mode") == plan_meta.get("parser_mode")
    assert metrics_block.get("resource_count") == plan_meta.get("resource_count")
    struct = payload.get("violations_struct") or []
    assert len(struct) == 2
    encryption = next(v for v in struct if v["policy_id"] == "P-SEC-001")
    tagging = next(v for v in struct if v["policy_id"] == "P-FIN-001")
    assert encryption["remediation"]["hcl_completeness"] == pytest.approx(0.75)
    assert tagging["remediation"]["hcl_completeness"] == pytest.approx(0.75)
    assert encryption["resource_details"]["data_taint"] == "resource_body"
    assert tagging["resource_details"]["data_taint"] in {"resource_body", "module_source"}
    for entry in struct:
        remediation = entry["remediation"]
        assert remediation["docs"], "Docs list should not be empty"
        assert remediation["hcl_examples"], "HCL examples required for remediation"

# Combinatorial test: deeply nested child modules
def test_iter_resources_deep_nesting():
    plan = {"planned_values": {"root_module": {"resources": [], "child_modules": [
        {"resources": [], "child_modules": [
            {"resources": [{"type": "aws_db_instance"}]}
        ]}
    ]}}}
    res = vs.iter_resources(plan)
    assert any(r["type"] == "aws_db_instance" for r in res)

# Negative test: malformed resource (missing type)
def test_check_encryption_malformed():
    resources = [{"values": {"storage_encrypted": True}}]
    out = vs.check_encryption(resources)
    assert isinstance(out, list)

# Edge case: _is_nonempty_string with whitespace and special chars
@pytest.mark.parametrize("val,expected", [
    ("   ", False),
    ("\n\t", False),
    ("foo", True),
    ("!@#", True),
    ("", False),
    (None, False),
])
def test__is_nonempty_string_edge(val, expected):
    assert vs._is_nonempty_string(val) == expected

# Stress test: large number of resources
def test_iter_resources_large():
    resources = [{"type": "aws_db_instance", "values": {"storage_encrypted": True, "tags": {}}}] * 1000
    plan = {"planned_values": {"root_module": {"resources": resources}}}
    res = vs.iter_resources(plan)
    assert len(res) == 1000
# --- Additional test expansions for uncovered logic and error handling ---
import pytest

def test_iter_resources_empty_child_modules():
    plan = {"planned_values": {"root_module": {"resources": [], "child_modules": []}}}
    res = vs.iter_resources(plan)
    assert res == []

def test_check_encryption_multiple_resources():
    resources = [
        {"type": "aws_db_instance", "values": {"storage_encrypted": True, "kms_key_id": "abc"}},
        {"type": "aws_db_instance", "values": {"storage_encrypted": False, "kms_key_id": "abc"}, "name": "db1"},
        {"type": "aws_db_instance", "values": {"storage_encrypted": True}, "name": "db2"},
    ]
    out = vs.check_encryption(resources)
    assert any("storage_encrypted" in v for v in out)
    assert any("kms_key_id" in v for v in out)

def test_check_tags_missing_all_tags():
    resources = [
        {"type": "aws_db_instance", "values": {"tags": {}}},
        {"type": "aws_db_instance", "values": {}, "name": "db2"},
    ]
    out = vs.check_tags(resources)
    assert all("no tags" in v for v in out)

def test__write_local_capture_creates_dir(tmp_path, monkeypatch):
    import os
    payload = {"foo": "bar"}
    # Patch __file__ to use tmp_path
    monkeypatch.setattr("vectorscan.__file__", str(tmp_path / "vectorscan.py"))
    path = vs._write_local_capture(payload)
    assert path.exists()
    with open(path) as f:
        assert "foo" in f.read()
    os.remove(path)

def test__maybe_post_invalid_url():
    ok, info = vs._maybe_post("http://invalid:9999", {"foo": "bar"}, timeout=1)
    assert not ok
    assert isinstance(info, str)
import pytest

def test_load_json_valid_plan(tmp_path):
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [],
                "child_modules": [],
            }
        }
    }
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan))
    result = vs.load_json(path)
    assert result == plan


@pytest.mark.parametrize("content", ["[]", "123", "null", "\"x\"", "true", "false"])
def test_load_json_non_object(tmp_path, monkeypatch, content):
    import sys

    path = tmp_path / "plan.json"
    path.write_text(content)

    class DummySchemaError(Exception):
        pass

    def fake_exit(code):
        raise DummySchemaError()

    monkeypatch.setattr(sys, "exit", fake_exit)

    with pytest.raises(DummySchemaError):
        vs.load_json(path)

def test_load_json_file_not_found(monkeypatch):
    import sys
    import builtins
    class DummyFileNotFound(Exception): pass
    def fake_exit(code):
        raise DummyFileNotFound()
    monkeypatch.setattr(sys, "exit", fake_exit)
    try:
        vs.load_json(Path("/not/a/real/file.json"))
    except DummyFileNotFound:
        pass
    else:
        assert False, "Should exit on file not found"

def test_load_json_invalid_json(monkeypatch):
    import sys, tempfile
    class DummyJSONDecode(Exception): pass
    def fake_exit(code):
        raise DummyJSONDecode()
    monkeypatch.setattr(sys, "exit", fake_exit)
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=True) as tf:
        tf.write("not valid json")
        tf.flush()
        try:
            vs.load_json(Path(tf.name))
        except DummyJSONDecode:
            pass
        else:
            assert False, "Should exit on invalid JSON"


def test_load_json_missing_root(monkeypatch, tmp_path):
    import sys

    plan = {"planned_values": {}}
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan))

    class DummySchemaError(Exception):
        pass

    def fake_exit(code):
        raise DummySchemaError()

    monkeypatch.setattr(sys, "exit", fake_exit)

    try:
        vs.load_json(path)
    except DummySchemaError:
        pass
    else:
        assert False, "Schema error should exit"


def test_load_json_child_modules_must_be_list(monkeypatch, tmp_path):
    import sys

    plan = {
        "planned_values": {
            "root_module": {
                "resources": [],
                "child_modules": "bad",
            }
        }
    }
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan))

    class DummySchemaError(Exception):
        pass

    def fake_exit(code):
        raise DummySchemaError()

    monkeypatch.setattr(sys, "exit", fake_exit)

    with pytest.raises(DummySchemaError):
        vs.load_json(path)


@pytest.mark.parametrize("plan,expected_types", [
    ( {"planned_values": {"root_module": {"resources": [{"type": "aws_db_instance"}], "child_modules": [{"resources": [{"type": "aws_rds_cluster"}]}]}}}, {"aws_db_instance", "aws_rds_cluster"}),
    ( {"planned_values": {"root_module": {}}}, set()),
    ( {}, set()),
    ( {"planned_values": {"root_module": {"resources": []}}}, set()),
    ( {"planned_values": {"root_module": {"resources": [{"type": "aws_s3_bucket"}]}}}, {"aws_s3_bucket"}),
])
def test_iter_resources_cases(plan, expected_types):
    res = vs.iter_resources(plan)
    assert {r["type"] for r in res} == expected_types


def test_compute_plan_metadata_counts_and_modules():
    plan = {
        "planned_values": {
            "root_module": {
                "address": "root",
                "resources": [
                    {"type": "aws_db_instance"},
                    {"type": "aws_s3_bucket"},
                ],
                "child_modules": [
                    {
                        "address": "module.child",
                        "resources": [{"type": "aws_db_instance"}],
                        "child_modules": [],
                    }
                ],
            }
        }
    }

    metadata = vs.compute_plan_metadata(plan)

    assert metadata["resource_count"] == 3
    assert metadata["resource_types"] == {"aws_db_instance": 2, "aws_s3_bucket": 1}
    assert metadata["providers"] == ["aws"]
    assert metadata["module_count"] == 2
    modules = metadata["modules"]
    assert modules["root"] == "root"
    assert modules["with_resources"] == 2
    assert modules["child_module_count"] == 1
    assert modules["has_child_modules"] is True
    assert metadata["change_summary"] == {"adds": 0, "changes": 0, "destroys": 0}
    assert metadata["resources_by_type"]["aws_db_instance"]["planned"] == 2
    assert metadata["resources_by_type"]["aws_s3_bucket"]["planned"] == 1
    assert metadata["file_size_mb"] is None
    assert metadata["parser_mode"] == "legacy"


def test_compute_plan_metadata_respects_plan_limits_parser_mode():
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {"type": "aws_db_instance"},
                ],
                "child_modules": [],
            }
        }
    }
    plan_limits = {
        "parser_mode": "streaming",
        "file_size_bytes": 100,
        "parse_duration_ms": 5,
        "plan_slo": {},
        "exceeds_threshold": False,
    }

    metadata = vs.compute_plan_metadata(plan, plan_limits=plan_limits)

    assert metadata["parser_mode"] == "streaming"


def test_policy_isolation_runs_other_checks_when_encryption_fails(monkeypatch, tmp_path, capsys):
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "type": "aws_db_instance",
                        "name": "db1",
                        "values": {"storage_encrypted": False, "tags": {}},
                    }
                ]
            }
        }
    }
    plan_path = _write_plan(tmp_path, plan)

    encryption_policy = get_policy("P-SEC-001")

    def boom(_resources):
        raise RuntimeError("encryption blew up")

    monkeypatch.setattr(encryption_policy, "evaluate", boom)

    code = vs.main([str(plan_path), "--json"])
    output = capsys.readouterr().out
    payload = json.loads(output)

    assert code == 3
    assert payload["status"] == "FAIL"
    assert any("P-FIN-001" in v for v in payload["violations"])
    assert payload["policy_errors"][0]["policy"] == "P-SEC-001"


def test_policy_isolation_runs_other_checks_when_tags_fail(monkeypatch, tmp_path, capsys):
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "type": "aws_db_instance",
                        "name": "db2",
                        "values": {
                            "storage_encrypted": False,
                            "kms_key_id": None,
                            "tags": {"CostCenter": "A", "Project": "B"},
                        },
                    }
                ]
            }
        }
    }
    plan_path = _write_plan(tmp_path, plan)

    tagging_policy = get_policy("P-FIN-001")

    def boom(_resources):
        raise RuntimeError("tag engine outage")

    monkeypatch.setattr(tagging_policy, "evaluate", boom)

    code = vs.main([str(plan_path), "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert code == 3
    assert payload["status"] == "FAIL"
    assert any("P-SEC-001" in v for v in payload["violations"])
    assert payload["policy_errors"][0]["policy"] == "P-FIN-001"


def test_vectorscan_json_handles_unicode(monkeypatch, tmp_path, capsys):
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "type": "aws_db_instance",
                        "name": "数据库-一号",
                        "values": {
                            "storage_encrypted": False,
                            "kms_key_id": None,
                            "tags": {"CostCenter": "成本中心-一", "Project": "项目🚀"},
                        },
                    }
                ]
            }
        }
    }
    plan_path = _write_plan(tmp_path, plan)
    _set_deterministic_clock(monkeypatch)

    capsys.readouterr()
    code = vs.main([str(plan_path), "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert code == 3
    assert any("数据库" in v for v in payload["violations"])
    serialized = json.dumps(payload, ensure_ascii=False)
    assert "数据库" in serialized


@pytest.mark.parametrize("resources,expected_violations", [
    ([{"type": "aws_db_instance", "values": {"storage_encrypted": True, "kms_key_id": "abc"}}], []),
    ([{"type": "aws_db_instance", "values": {"storage_encrypted": False, "kms_key_id": "abc"}, "name": "db1"}], ["storage_encrypted"]),
    ([{"type": "aws_db_instance", "values": {"storage_encrypted": True}, "name": "db2"}], ["kms_key_id"]),
    ([{"type": "aws_s3_bucket", "values": {}}], []),
    ([{"type": "aws_db_instance", "values": {}}], ["storage_encrypted"]),
    ([{"type": "aws_rds_cluster", "values": {"storage_encrypted": False, "kms_key_id": None}, "name": "c1"}], ["storage_encrypted"]),
])
def test_check_encryption_cases(resources, expected_violations):
    out = vs.check_encryption(resources)
    for v in expected_violations:
        assert any(v in msg for msg in out)
    if not expected_violations:
        assert out == []


def test_vectorscan_json_output_stable(monkeypatch, capsys):
    plan_path = ROOT / "examples" / "aws-pgvector-rag" / "tfplan-fail.json"

    monkeypatch.setenv("VSCAN_CLOCK_EPOCH", "1700000000")
    monkeypatch.setenv("VSCAN_CLOCK_ISO", "2024-01-02T00:00:00Z")
    monkeypatch.setenv("VSCAN_FORCE_DURATION_MS", "1")

    def run_once():
        capsys.readouterr()  # clear buffers
        exit_code = vs.main([str(plan_path), "--json"])
        captured = capsys.readouterr()
        return exit_code, captured.out

    code1, output1 = run_once()
    code2, output2 = run_once()

    assert code1 == code2
    assert output1 == output2
    assert json.loads(output1) == json.loads(output2)


def _write_plan(tmp_path, payload):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(payload))
    return path


def _set_deterministic_clock(monkeypatch):
    monkeypatch.setenv("VSCAN_CLOCK_EPOCH", "1700000000")
    monkeypatch.setenv("VSCAN_CLOCK_ISO", "2024-01-02T00:00:00Z")


def _enable_strict_mode(monkeypatch):
    monkeypatch.setenv("VSCAN_STRICT", "1")


def test_build_environment_metadata_overrides(monkeypatch):
    monkeypatch.setenv("VSCAN_ENV_PLATFORM", "unit-os")
    monkeypatch.setenv("VSCAN_ENV_PLATFORM_RELEASE", "release-x")
    monkeypatch.setenv("VSCAN_ENV_PYTHON_VERSION", "3.99-test")
    monkeypatch.setenv("VSCAN_ENV_PYTHON_IMPL", "UnitPy")
    monkeypatch.setenv("VSCAN_ENV_TERRAFORM_VERSION", "1.2.3")
    monkeypatch.setenv("VSCAN_ENV_TERRAFORM_SOURCE", "system")
    meta = vs._build_environment_metadata(
        strict_mode=True,
        offline_mode=False,
        terraform_report=None,
        vectorscan_version_value="9.9.9",
    )
    assert meta["platform"] == "unit-os"
    assert meta["platform_release"] == "release-x"
    assert meta["python_version"] == "3.99-test"
    assert meta["python_implementation"] == "UnitPy"
    assert meta["terraform_version"] == "1.2.3"
    assert meta["terraform_source"] == "system"
    assert meta["vectorscan_version"] == "9.9.9"
    assert meta["strict_mode"] is True
    assert meta["offline_mode"] is False


def test_cli_outputs_environment_block(monkeypatch, tmp_path, capsys):
    plan = {"planned_values": {"root_module": {"resources": []}}}
    plan_path = _write_plan(tmp_path, plan)
    _set_deterministic_clock(monkeypatch)
    monkeypatch.setenv("VSCAN_ENV_PLATFORM", "unit-os")
    monkeypatch.setenv("VSCAN_ENV_PLATFORM_RELEASE", "rel-1")
    monkeypatch.setenv("VSCAN_ENV_PYTHON_VERSION", "3.11.test")
    monkeypatch.setenv("VSCAN_ENV_PYTHON_IMPL", "CPython")
    monkeypatch.setenv("VSCAN_ENV_TERRAFORM_VERSION", "not-run")
    monkeypatch.setenv("VSCAN_ENV_TERRAFORM_SOURCE", "not-run")

    capsys.readouterr()
    code = vs.main([str(plan_path), "--json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert code == 0
    env_block = data["environment"]
    assert env_block["platform"] == "unit-os"
    assert env_block["python_version"] == "3.11.test"
    assert env_block["terraform_version"] == "not-run"


def test_strict_mode_requires_clock_overrides(monkeypatch, tmp_path, capsys):
    plan_path = _write_plan(tmp_path, {"planned_values": {"root_module": {"resources": []}}})
    _enable_strict_mode(monkeypatch)
    for key in ("VSCAN_CLOCK_EPOCH", "VSCAN_CLOCK_ISO", "SOURCE_DATE_EPOCH"):
        monkeypatch.delenv(key, raising=False)

    capsys.readouterr()
    code = vs.main([str(plan_path), "--json"])
    captured = capsys.readouterr()

    assert code == vs.EXIT_CONFIG_ERROR
    assert "[Strict Mode]" in captured.err


def test_strict_mode_disallows_policy_errors(monkeypatch, tmp_path, capsys):
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "type": "aws_db_instance",
                        "name": "db1",
                        "values": {"storage_encrypted": False, "kms_key_id": None, "tags": {}},
                    }
                ]
            }
        }
    }
    plan_path = _write_plan(tmp_path, plan)
    _set_deterministic_clock(monkeypatch)
    _enable_strict_mode(monkeypatch)

    encryption_policy = get_policy("P-SEC-001")

    def boom(_resources):  # pragma: no cover - monkeypatched helper
        raise RuntimeError("strict failure trigger")

    monkeypatch.setattr(encryption_policy, "evaluate", boom)

    capsys.readouterr()
    code = vs.main([str(plan_path), "--json"])
    captured = capsys.readouterr()

    assert code == vs.EXIT_CONFIG_ERROR
    assert "[Strict Mode]" in captured.err


def test_strict_mode_passes_when_clean(monkeypatch, tmp_path, capsys):
    plan = {"planned_values": {"root_module": {"resources": []}}}
    plan_path = _write_plan(tmp_path, plan)
    _set_deterministic_clock(monkeypatch)
    _enable_strict_mode(monkeypatch)

    capsys.readouterr()
    code = vs.main([str(plan_path), "--json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert code == 0
    assert data["policy_errors"] == []


def test_compliance_score_penalty_clamped(monkeypatch, tmp_path, capsys):
    policy_after = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["iam:*"], "Resource": "*"}
            ],
        }
    )
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "type": "aws_db_instance",
                        "values": {
                            "storage_encrypted": True,
                            "kms_key_id": "kms123",
                            "tags": {"CostCenter": "C", "Project": "P"},
                        },
                    }
                ]
            }
        },
        "resource_changes": [
            {
                "type": "aws_iam_policy",
                "name": "wildcard",
                "change": {
                    "before": None,
                    "after": {"policy": policy_after},
                    "actions": ["create"],
                },
            }
        ],
    }
    plan_path = _write_plan(tmp_path, plan)
    _set_deterministic_clock(monkeypatch)

    capsys.readouterr()
    exit_code = vs.main([str(plan_path), "--json", "--iam-drift-penalty", "250"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert exit_code == 0
    assert data["metrics"]["iam_drift"]["status"] == "FAIL"
    assert 0 <= data["metrics"]["compliance_score"] <= 100
    assert data["metrics"]["compliance_score"] == 0


def test_unknown_resource_types_handled(monkeypatch, tmp_path, capsys):
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "type": "custom_provider_widget",
                        "values": {"tags": {"Foo": "Bar"}},
                    }
                ]
            }
        }
    }
    plan_path = _write_plan(tmp_path, plan)
    _set_deterministic_clock(monkeypatch)

    capsys.readouterr()
    exit_code = vs.main([str(plan_path), "--json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert exit_code == 0
    assert data["counts"]["violations"] == 0
    assert data["metrics"]["eligible_checks"] == 0
    assert data["metrics"]["compliance_score"] == 100

def test__is_nonempty_string():
    assert vs._is_nonempty_string("foo")
    assert not vs._is_nonempty_string("")
    assert not vs._is_nonempty_string(None)
    assert not vs._is_nonempty_string("   ")


@pytest.mark.parametrize("resources,expected", [
    ([{"type": "aws_db_instance", "values": {"tags": {"CostCenter": "A", "Project": "B"}}}], []),
    ([{"type": "aws_db_instance", "values": {"tags": {"CostCenter": "", "Project": "B"}}, "name": "db1"}], ["missing/empty tag"]),
    ([{"type": "aws_db_instance", "values": {}, "name": "db2"}], ["no tags"]),
    ([{"type": "aws_lambda_function", "values": {"tags": {"CostCenter": "A", "Project": "B"}}}], []),
    ([{"type": "aws_db_instance", "values": {"tags": {}}}], ["no tags"]),
    ([{"type": "aws_db_instance", "values": {"tags": {"CostCenter": "A"}}}], ["missing/empty tag"]),
])
def test_check_tags_cases(resources, expected):
    out = vs.check_tags(resources)
    for v in expected:
        assert any(v in msg for msg in out)
    if not expected:
        assert out == []


def test__write_local_capture(tmp_path):
    import os
    payload = {"foo": "bar"}
    path = vs._write_local_capture(payload)
    assert path.exists()
    with open(path) as f:
        assert "foo" in f.read()
    os.remove(path)


def test__maybe_post():
    # Should fail with invalid endpoint
    ok, info = vs._maybe_post("http://localhost:9999/doesnotexist", {"foo": "bar"}, timeout=1)
    assert not ok
    assert isinstance(info, str)


def test_main_smoke(tmp_path):
    import json as js
    f = tmp_path / "plan.json"
    f.write_text(js.dumps({"planned_values": {"root_module": {"resources": []}}}))
    code = vs.main([str(f), "--json"])
    assert code == 0


def test_offline_mode_disables_terraform_auto_download(tmp_path, monkeypatch):
    plan = {"planned_values": {"root_module": {"resources": []}}}
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan))

    monkeypatch.setenv("VSCAN_OFFLINE", "1")
    monkeypatch.setenv("VSCAN_TERRAFORM_TESTS", "1")

    captured = {}

    def fake_run(override_bin, auto_download):
        captured["auto_download"] = auto_download
        return {"status": "SKIP", "message": "offline test"}

    monkeypatch.setattr(vs, "run_terraform_tests", fake_run)

    code = vs.main([str(plan_path)])
    assert code == 0
    assert captured.get("auto_download") is False
    monkeypatch.delenv("VSCAN_OFFLINE", raising=False)
    monkeypatch.delenv("VSCAN_TERRAFORM_TESTS", raising=False)
