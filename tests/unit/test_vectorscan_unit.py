import pytest
from hypothesis import given, strategies as st

# Property-based test: iter_resources with random nested modules
@given(
    resources=st.lists(st.dictionaries(st.text(), st.integers() | st.text() | st.none() | st.dictionaries(st.text(), st.integers() | st.text() | st.none())), max_size=5),
    child_modules=st.lists(st.dictionaries(keys=st.just("resources"), values=st.lists(st.dictionaries(st.text(), st.integers() | st.text() | st.none()), max_size=3)), max_size=3)
)
def test_iter_resources_property(resources, child_modules):
    from vectorscan import iter_resources
    plan = {"planned_values": {"root_module": {"resources": resources, "child_modules": child_modules}}}
    res = iter_resources(plan)
    assert isinstance(res, list)

# Property-based test: check_encryption with random resource dicts
@given(
    resources=st.lists(st.dictionaries(st.text(), st.integers() | st.text() | st.none() | st.dictionaries(st.text(), st.integers() | st.text() | st.none())), max_size=5)
)
def test_check_encryption_property(resources):
    from vectorscan import check_encryption
    out = check_encryption(resources)
    assert isinstance(out, list)

# Property-based test: check_tags with random resource dicts
@given(
    resources=st.lists(st.dictionaries(st.text(), st.integers() | st.text() | st.none() | st.dictionaries(st.text(), st.integers() | st.text() | st.none())), max_size=5)
)
def test_check_tags_property(resources):
    from vectorscan import check_tags
    out = check_tags(resources)
    assert isinstance(out, list)

# Combinatorial test: deeply nested child modules
def test_iter_resources_deep_nesting():
    from vectorscan import iter_resources
    plan = {"planned_values": {"root_module": {"resources": [], "child_modules": [
        {"resources": [], "child_modules": [
            {"resources": [{"type": "aws_db_instance"}]}
        ]}
    ]}}}
    res = iter_resources(plan)
    assert any(r["type"] == "aws_db_instance" for r in res)

# Negative test: malformed resource (missing type)
def test_check_encryption_malformed():
    from vectorscan import check_encryption
    resources = [{"values": {"storage_encrypted": True}}]
    out = check_encryption(resources)
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
    from vectorscan import _is_nonempty_string
    assert _is_nonempty_string(val) == expected

# Stress test: large number of resources
def test_iter_resources_large():
    from vectorscan import iter_resources
    resources = [{"type": "aws_db_instance", "values": {"storage_encrypted": True, "tags": {}}}] * 1000
    plan = {"planned_values": {"root_module": {"resources": resources}}}
    res = iter_resources(plan)
    assert len(res) == 1000
# --- Additional test expansions for uncovered logic and error handling ---
import pytest

def test_iter_resources_empty_child_modules():
    from vectorscan import iter_resources
    plan = {"planned_values": {"root_module": {"resources": [], "child_modules": []}}}
    res = iter_resources(plan)
    assert res == []

def test_check_encryption_multiple_resources():
    from vectorscan import check_encryption
    resources = [
        {"type": "aws_db_instance", "values": {"storage_encrypted": True, "kms_key_id": "abc"}},
        {"type": "aws_db_instance", "values": {"storage_encrypted": False, "kms_key_id": "abc"}, "name": "db1"},
        {"type": "aws_db_instance", "values": {"storage_encrypted": True}, "name": "db2"},
    ]
    out = check_encryption(resources)
    assert any("storage_encrypted" in v for v in out)
    assert any("kms_key_id" in v for v in out)

def test_check_tags_missing_all_tags():
    from vectorscan import check_tags
    resources = [
        {"type": "aws_db_instance", "values": {"tags": {}}},
        {"type": "aws_db_instance", "values": {}, "name": "db2"},
    ]
    out = check_tags(resources)
    assert all("no tags" in v for v in out)

def test__write_local_capture_creates_dir(tmp_path, monkeypatch):
    from vectorscan import _write_local_capture
    import os
    payload = {"foo": "bar"}
    # Patch __file__ to use tmp_path
    monkeypatch.setattr("vectorscan.__file__", str(tmp_path / "vectorscan.py"))
    path = _write_local_capture(payload)
    assert path.exists()
    with open(path) as f:
        assert "foo" in f.read()
    os.remove(path)

def test__maybe_post_invalid_url():
    from vectorscan import _maybe_post
    ok, info = _maybe_post("http://invalid:9999", {"foo": "bar"}, timeout=1)
    assert not ok
    assert isinstance(info, str)
from pathlib import Path

import pytest

@pytest.mark.parametrize("content,expected", [
    ("{}", {}),
    ("{\"foo\": 1}", {"foo": 1}),
    ("[]", []),
    ("123", 123),
    ("null", None),
    ("\"string\"", "string"),
    ("true", True),
    ("false", False),
])
def test_load_json_cases(tmp_path, content, expected):
    from vectorscan import load_json
    f = tmp_path / "test.json"
    f.write_text(content)
    result = load_json(f)
    assert result == expected

def test_load_json_file_not_found(monkeypatch):
    from vectorscan import load_json
    import sys
    import builtins
    class DummyFileNotFound(Exception): pass
    def fake_exit(code):
        raise DummyFileNotFound()
    monkeypatch.setattr(sys, "exit", fake_exit)
    try:
        load_json(Path("/not/a/real/file.json"))
    except DummyFileNotFound:
        pass
    else:
        assert False, "Should exit on file not found"

def test_load_json_invalid_json(monkeypatch):
    from vectorscan import load_json
    import sys, tempfile
    class DummyJSONDecode(Exception): pass
    def fake_exit(code):
        raise DummyJSONDecode()
    monkeypatch.setattr(sys, "exit", fake_exit)
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=True) as tf:
        tf.write("not valid json")
        tf.flush()
        try:
            load_json(Path(tf.name))
        except DummyJSONDecode:
            pass
        else:
            assert False, "Should exit on invalid JSON"


@pytest.mark.parametrize("plan,expected_types", [
    ( {"planned_values": {"root_module": {"resources": [{"type": "aws_db_instance"}], "child_modules": [{"resources": [{"type": "aws_rds_cluster"}]}]}}}, {"aws_db_instance", "aws_rds_cluster"}),
    ( {"planned_values": {"root_module": {}}}, set()),
    ( {}, set()),
    ( {"planned_values": {"root_module": {"resources": []}}}, set()),
    ( {"planned_values": {"root_module": {"resources": [{"type": "aws_s3_bucket"}]}}}, {"aws_s3_bucket"}),
])
def test_iter_resources_cases(plan, expected_types):
    from vectorscan import iter_resources
    res = iter_resources(plan)
    assert {r["type"] for r in res} == expected_types


@pytest.mark.parametrize("resources,expected_violations", [
    ([{"type": "aws_db_instance", "values": {"storage_encrypted": True, "kms_key_id": "abc"}}], []),
    ([{"type": "aws_db_instance", "values": {"storage_encrypted": False, "kms_key_id": "abc"}, "name": "db1"}], ["storage_encrypted"]),
    ([{"type": "aws_db_instance", "values": {"storage_encrypted": True}, "name": "db2"}], ["kms_key_id"]),
    ([{"type": "aws_s3_bucket", "values": {}}], []),
    ([{"type": "aws_db_instance", "values": {}}], ["storage_encrypted"]),
    ([{"type": "aws_rds_cluster", "values": {"storage_encrypted": False, "kms_key_id": None}, "name": "c1"}], ["storage_encrypted"]),
])
def test_check_encryption_cases(resources, expected_violations):
    from vectorscan import check_encryption
    out = check_encryption(resources)
    for v in expected_violations:
        assert any(v in msg for msg in out)
    if not expected_violations:
        assert out == []

def test__is_nonempty_string():
    from vectorscan import _is_nonempty_string
    assert _is_nonempty_string("foo")
    assert not _is_nonempty_string("")
    assert not _is_nonempty_string(None)
    assert not _is_nonempty_string("   ")


@pytest.mark.parametrize("resources,expected", [
    ([{"type": "aws_db_instance", "values": {"tags": {"CostCenter": "A", "Project": "B"}}}], []),
    ([{"type": "aws_db_instance", "values": {"tags": {"CostCenter": "", "Project": "B"}}, "name": "db1"}], ["missing/empty tag"]),
    ([{"type": "aws_db_instance", "values": {}, "name": "db2"}], ["no tags"]),
    ([{"type": "aws_lambda_function", "values": {"tags": {"CostCenter": "A", "Project": "B"}}}], []),
    ([{"type": "aws_db_instance", "values": {"tags": {}}}], ["no tags"]),
    ([{"type": "aws_db_instance", "values": {"tags": {"CostCenter": "A"}}}], ["missing/empty tag"]),
])
def test_check_tags_cases(resources, expected):
    from vectorscan import check_tags
    out = check_tags(resources)
    for v in expected:
        assert any(v in msg for msg in out)
    if not expected:
        assert out == []


def test__write_local_capture(tmp_path):
    from vectorscan import _write_local_capture
    import os
    payload = {"foo": "bar"}
    path = _write_local_capture(payload)
    assert path.exists()
    with open(path) as f:
        assert "foo" in f.read()
    os.remove(path)


def test__maybe_post():
    from vectorscan import _maybe_post
    # Should fail with invalid endpoint
    ok, info = _maybe_post("http://localhost:9999/doesnotexist", {"foo": "bar"}, timeout=1)
    assert not ok
    assert isinstance(info, str)


def test_main_smoke(tmp_path):
    from vectorscan import main
    import json as js
    f = tmp_path / "plan.json"
    f.write_text(js.dumps({"planned_values": {"root_module": {"resources": []}}}))
    code = main([str(f), "--json"])
    assert code == 0
