import random
import tempfile
from typing import Callable, cast

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

FakeGlob = Callable[[str], list[str]]
FakePrint = Callable[..., None]


# Property-based test: load_json with random valid/invalid JSON and encodings
@given(
    content=st.one_of(
        st.text(),
        st.binary(),
        st.just(""),
        st.just('{"foo": 1}'),
        st.just("not json"),
    )
)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=30)
def test_load_json_property_varied(tmp_path, content):
    from aggregate_metrics import load_json

    f = tmp_path / f"rand_{random.randint(0, 100000)}.json"
    # Write as text or binary depending on type
    if isinstance(content, str):
        f.write_text(content, encoding="utf-8", errors="ignore")
    else:
        f.write_bytes(content)
    try:
        load_json(f)
    except Exception:
        pass


# Property-based test: extract_result with random dicts/lists
@given(
    obj=st.one_of(
        st.dictionaries(
            st.text(),
            st.integers() | st.text() | st.none() | st.lists(st.integers() | st.text() | st.none()),
            max_size=5,
        ),
        st.lists(st.integers() | st.text() | st.none(), max_size=5),
        st.none(),
    )
)
def test_extract_result_property_varied(obj):
    from aggregate_metrics import extract_result

    try:
        extract_result(obj)
    except Exception:
        pass


# Combinatorial test: main with many files and mixed results
def test_main_stress_mixed(tmp_path):
    import glob

    from aggregate_metrics import main

    files = []
    for i in range(50):
        status = "PASS" if i % 2 == 0 else "FAIL"
        f = tmp_path / f"file_{i}.json"
        f.write_text(
            json.dumps(
                {"status": status, "violations": [] if status == "PASS" else [f"P-SEC-{i:03d}"]}
            ),
            encoding="utf-8",
        )
        files.append(f)
    orig_glob = glob.glob
    glob.glob = cast(FakeGlob, lambda g: [str(f) for f in files])
    import builtins

    out = []
    orig_print = builtins.print
    builtins.print = cast(FakePrint, lambda *a, **k: out.append(" ".join(map(str, a))))
    code = main(["--glob", str(files[0])])
    builtins.print = orig_print
    glob.glob = orig_glob
    assert any("PASS" in line for line in out)
    assert any("FAIL" in line for line in out)
    assert code == 1


# Negative test: main with unreadable files
def test_main_unreadable_files(tmp_path):
    import glob

    from aggregate_metrics import main

    files = []
    for i in range(3):
        f = tmp_path / f"unreadable_{i}.json"
        f.write_text(json.dumps({"status": "PASS", "violations": []}), encoding="utf-8")
        f.chmod(0o000)
        files.append(f)
    orig_glob = glob.glob
    glob.glob = cast(FakeGlob, lambda g: [str(f) for f in files])
    import builtins

    out = []
    orig_print = builtins.print
    builtins.print = cast(FakePrint, lambda *a, **k: out.append(" ".join(map(str, a))))
    try:
        code = main(["--glob", str(files[0])])
    finally:
        for f in files:
            f.chmod(0o644)
        builtins.print = orig_print
        glob.glob = orig_glob
    assert code == 0 or code == 1


# Edge test: main with deeply nested results
def test_main_deeply_nested(tmp_path):
    import glob

    from aggregate_metrics import main

    f = tmp_path / "deep.json"
    deep = {"result": {"status": "PASS", "violations": [], "extra": {"nested": {"level": 5}}}}
    f.write_text(json.dumps(deep), encoding="utf-8")
    orig_glob = glob.glob
    glob.glob = cast(FakeGlob, lambda g: [str(f)])
    import builtins

    out = []
    orig_print = builtins.print
    builtins.print = cast(FakePrint, lambda *a, **k: out.append(" ".join(map(str, a))))
    code = main(["--glob", str(f)])
    builtins.print = orig_print
    glob.glob = orig_glob
    assert any("PASS" in line for line in out)
    assert code == 0 or code == 1


from hypothesis import given
from hypothesis import strategies as st


# Property-based test for load_json: any valid JSON string should parse without error
@given(
    st.dictionaries(
        st.text(),
        st.integers() | st.text() | st.none() | st.lists(st.integers() | st.text() | st.none()),
        max_size=5,
    )
)
def test_load_json_property(content):
    with tempfile.NamedTemporaryFile("w+", delete=True, suffix=".json") as f:
        f.write(json.dumps(content))
        f.flush()
        from pathlib import Path

        assert load_json(Path(f.name)) == content


# Property-based test for extract_result: should return None for objects without 'result' or with None
@given(
    st.dictionaries(
        st.text(),
        st.integers() | st.text() | st.none() | st.lists(st.integers() | st.text() | st.none()),
        max_size=5,
    )
)
def test_extract_result_property(obj):
    if "result" not in obj or obj.get("result") is None:
        assert extract_result(obj) is None


# Negative test: unreadable file (permission error)
def test_load_json_permission_error(tmp_path):
    f = tmp_path / "no_read.json"
    f.write_text('{"foo": 1}')
    f.chmod(0o000)
    try:
        assert load_json(f) is None
    finally:
        f.chmod(0o644)


# Negative test: file with invalid encoding
def test_load_json_invalid_encoding(tmp_path):
    f = tmp_path / "badenc.json"
    f.write_bytes(b"\xff\xfe\xfd")
    assert load_json(f) is None


# Combinatorial test: multiple files with mixed PASS/FAIL/invalid
def test_main_mixed_files(tmp_path):
    f1 = tmp_path / "pass.json"
    f2 = tmp_path / "fail.json"
    f3 = tmp_path / "bad.json"
    f1.write_text(json.dumps({"status": "PASS", "violations": []}))
    f2.write_text(json.dumps({"status": "FAIL", "violations": ["P-SEC-001"]}))
    f3.write_text("not json")
    import glob

    orig_glob = glob.glob
    glob.glob = cast(FakeGlob, lambda g: [str(f1), str(f2), str(f3)])
    import builtins

    out = []
    orig_print = builtins.print
    builtins.print = cast(FakePrint, lambda *a, **k: out.append(" ".join(map(str, a))))
    code = main(["--glob", str(f1)])
    builtins.print = orig_print
    glob.glob = orig_glob
    assert any("PASS" in line for line in out)
    assert any("FAIL" in line for line in out)
    assert code == 1


import json

import pytest

from aggregate_metrics import extract_result, load_json, main


# Parameterized tests for load_json
@pytest.mark.parametrize(
    "content,expected",
    [
        (json.dumps({"foo": 1}), {"foo": 1}),
        ("not json", None),
        ("", None),
        ("123", 123),
        (json.dumps([1, 2, 3]), [1, 2, 3]),
        (json.dumps({"result": {"status": "PASS"}}), {"result": {"status": "PASS"}}),
        (
            json.dumps({"status": "FAIL", "violations": ["P-SEC-001"]}),
            {"status": "FAIL", "violations": ["P-SEC-001"]},
        ),
        (json.dumps({"unexpected": True}), {"unexpected": True}),
        (json.dumps(None), None),
    ],
)
def test_load_json_cases(tmp_path, content, expected):
    f = tmp_path / "test.json"
    f.write_text(content)
    assert load_json(f) == expected


# Parameterized tests for extract_result
@pytest.mark.parametrize(
    "obj,expected",
    [
        ({"result": {"status": "PASS", "violations": []}}, {"status": "PASS", "violations": []}),
        (
            {"status": "FAIL", "violations": ["P-SEC-001: ..."]},
            {"status": "FAIL", "violations": ["P-SEC-001: ..."]},
        ),
        ({}, None),
        ([], None),
        (None, None),
        ({"result": None}, None),
        ({"status": "PASS"}, None),
        ({"violations": []}, None),
        (
            {"result": {"status": "FAIL", "violations": ["P-SEC-002"]}},
            {"status": "FAIL", "violations": ["P-SEC-002"]},
        ),
        ({"result": {"status": "PASS"}}, {"status": "PASS"}),
        ({"result": {"violations": []}}, {"violations": []}),
    ],
)
def test_extract_result_cases(obj, expected):
    assert extract_result(obj) == expected


def test_main_summary(tmp_path):
    # Create two files: one PASS, one FAIL
    f1 = tmp_path / "pass.json"
    f2 = tmp_path / "fail.json"
    f1.write_text(json.dumps({"status": "PASS", "violations": []}), encoding="utf-8")
    f2.write_text(
        json.dumps({"status": "FAIL", "violations": ["P-SEC-001: ..."]}), encoding="utf-8"
    )
    import glob

    orig_glob = glob.glob
    glob.glob = cast(FakeGlob, lambda g: [str(f1), str(f2)])
    import builtins

    out = []
    orig_print = builtins.print
    builtins.print = cast(FakePrint, lambda *a, **k: out.append(" ".join(map(str, a))))
    code = main(["--glob", str(f1)])
    builtins.print = orig_print
    glob.glob = orig_glob
    assert any("PASS" in line for line in out)
    assert any("FAIL" in line for line in out)
    assert code == 1


def test_main_no_files(tmp_path):
    # Simulate no files found by glob
    import glob

    orig_glob = glob.glob
    glob.glob = cast(FakeGlob, lambda g: [])
    import builtins

    out = []
    orig_print = builtins.print
    builtins.print = cast(FakePrint, lambda *a, **k: out.append(" ".join(map(str, a))))
    code = main(["--glob", "nonexistent.json"])
    builtins.print = orig_print
    glob.glob = orig_glob
    assert "Runs: 0" in " ".join(out)
    assert code == 0


def test_main_out_file(tmp_path):
    # Test writing metrics JSON to file
    f1 = tmp_path / "pass.json"
    f1.write_text(json.dumps({"status": "PASS", "violations": []}), encoding="utf-8")
    out_file = tmp_path / "metrics.json"
    import glob

    orig_glob = glob.glob
    glob.glob = cast(FakeGlob, lambda g: [str(f1)])
    import builtins

    orig_print = builtins.print
    builtins.print = cast(FakePrint, lambda *a, **k: None)
    result_code = main(["--glob", str(f1), "--out", str(out_file)])
    builtins.print = orig_print
    glob.glob = orig_glob
    assert out_file.exists()
    data = json.loads(out_file.read_text())
    assert data["runs"] == 1
    assert data["pass"] == 1
    assert data["fail"] == 0
    assert result_code == 0
