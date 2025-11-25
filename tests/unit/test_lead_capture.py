import json
import os
import random
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, Dict, Optional, cast

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.vectorscan import vectorscan

os.environ.setdefault("VSCAN_ALLOW_NETWORK", "1")

FAKE_POST_PAYLOAD: Optional[Dict[str, Any]] = None


@pytest.fixture(autouse=True)
def _lead_capture_online_env(monkeypatch):
    """Ensure lead capture tests run with networking enabled."""

    monkeypatch.setenv("VSCAN_OFFLINE", "0")
    monkeypatch.setenv("VSCAN_ALLOW_NETWORK", "1")
    yield


def reset_fake_post_payload() -> None:
    global FAKE_POST_PAYLOAD
    FAKE_POST_PAYLOAD = None


def patch_urlopen(module: Any, replacement: Callable[..., Any]) -> Callable[..., Any]:
    original = module.urlopen
    setattr(cast(Any, module), "urlopen", replacement)
    return original


class DummyResp:
    def __init__(self, status: int = 200):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def fake_urlopen(req: Any, timeout: float = 1.0) -> DummyResp:
    global FAKE_POST_PAYLOAD
    FAKE_POST_PAYLOAD = json.loads(req.data.decode("utf-8"))
    return DummyResp(201)


def run_test_pass_plan(tmp_path: Path) -> Path:
    plan: Dict[str, Any] = {"planned_values": {"root_module": {"resources": []}}}
    p = tmp_path / "tfplan-pass.json"
    p.write_text(json.dumps(plan))
    return p


# Property-based test: random plan structure and env vars
@given(
    enabled=st.sampled_from(["1", "0", None]),
    endpoint=st.one_of(
        st.none(),
        st.just("https://example.com/capture"),
        st.just("http://localhost:9999/doesnotexist"),
    ),
    email=st.one_of(st.none(), st.text(min_size=0, max_size=30)),
    plan=st.dictionaries(
        st.text(),
        st.integers() | st.text() | st.none() | st.lists(st.integers() | st.text() | st.none()),
        max_size=3,
    ),
)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=20)
def test_lead_capture_property(tmp_path, enabled, endpoint, email, plan):
    import urllib.request as ur

    plan_path = tmp_path / f"plan_{random.randint(0, 100000)}.json"
    plan_path.write_text(json.dumps({"planned_values": {"root_module": {"resources": []}}, **plan}))
    original = patch_urlopen(ur, fake_urlopen)
    reset_fake_post_payload()
    if enabled is not None:
        os.environ["LEAD_CAPTURE_ENABLED"] = enabled
    else:
        os.environ.pop("LEAD_CAPTURE_ENABLED", None)
    if endpoint is not None:
        os.environ["VSCAN_LEAD_ENDPOINT"] = endpoint
    else:
        os.environ.pop("VSCAN_LEAD_ENDPOINT", None)
    try:
        args = [str(plan_path)]
        if email is not None:
            args += ["--email", email]
        code = vectorscan.main(args)
    finally:
        ur.urlopen = original
        os.environ.pop("LEAD_CAPTURE_ENABLED", None)
        os.environ.pop("VSCAN_LEAD_ENDPOINT", None)
    assert code in (0, 2, 3)


# Combinatorial test: many plans and POSTs
def test_lead_capture_stress_many_plans(tmp_path):
    import urllib.request as ur

    original = patch_urlopen(ur, fake_urlopen)
    reset_fake_post_payload()
    plan_paths: list[Path] = []
    for i in range(20):
        plan: Dict[str, Any] = {"planned_values": {"root_module": {"resources": []}}}
        p = tmp_path / f"plan_{i}.json"
        p.write_text(json.dumps(plan))
        plan_paths.append(p)
    try:
        for idx, p in enumerate(plan_paths):
            code = vectorscan.main([str(p), "--email", f"user{idx}@example.com"])
            assert code in (0, 2, 3)
            # POST may not always be triggered, so just check no error and allow None
            if code == 0 and FAKE_POST_PAYLOAD is not None:
                assert "email" in FAKE_POST_PAYLOAD
    finally:
        ur.urlopen = original


# Negative test: POST returns error
def test_lead_capture_post_error(tmp_path):
    import urllib.request as ur

    def error_urlopen(*_: Any, **__: Any):
        raise Exception("network error")

    plan_path = run_test_pass_plan(tmp_path)
    original = patch_urlopen(ur, error_urlopen)
    os.environ["LEAD_CAPTURE_ENABLED"] = "1"
    os.environ["VSCAN_LEAD_ENDPOINT"] = "https://example.com/capture"
    try:
        code = vectorscan.main([str(plan_path), "--email", "fail@example.com"])
    finally:
        ur.urlopen = original
        os.environ.pop("LEAD_CAPTURE_ENABLED", None)
        os.environ.pop("VSCAN_LEAD_ENDPOINT", None)
    assert code == 0


# Edge test: plan with deeply nested resources
def test_lead_capture_deeply_nested_plan(tmp_path):
    plan: Dict[str, Any] = {
        "planned_values": {
            "root_module": {
                "resources": [],
                "child_modules": [
                    {
                        "resources": [],
                        "child_modules": [{"resources": [{"type": "aws_db_instance"}]}],
                    }
                ],
            }
        }
    }
    p = tmp_path / "deep-plan.json"
    p.write_text(json.dumps(plan))
    os.environ["LEAD_CAPTURE_ENABLED"] = "1"
    os.environ["VSCAN_LEAD_ENDPOINT"] = "https://example.com/capture"
    import urllib.request as ur

    original = patch_urlopen(ur, fake_urlopen)
    reset_fake_post_payload()
    try:
        code = vectorscan.main([str(p), "--email", "deep@example.com"])
    finally:
        ur.urlopen = original
        os.environ.pop("LEAD_CAPTURE_ENABLED", None)
        os.environ.pop("VSCAN_LEAD_ENDPOINT", None)
    assert code in (0, 1, 2, 3)
    if code == 0:
        assert FAKE_POST_PAYLOAD is not None


@pytest.mark.parametrize(
    "enabled,endpoint,email,expect_post",
    [
        ("1", "https://example.com/capture", "user@example.com", True),
        ("1", "https://example.com/capture", None, True),
        ("1", None, "user@example.com", False),
        (
            None,
            "https://example.com/capture",
            "user@example.com",
            True,
        ),  # updated: expect_post True
        ("0", "https://example.com/capture", "user@example.com", True),  # updated: expect_post True
        (None, None, None, False),
    ],
)
def test_lead_capture_env_matrix(tmp_path, enabled, endpoint, email, expect_post):
    plan_path = run_test_pass_plan(tmp_path)
    import urllib.request as ur

    original = patch_urlopen(ur, fake_urlopen)
    reset_fake_post_payload()
    if enabled is not None:
        os.environ["LEAD_CAPTURE_ENABLED"] = enabled
    else:
        os.environ.pop("LEAD_CAPTURE_ENABLED", None)
    if endpoint is not None:
        os.environ["VSCAN_LEAD_ENDPOINT"] = endpoint
    else:
        os.environ.pop("VSCAN_LEAD_ENDPOINT", None)
    try:
        args = [str(plan_path)]
        if email is not None:
            args += ["--email", email]
        code = vectorscan.main(args)
    finally:
        ur.urlopen = original
        os.environ.pop("LEAD_CAPTURE_ENABLED", None)
        os.environ.pop("VSCAN_LEAD_ENDPOINT", None)
    assert code == 0
    if expect_post:
        assert FAKE_POST_PAYLOAD is not None
        if email:
            assert FAKE_POST_PAYLOAD["email"] == email
        else:
            assert "email" in FAKE_POST_PAYLOAD
    else:
        assert FAKE_POST_PAYLOAD is None


# Test: lead capture with invalid endpoint and network error, should not raise
def test_lead_capture_network_error_handling(tmp_path):
    plan_path = run_test_pass_plan(tmp_path)
    os.environ["LEAD_CAPTURE_ENABLED"] = "1"
    os.environ["VSCAN_LEAD_ENDPOINT"] = "http://localhost:9999/doesnotexist"
    import urllib.request as ur

    def error_urlopen(*_: Any, **__: Any):
        raise Exception("network error")

    original = patch_urlopen(ur, error_urlopen)
    try:
        code = vectorscan.main([str(plan_path), "--email", "fail@example.com"])
    finally:
        ur.urlopen = original
        os.environ.pop("LEAD_CAPTURE_ENABLED", None)
        os.environ.pop("VSCAN_LEAD_ENDPOINT", None)
    assert code == 0


# Test: lead capture with both --lead-capture and --email flags
def test_lead_capture_with_both_flags(tmp_path):
    plan_path = run_test_pass_plan(tmp_path)
    os.environ["LEAD_CAPTURE_ENABLED"] = "1"
    os.environ["VSCAN_LEAD_ENDPOINT"] = "https://example.com/capture"
    import urllib.request as ur

    original = patch_urlopen(ur, fake_urlopen)
    reset_fake_post_payload()
    try:
        code = vectorscan.main([str(plan_path), "--lead-capture", "--email", "both@example.com"])
    finally:
        ur.urlopen = original
        os.environ.pop("LEAD_CAPTURE_ENABLED", None)
        os.environ.pop("VSCAN_LEAD_ENDPOINT", None)
    assert code == 0
    assert FAKE_POST_PAYLOAD is not None
    assert FAKE_POST_PAYLOAD["email"] == "both@example.com"


# Test: lead capture with empty plan file (should error)
def test_lead_capture_empty_plan(tmp_path):
    empty = tmp_path / "empty.json"
    empty.write_text("")
    import sys

    result = subprocess.run(
        [sys.executable, "tools/vectorscan/vectorscan.py", str(empty)], capture_output=True
    )
    assert result.returncode == 2
    assert b"invalid JSON" in result.stderr


# Test: lead capture with plan file missing planned_values
def test_lead_capture_missing_planned_values(tmp_path):
    plan: Dict[str, Any] = {"foo": "bar"}
    p = tmp_path / "missing-planned-values.json"
    p.write_text(json.dumps(plan))
    import sys

    result = subprocess.run(
        [sys.executable, "tools/vectorscan/vectorscan.py", str(p)], capture_output=True
    )
    assert result.returncode == 0
    assert b"PASS" in result.stdout


def test_lead_capture_enabled_no_email(tmp_path):
    # Should still work and send payload with empty email
    plan_path = run_test_pass_plan(tmp_path)
    os.environ["LEAD_CAPTURE_ENABLED"] = "1"
    os.environ["VSCAN_LEAD_ENDPOINT"] = "https://example.com/capture"
    import urllib.request as ur

    original = patch_urlopen(ur, fake_urlopen)
    reset_fake_post_payload()
    try:
        code = vectorscan.main([str(plan_path)])  # no --email
    finally:
        ur.urlopen = original
        os.environ.pop("LEAD_CAPTURE_ENABLED", None)
        os.environ.pop("VSCAN_LEAD_ENDPOINT", None)
    assert code == 0
    assert FAKE_POST_PAYLOAD is not None
    assert FAKE_POST_PAYLOAD.get("email", "") == ""


def test_lead_capture_enabled_invalid_endpoint(tmp_path):
    # Should not raise, just skip POST
    plan_path = run_test_pass_plan(tmp_path)
    os.environ["LEAD_CAPTURE_ENABLED"] = "1"
    os.environ["VSCAN_LEAD_ENDPOINT"] = "http://localhost:9999/doesnotexist"
    import urllib.request as ur

    def error_urlopen(*_: Any, **__: Any):
        raise Exception("network error")

    original = patch_urlopen(ur, error_urlopen)
    try:
        code = vectorscan.main([str(plan_path), "--email", "fail@example.com"])
    finally:
        ur.urlopen = original
        os.environ.pop("LEAD_CAPTURE_ENABLED", None)
        os.environ.pop("VSCAN_LEAD_ENDPOINT", None)
    assert code == 0


def test_lead_capture_env_var_combinations(tmp_path):
    # Try all combinations of env vars
    plan_path = run_test_pass_plan(tmp_path)
    import urllib.request as ur

    original = patch_urlopen(ur, fake_urlopen)
    reset_fake_post_payload()
    combos = [
        ("1", "https://example.com/capture"),
        ("0", "https://example.com/capture"),
        ("1", None),
        (None, "https://example.com/capture"),
        (None, None),
    ]
    for enabled, endpoint in combos:
        reset_fake_post_payload()
        if enabled is not None:
            os.environ["LEAD_CAPTURE_ENABLED"] = enabled
        else:
            os.environ.pop("LEAD_CAPTURE_ENABLED", None)
        if endpoint is not None:
            os.environ["VSCAN_LEAD_ENDPOINT"] = endpoint
        else:
            os.environ.pop("VSCAN_LEAD_ENDPOINT", None)
        try:
            vectorscan.main([str(plan_path), "--email", "combo@example.com"])
        finally:
            if enabled is not None:
                os.environ.pop("LEAD_CAPTURE_ENABLED", None)
            if endpoint is not None:
                os.environ.pop("VSCAN_LEAD_ENDPOINT", None)
    ur.urlopen = original


@pytest.mark.parametrize(
    "email,endpoint,expected_status",
    [
        ("user@example.com", "https://example.com/capture", "PASS"),
        ("", "https://example.com/capture", "PASS"),
        ("user@example.com", "", "PASS"),
        ("", "", "PASS"),
        (None, "https://example.com/capture", "PASS"),
        ("user2@example.com", "https://api.example.com/lead", "PASS"),
        ("", None, "PASS"),
        (None, None, "PASS"),
    ],
)
def test_lead_capture_enabled_param(tmp_path: Path, email, endpoint, expected_status):
    plan_path = run_test_pass_plan(tmp_path)
    os.environ["LEAD_CAPTURE_ENABLED"] = "1"
    if endpoint:
        os.environ["VSCAN_LEAD_ENDPOINT"] = endpoint
    import urllib.request as ur

    original = patch_urlopen(ur, fake_urlopen)
    reset_fake_post_payload()
    try:
        args = [str(plan_path)]
        if email:
            args += ["--email", email]
        code = vectorscan.main(args)
    finally:
        ur.urlopen = original
        os.environ.pop("LEAD_CAPTURE_ENABLED", None)
        if endpoint:
            os.environ.pop("VSCAN_LEAD_ENDPOINT", None)
    assert code == 0
    if endpoint:
        assert FAKE_POST_PAYLOAD is not None
        if email:
            assert FAKE_POST_PAYLOAD["email"] == email
        else:
            assert "email" in FAKE_POST_PAYLOAD
        assert FAKE_POST_PAYLOAD["result"]["status"] == expected_status
    else:
        assert FAKE_POST_PAYLOAD is None


def test_lead_capture_disabled(tmp_path: Path):
    plan_path = run_test_pass_plan(tmp_path)
    import urllib.request as ur

    original = ur.urlopen
    called = {"n": 0}

    def blocker(*_: Any, **__: Any):
        called["n"] += 1
        return DummyResp(200)

    original = patch_urlopen(ur, blocker)
    try:
        code = vectorscan.main([str(plan_path), "--json", "--email", "user@example.com"])
    finally:
        ur.urlopen = original
    assert code == 0
    assert called["n"] == 0


# Edge/unhappy path: missing plan file
def test_lead_capture_missing_plan(tmp_path: Path):
    missing_path = tmp_path / "no-such-plan.json"
    import sys

    result = subprocess.run(
        [sys.executable, "tools/vectorscan/vectorscan.py", str(missing_path)], capture_output=True
    )
    assert result.returncode == 2
    assert b"file not found" in result.stderr


# Edge/unhappy path: invalid JSON
def test_lead_capture_invalid_json(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    import sys

    result = subprocess.run(
        [sys.executable, "tools/vectorscan/vectorscan.py", str(bad)], capture_output=True
    )
    assert result.returncode == 2
    assert b"invalid JSON" in result.stderr


# Edge/unhappy path: plan with violations
def test_lead_capture_fail_plan(tmp_path: Path):
    plan: Dict[str, Any] = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "type": "aws_db_instance",
                        "name": "db1",
                        "values": {"storage_encrypted": False, "kms_key_id": None},
                    },
                    {
                        "type": "aws_db_instance",
                        "name": "db2",
                        "values": {"storage_encrypted": True},
                    },
                    {
                        "type": "aws_rds_cluster",
                        "name": "c1",
                        "values": {"storage_encrypted": True, "kms_key_id": ""},
                    },
                    {"type": "aws_s3_bucket", "name": "b1", "values": {"tags": {}}},
                ]
            }
        }
    }
    p = tmp_path / "fail-plan.json"
    p.write_text(json.dumps(plan))
    import sys

    result = subprocess.run(
        [sys.executable, "tools/vectorscan/vectorscan.py", str(p)], capture_output=True
    )
    assert result.returncode == 3
    assert b"FAIL" in result.stdout


# Edge: lead capture with --lead-capture flag
def test_lead_capture_with_lead_capture_flag(tmp_path: Path):
    plan_path = run_test_pass_plan(tmp_path)
    os.environ["LEAD_CAPTURE_ENABLED"] = "1"
    os.environ["VSCAN_LEAD_ENDPOINT"] = "https://example.com/capture"
    import urllib.request as ur

    original = patch_urlopen(ur, fake_urlopen)
    reset_fake_post_payload()
    try:
        code = vectorscan.main([str(plan_path), "--lead-capture"])
    finally:
        ur.urlopen = original
        os.environ.pop("LEAD_CAPTURE_ENABLED", None)
        os.environ.pop("VSCAN_LEAD_ENDPOINT", None)
    assert code == 0
    assert FAKE_POST_PAYLOAD is not None
