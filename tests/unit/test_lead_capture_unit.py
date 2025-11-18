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

from tools.vectorscan import vectorscan

ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = ROOT / "tools" / "vectorscan" / "vectorscan.py"

os.environ.setdefault("VSCAN_ALLOW_NETWORK", "1")


FAKE_POST_PAYLOAD: Optional[Dict[str, Any]] = None


def reset_fake_post_payload() -> None:
    global FAKE_POST_PAYLOAD
    FAKE_POST_PAYLOAD = None


def patch_urlopen(module: Any, replacement: Callable[..., Any]) -> Callable[..., Any]:
    original = module.urlopen
    setattr(cast(Any, module), "urlopen", replacement)
    return original


def run_vectorscan_cli(args) -> subprocess.CompletedProcess[bytes]:
    env = os.environ.copy()
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(ROOT), existing]))
    return subprocess.run([sys.executable, str(CLI_PATH), *args], capture_output=True, env=env)


class DummyResp:
    def __init__(self, status: int = 200) -> None:
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def fake_urlopen(req: Any, timeout: float = 1.0) -> "DummyResp":
    global FAKE_POST_PAYLOAD
    FAKE_POST_PAYLOAD = json.loads(req.data.decode("utf-8"))
    return DummyResp(201)


def run_test_pass_plan(tmp_path: Path) -> Path:
    plan: Dict[str, Any] = {"planned_values": {"root_module": {"resources": []}}}
    target = tmp_path / "tfplan-pass.json"
    target.write_text(json.dumps(plan))
    return target


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


@pytest.mark.parametrize(
    "enabled,endpoint,email,expect_post",
    [
        ("1", "https://example.com/capture", "user@example.com", True),
        ("1", "https://example.com/capture", None, True),
        ("1", None, "user@example.com", False),
        (None, "https://example.com/capture", "user@example.com", True),
        ("0", "https://example.com/capture", "user@example.com", True),
        (None, None, None, False),
    ],
)
def test_lead_capture_env_matrix(tmp_path, enabled, endpoint, email, expect_post):
    import urllib.request as ur

    plan_path = run_test_pass_plan(tmp_path)
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
        payload = FAKE_POST_PAYLOAD
        if email:
            assert payload["email"] == email
        else:
            assert "email" in payload
    else:
        assert FAKE_POST_PAYLOAD is None


def test_lead_capture_stress_many_plans(tmp_path):
    import urllib.request as ur

    plan_paths: list[Path] = []
    for i in range(20):
        plan: Dict[str, Any] = {"planned_values": {"root_module": {"resources": []}}}
        p = tmp_path / f"plan_{i}.json"
        p.write_text(json.dumps(plan))
        plan_paths.append(p)

    original = patch_urlopen(ur, fake_urlopen)
    reset_fake_post_payload()

    try:
        for idx, plan_path in enumerate(plan_paths):
            code = vectorscan.main([str(plan_path), "--email", f"user{idx}@example.com"])
            assert code in (0, 2, 3)
            if code == 0 and FAKE_POST_PAYLOAD is not None:
                assert "email" in FAKE_POST_PAYLOAD
    finally:
        ur.urlopen = original


def test_lead_capture_post_error(tmp_path):
    import urllib.request as ur

    def error_urlopen(*_, **__):
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


def test_lead_capture_deeply_nested_plan(tmp_path):
    import urllib.request as ur

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
    plan_path = tmp_path / "deep-plan.json"
    plan_path.write_text(json.dumps(plan))
    os.environ["LEAD_CAPTURE_ENABLED"] = "1"
    os.environ["VSCAN_LEAD_ENDPOINT"] = "https://example.com/capture"

    original = patch_urlopen(ur, fake_urlopen)
    reset_fake_post_payload()

    try:
        code = vectorscan.main([str(plan_path), "--email", "deep@example.com"])
    finally:
        ur.urlopen = original
        os.environ.pop("LEAD_CAPTURE_ENABLED", None)
        os.environ.pop("VSCAN_LEAD_ENDPOINT", None)

    assert code in (0, 3)
    if code == 0:
        assert FAKE_POST_PAYLOAD is not None


def test_lead_capture_network_error_handling(tmp_path):
    import urllib.request as ur

    def error_urlopen(*_: Any, **__: Any):
        raise Exception("network error")

    plan_path = run_test_pass_plan(tmp_path)
    os.environ["LEAD_CAPTURE_ENABLED"] = "1"
    os.environ["VSCAN_LEAD_ENDPOINT"] = "http://localhost:9999/doesnotexist"

    original = patch_urlopen(ur, error_urlopen)

    try:
        code = vectorscan.main([str(plan_path), "--email", "fail@example.com"])
    finally:
        ur.urlopen = original
        os.environ.pop("LEAD_CAPTURE_ENABLED", None)
        os.environ.pop("VSCAN_LEAD_ENDPOINT", None)

    assert code == 0


def test_lead_capture_with_both_flags(tmp_path):
    import urllib.request as ur

    plan_path = run_test_pass_plan(tmp_path)
    os.environ["LEAD_CAPTURE_ENABLED"] = "1"
    os.environ["VSCAN_LEAD_ENDPOINT"] = "https://example.com/capture"

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


def test_lead_capture_enabled_no_email(tmp_path):
    import urllib.request as ur

    plan_path = run_test_pass_plan(tmp_path)
    os.environ["LEAD_CAPTURE_ENABLED"] = "1"
    os.environ["VSCAN_LEAD_ENDPOINT"] = "https://example.com/capture"

    original = patch_urlopen(ur, fake_urlopen)
    reset_fake_post_payload()

    try:
        code = vectorscan.main([str(plan_path)])
    finally:
        ur.urlopen = original
        os.environ.pop("LEAD_CAPTURE_ENABLED", None)
        os.environ.pop("VSCAN_LEAD_ENDPOINT", None)

    assert code == 0
    assert FAKE_POST_PAYLOAD is not None
    assert FAKE_POST_PAYLOAD.get("email", "") == ""


def test_lead_capture_enabled_invalid_endpoint(tmp_path):
    import urllib.request as ur

    def error_urlopen(*_: Any, **__: Any):
        raise Exception("network error")

    plan_path = run_test_pass_plan(tmp_path)
    os.environ["LEAD_CAPTURE_ENABLED"] = "1"
    os.environ["VSCAN_LEAD_ENDPOINT"] = "http://localhost:9999/doesnotexist"

    original = patch_urlopen(ur, error_urlopen)

    try:
        code = vectorscan.main([str(plan_path), "--email", "fail@example.com"])
    finally:
        ur.urlopen = original
        os.environ.pop("LEAD_CAPTURE_ENABLED", None)
        os.environ.pop("VSCAN_LEAD_ENDPOINT", None)

    assert code == 0


def test_lead_capture_env_var_combinations(tmp_path):
    import urllib.request as ur

    plan_path = run_test_pass_plan(tmp_path)
    original = patch_urlopen(ur, fake_urlopen)

    combos = [
        ("1", "https://example.com/capture"),
        ("0", "https://example.com/capture"),
        ("1", None),
        (None, "https://example.com/capture"),
        (None, None),
    ]

    try:
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
                code = vectorscan.main([str(plan_path), "--email", "combo@example.com"])
            finally:
                if enabled is not None:
                    os.environ.pop("LEAD_CAPTURE_ENABLED", None)
                if endpoint is not None:
                    os.environ.pop("VSCAN_LEAD_ENDPOINT", None)

            assert code in (0, 2, 3)
    finally:
        ur.urlopen = original


def test_lead_capture_disabled(tmp_path):
    import urllib.request as ur

    plan_path = run_test_pass_plan(tmp_path)
    calls = {"n": 0}

    def blocker(*_: Any, **__: Any):
        calls["n"] += 1
        return DummyResp(200)

    original = patch_urlopen(ur, blocker)

    try:
        code = vectorscan.main([str(plan_path), "--json", "--email", "user@example.com"])
    finally:
        ur.urlopen = original

    assert code == 0
    assert calls["n"] == 0


def test_lead_capture_missing_plan(tmp_path):
    missing_path = tmp_path / "no-such-plan.json"
    result = run_vectorscan_cli([str(missing_path)])
    assert result.returncode == 2
    assert b"file not found" in result.stderr


def test_lead_capture_invalid_json(tmp_path):
    bad_path = tmp_path / "bad.json"
    bad_path.write_text("not json")
    result = run_vectorscan_cli([str(bad_path)])
    assert result.returncode == 2
    assert b"invalid JSON" in result.stderr


def test_lead_capture_skipped_in_offline_mode(tmp_path, monkeypatch):
    plan_path = run_test_pass_plan(tmp_path)
    monkeypatch.setenv("VSCAN_OFFLINE", "1")
    called = {"write": 0, "post": 0}

    def fail_write(payload):
        called["write"] += 1
        raise AssertionError("Lead capture should be disabled in offline mode")

    def fail_post(endpoint, payload, timeout=5):
        called["post"] += 1
        raise AssertionError("Lead POST should be disabled in offline mode")

    monkeypatch.setattr(vectorscan, "_write_local_capture", fail_write)
    monkeypatch.setattr(vectorscan, "_maybe_post", fail_post)

    code = vectorscan.main(
        [
            str(plan_path),
            "--lead-capture",
            "--email",
            "offline@example.com",
            "--endpoint",
            "https://example.com/capture",
        ]
    )

    assert code in (0, 3)
    assert called["write"] == 0
    assert called["post"] == 0
    monkeypatch.delenv("VSCAN_OFFLINE", raising=False)


def test_allow_network_flag_enables_post(tmp_path, monkeypatch):
    plan_path = run_test_pass_plan(tmp_path)
    monkeypatch.delenv("VSCAN_ALLOW_NETWORK", raising=False)
    monkeypatch.delenv("VSCAN_OFFLINE", raising=False)

    os.environ["LEAD_CAPTURE_ENABLED"] = "1"
    os.environ["VSCAN_LEAD_ENDPOINT"] = "https://example.com/capture"

    calls = {"post": 0}

    def fake_post(endpoint, payload, timeout=5):
        calls["post"] += 1
        return True, "ok"

    def fake_write(payload):
        target = tmp_path / "lead.json"
        target.write_text(json.dumps(payload))
        return target

    monkeypatch.setattr(vectorscan, "_maybe_post", fake_post)
    monkeypatch.setattr(vectorscan, "_write_local_capture", fake_write)

    try:
        code = vectorscan.main(
            [str(plan_path), "--lead-capture", "--email", "flag@example.com", "--allow-network"]
        )
    finally:
        os.environ.pop("LEAD_CAPTURE_ENABLED", None)
        os.environ.pop("VSCAN_LEAD_ENDPOINT", None)

    assert code == 0
    assert calls["post"] == 1


def test_allow_network_flag_required_for_post(tmp_path, monkeypatch):
    plan_path = run_test_pass_plan(tmp_path)
    monkeypatch.delenv("VSCAN_ALLOW_NETWORK", raising=False)
    monkeypatch.delenv("VSCAN_OFFLINE", raising=False)

    os.environ["LEAD_CAPTURE_ENABLED"] = "1"
    os.environ["VSCAN_LEAD_ENDPOINT"] = "https://example.com/capture"

    calls = {"post": 0}

    def fake_post(endpoint, payload, timeout=5):
        calls["post"] += 1
        return True, "ok"

    def fake_write(payload):
        target = tmp_path / "lead-2.json"
        target.write_text(json.dumps(payload))
        return target

    monkeypatch.setattr(vectorscan, "_maybe_post", fake_post)
    monkeypatch.setattr(vectorscan, "_write_local_capture", fake_write)

    try:
        code = vectorscan.main([str(plan_path), "--lead-capture", "--email", "flag@example.com"])
    finally:
        os.environ.pop("LEAD_CAPTURE_ENABLED", None)
        os.environ.pop("VSCAN_LEAD_ENDPOINT", None)

    assert code == 0
    assert calls["post"] == 0


def test_lead_capture_fail_plan(tmp_path):
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
                    {
                        "type": "aws_s3_bucket",
                        "name": "b1",
                        "values": {"tags": {}},
                    },
                ]
            }
        }
    }
    plan_path = tmp_path / "fail-plan.json"
    plan_path.write_text(json.dumps(plan))
    result = run_vectorscan_cli([str(plan_path)])
    assert result.returncode == 3
    assert b"FAIL" in result.stdout


def test_lead_capture_with_lead_capture_flag(tmp_path):
    import urllib.request as ur

    plan_path = run_test_pass_plan(tmp_path)
    os.environ["LEAD_CAPTURE_ENABLED"] = "1"
    os.environ["VSCAN_LEAD_ENDPOINT"] = "https://example.com/capture"

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


def test_write_local_capture_fallback_on_permission_error(monkeypatch, tmp_path):
    primary = Path(vectorscan.__file__).parent / "captures"
    original_mkdir = Path.mkdir

    def fake_mkdir(self, *args, **kwargs):  # pragma: no cover - monkeypatched helper
        if self == primary:
            raise PermissionError("denied")
        return original_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", fake_mkdir)
    monkeypatch.setattr(vectorscan.tempfile, "gettempdir", lambda: str(tmp_path))

    payload = {"email": "fallback@example.com", "result": {}}
    target = vectorscan._write_local_capture(payload)
    assert target.parent == Path(tmp_path) / "vectorscan-captures"
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["email"] == "fallback@example.com"
