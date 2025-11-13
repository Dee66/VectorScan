
import pytest

# Combinatorial test: _allow_request with randomized IPs and time windows
@pytest.mark.parametrize("ip,window_offset", [
    ("10.0.0.1", 0),
    ("10.0.0.2", -100),
    ("10.0.0.3", 100),
])
def test__allow_request_randomized_window(ip, window_offset, monkeypatch):
    from lead_api import _HITS, _WINDOW_SECONDS, _allow_request
    import time
    now = int(time.time())
    _HITS[ip] = [now + window_offset for _ in range(10)]
    if window_offset < 0:
        # All hits are outside window, should allow
        assert _allow_request(ip)
    else:
        # All hits are inside window, should not allow
        assert not _allow_request(ip)
import pytest
import json
from pathlib import Path
from lead_api import save_payload, _allow_request, ViolationModel, ResultModel, LeadModel


# Parameterized and edge case tests for save_payload
import json
from pathlib import Path
from lead_api import save_payload, _allow_request, ViolationModel, ResultModel, LeadModel



@pytest.mark.parametrize("policy_id,message,resource", [
    ("P-SEC-001", "fail", "r1"),
    ("P-SEC-002", "warn", None),
    ("P-TEST", "", "res"),
    ("P-EXTRA", "extra", "extra-res"),
])
def test_violation_model_param(policy_id, message, resource):
    v = ViolationModel(policy_id=policy_id, message=message, resource=resource)
    assert v.policy_id == policy_id
    assert v.message == message
    assert v.resource == resource


@pytest.mark.parametrize("kwargs", [
    {"status": "PASS", "file": "f.json", "violations": ["v1"], "violations_struct": [ViolationModel(policy_id="P", message="m")], "counts": {"violations": 1}, "checks": ["P-SEC-001"], "vectorscan_version": "0.1.0"},
    {"status": "FAIL"},
    {"status": "PASS", "violations": []},
    {"status": "FAIL", "file": "fail2.json", "violations": ["err2"], "counts": {"violations": 3}, "checks": ["P-SEC-003"]},
    {"status": "PASS", "file": "pass2.json", "violations": [], "counts": {}, "checks": ["P-SEC-004"]},
])
def test_result_model_param(kwargs):
    r = ResultModel(**kwargs)
    assert r.status in {"PASS", "FAIL"}
    if "file" in kwargs:
        assert r.file == kwargs["file"]
    if "violations" in kwargs:
        assert r.violations == kwargs["violations"]
    if "violations_struct" in kwargs and kwargs["violations_struct"]:
        assert isinstance(r.violations_struct[0], ViolationModel)
    if "counts" in kwargs:
        assert r.counts == kwargs["counts"]
    if "checks" in kwargs:
        assert r.checks == kwargs["checks"]
    if "vectorscan_version" in kwargs:
        assert r.vectorscan_version == kwargs["vectorscan_version"]


@pytest.mark.parametrize("email,result,timestamp,source", [
    ("a@b.com", ResultModel(status="FAIL"), 123, "cli"),
    ("b@c.com", ResultModel(status="PASS"), None, None),
    ("e@f.com", ResultModel(status="PASS"), 42, "edge"),
    ("f@g.com", ResultModel(status="FAIL"), -1, "neg"),
])
def test_lead_model_param(email, result, timestamp, source):
    l = LeadModel(email=email, result=result, timestamp=timestamp, source=source)
    assert l.email == email
    assert l.result.status in {"PASS", "FAIL"}
    if timestamp is not None:
        assert l.timestamp == timestamp
    if source is not None:
        assert l.source == source


# --- Expanded and parameterized tests ---
@pytest.mark.parametrize("payload", [
    {"foo": "bar"},
    {"email": "test@example.com", "result": {"status": "PASS"}},
    {},
])
def test_save_payload_various(tmp_path, monkeypatch, payload):
    monkeypatch.setenv("LEAD_API_OUTPUT_DIR", str(tmp_path))
    out = save_payload(payload)
    assert out.exists()
    with open(out) as f:
        data = json.load(f)
        for k in payload:
            assert k in data

@pytest.mark.parametrize("ip", [
    "1.2.3.4",
    "5.6.7.8",
])
def test__allow_request_limits(ip):
    # Use the default _MAX_PER_WINDOW = 10
    from lead_api import _HITS
    _HITS[ip] = []
    for _ in range(10):
        assert _allow_request(ip)
    assert not _allow_request(ip)

def test_violation_model_edge_cases():
    v = ViolationModel(policy_id="P-SEC-002", message="warn")
    assert v.policy_id == "P-SEC-002"
    assert v.message == "warn"
    assert v.resource is None

def test_result_model_minimal():
    r = ResultModel(status="FAIL")
    assert r.status == "FAIL"
    assert r.violations == []
    assert r.counts == {}
    assert r.checks == []


def test_lead_model_invalid_email():
    with pytest.raises(Exception):
        LeadModel(email="not-an-email", result=ResultModel(status="PASS"))


# Edge: test save_payload with non-serializable object
def test_save_payload_nonserializable(tmp_path, monkeypatch):
    monkeypatch.setenv("LEAD_API_OUTPUT_DIR", str(tmp_path))
    class NotSerializable:
        pass
    payload = {"foo": NotSerializable()}
    with pytest.raises(TypeError):
        save_payload(payload)

# Edge: test _allow_request with rapid calls (simulate time window expiry)
def test__allow_request_time_window(monkeypatch):
    from lead_api import _HITS, _WINDOW_SECONDS
    import time
    ip = "9.8.7.6"
    _HITS[ip] = [int(time.time()) - _WINDOW_SECONDS - 1] * 10
    assert _allow_request(ip)

# Edge: test token auth middleware logic (unit, not integration)
def test_token_auth_env(monkeypatch):
    import os
    monkeypatch.setenv("LEAD_API_TOKEN", "secret")
    from fastapi import Request
    class DummyRequest:
        headers = {"x-api-key": "secret"}
        client = type("C", (), {"host": "1.2.3.4"})()
    # Should not raise
    from lead_api import token_auth_middleware
    import asyncio
    async def dummy_call_next(req):
        return "ok"
    req = DummyRequest()
    out = asyncio.run(token_auth_middleware(req, dummy_call_next))
    assert out == "ok"
