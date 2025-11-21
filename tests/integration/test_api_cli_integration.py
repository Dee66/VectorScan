import json
import os
import sys
from pathlib import Path
from typing import Any, Callable, Optional, cast

# Ensure repository root is importable for direct module imports like `lead_api`
_ROOT = Path(__file__).resolve().parents[2]
_TOOLS_VSCAN = _ROOT / "tools" / "vectorscan"
for p in (str(_ROOT), str(_TOOLS_VSCAN)):
    if p not in sys.path:
        sys.path.insert(0, p)

os.environ.setdefault("VSCAN_ALLOW_NETWORK", "1")

import pytest
from tools.vectorscan import vectorscan as vectorscan_cli


class DummyResp:
    def __init__(self, status: int = 201):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


UrlOpen = Callable[..., DummyResp]
_fake_urlopen_payload: Optional[dict[str, Any]] = None


def fake_urlopen(req, timeout=1.0):  # captures request body for assertions
    global _fake_urlopen_payload
    _fake_urlopen_payload = json.loads(req.data.decode("utf-8"))
    return DummyResp(201)


def make_plan(tmp_path: Path, resources) -> Path:
    plan = {"planned_values": {"root_module": {"resources": resources}}}
    p = tmp_path / "plan.json"
    p.write_text(json.dumps(plan))
    return p


def test_cli_to_api_lead_capture(tmp_path, monkeypatch):
    plan_path = make_plan(tmp_path, [])
    os.environ["LEAD_CAPTURE_ENABLED"] = "1"
    os.environ["VSCAN_LEAD_ENDPOINT"] = "https://example.com/capture"

    import urllib.request as ur

    original = ur.urlopen
    ur.urlopen = cast(UrlOpen, fake_urlopen)
    global _fake_urlopen_payload
    _fake_urlopen_payload = None
    try:
        code = vectorscan_cli.main([str(plan_path), "--lead-capture", "--email", "int@example.com"])
    finally:
        ur.urlopen = original
        os.environ.pop("LEAD_CAPTURE_ENABLED", None)
        os.environ.pop("VSCAN_LEAD_ENDPOINT", None)

    assert code == 0
    assert _fake_urlopen_payload is not None
    assert _fake_urlopen_payload["email"] == "int@example.com"
    assert _fake_urlopen_payload["result"]["status"] in {"PASS", "FAIL"}


def test_api_rate_limiting(monkeypatch):
    # Simulate rate limiting window filled for an IP
    import time

    from lead_api import _HITS, _allow_request

    ip = "10.1.2.3"
    now = int(time.time())
    _HITS[ip] = [now for _ in range(100)]  # many hits inside window
    assert _allow_request(ip) is False


@pytest.mark.skip(
    reason="CORS headers require running the real HTTP server; skipped in integration test"
)
def test_api_cors():
    assert True
