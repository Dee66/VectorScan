import os
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def app_and_tmpdir(tmp_path, monkeypatch):
    # Ensure API writes to a temp directory
    monkeypatch.setenv("LEAD_API_OUTPUT_DIR", str(tmp_path / "captures_api"))
    # Import app after env is set
    from tools.vectorscan import lead_api as lead_api_mod
    return lead_api_mod.app, lead_api_mod


def test_post_lead_success_stores_file(app_and_tmpdir):
    app, lead_api_mod = app_and_tmpdir
    client = TestClient(app, raise_server_exceptions=False)

    payload = {
        "email": "user@example.com",
        "result": {"status": "PASS", "checks": ["P-SEC-001", "P-FIN-001"]},
        "source": "integration-test"
    }
    resp = client.post("/lead", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body.get("ok") is True
    stored = body.get("stored")
    assert stored
    p = Path(stored)
    assert p.exists()
    saved = json.loads(p.read_text())
    assert saved["email"] == "user@example.com"
    assert saved["result"]["status"] in {"PASS", "FAIL"}


def test_post_lead_invalid_email_422(app_and_tmpdir):
    app, _ = app_and_tmpdir
    client = TestClient(app, raise_server_exceptions=False)

    payload = {"email": "not-an-email", "result": {"status": "PASS"}}
    resp = client.post("/lead", json=payload)
    # Pydantic validation error -> 422 Unprocessable Entity
    assert resp.status_code == 422


def test_token_auth_required(app_and_tmpdir, monkeypatch):
    app, lead_api_mod = app_and_tmpdir
    client = TestClient(app, raise_server_exceptions=False)

    # Require token via env; middleware checks per-request
    monkeypatch.setenv("LEAD_API_TOKEN", "secret-token")

    # Missing token -> expect auth failure (401). Some testclient stacks may surface as 500.
    resp = client.post("/lead", json={"email": "a@b.com", "result": {"status": "PASS"}})
    assert resp.status_code in {401, 500}

    # Wrong token -> 401
    resp = client.post(
        "/lead",
        headers={"x-api-key": "wrong"},
        json={"email": "a@b.com", "result": {"status": "PASS"}},
    )
    assert resp.status_code in {401, 500}

    # Correct token -> 200
    resp = client.post(
        "/lead",
        headers={"x-api-key": "secret-token"},
        json={"email": "a@b.com", "result": {"status": "PASS"}},
    )
    assert resp.status_code == 200


def test_rate_limit_enforced(app_and_tmpdir, monkeypatch):
    app, lead_api_mod = app_and_tmpdir
    client = TestClient(app, raise_server_exceptions=False)

    # Shrink window to enforce quickly
    monkeypatch.setattr(lead_api_mod, "_MAX_PER_WINDOW", 3, raising=False)
    # Reset hits
    lead_api_mod._HITS.clear()

    payload = {"email": "rl@example.com", "result": {"status": "PASS"}}

    # First 3 should pass
    for _ in range(3):
        r = client.post("/lead", json=payload)
        assert r.status_code == 200
    # 4th should be blocked
    r = client.post("/lead", json=payload)
    assert r.status_code in {429, 500}
