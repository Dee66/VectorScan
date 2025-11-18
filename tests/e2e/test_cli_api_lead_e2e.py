import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start_uvicorn(app_obj, host: str, port: int):
    import uvicorn

    config = uvicorn.Config(app_obj, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)

    def run_server():
        # uvicorn.Server.run() is blocking; run in a thread
        server.run()

    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()
    return server, thread


@pytest.mark.e2e
def test_cli_lead_capture_success(tmp_path):
    repo_root = Path(__file__).resolve().parents[2]
    plan_path = repo_root / "examples" / "aws-pgvector-rag" / "tfplan-pass.json"
    cli_path = repo_root / "tools" / "vectorscan" / "vectorscan.py"

    # Spin up lead API with custom output dir
    api_output_dir = tmp_path / "captures_api"
    api_output_dir.mkdir(parents=True, exist_ok=True)
    os.environ["LEAD_API_OUTPUT_DIR"] = str(api_output_dir)

    port = _find_free_port()
    host = "127.0.0.1"
    # Ensure repo root is on sys.path so we can import the app module
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    from tools.vectorscan.lead_api import app

    server, thread = _start_uvicorn(app, host, port)

    # Give the server a moment to start
    time.sleep(0.8)

    endpoint = f"http://{host}:{port}/lead"

    # Run CLI with lead-capture and endpoint
    env = os.environ.copy()
    cmd = [
        sys.executable,
        str(cli_path),
        str(plan_path),
        "--lead-capture",
        "--email",
        "user@example.com",
        "--endpoint",
        endpoint,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, env=env)

    # Stop server (best-effort): uvicorn doesn't expose a clean shutdown here; daemon thread will end at process exit
    # Validate CLI output
    out = (result.stdout or "") + (result.stderr or "")
    assert result.returncode in (0, 3)  # PASS/FAIL acceptable
    assert "Lead payload saved:" in out
    assert "Lead POST => HTTP" in out and "OK" in out

    # Validate local backup capture exists
    local_dir = repo_root / "tools" / "vectorscan" / "captures"
    captures = list(local_dir.glob("lead_*.json"))
    assert len(captures) >= 1

    # Validate API stored file exists in tmp output dir
    api_files = list(api_output_dir.glob("lead_*.json"))
    assert len(api_files) >= 1
    # Basic schema check
    with api_files[-1].open() as f:
        data = json.load(f)
        assert data.get("email") == "user@example.com"
        assert isinstance(data.get("result", {}), dict)


@pytest.mark.e2e
def test_cli_lead_capture_http_failure(tmp_path):
    repo_root = Path(__file__).resolve().parents[2]
    plan_path = repo_root / "examples" / "aws-pgvector-rag" / "tfplan-pass.json"
    cli_path = repo_root / "tools" / "vectorscan" / "vectorscan.py"

    # Endpoint points to unused port → HTTP failure
    port = _find_free_port()
    endpoint = f"http://127.0.0.1:{port}/lead"

    env = os.environ.copy()
    cmd = [
        sys.executable,
        str(cli_path),
        str(plan_path),
        "--lead-capture",
        "--email",
        "user2@example.com",
        "--endpoint",
        endpoint,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, env=env)

    out = (result.stdout or "") + (result.stderr or "")
    assert result.returncode in (0, 3)
    assert "Lead payload saved:" in out
    # HTTP failure path prints exception text; still should include SKIP/FAIL
    assert "Lead POST =>" in out and ("SKIP/FAIL" in out or "HTTP" in out)

    # Local backup should exist
    local_dir = repo_root / "tools" / "vectorscan" / "captures"
    captures = list(local_dir.glob("lead_*.json"))
    assert len(captures) >= 1
