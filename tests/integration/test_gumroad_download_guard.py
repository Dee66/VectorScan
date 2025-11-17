import hashlib
import hashlib
import http.server
import json
import socketserver
import subprocess
import sys
import threading
from contextlib import contextmanager
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "gumroad_download_guard.py"


class FlakyHandler(http.server.BaseHTTPRequestHandler):
    body = b"vectorscan"
    fail_until = 0
    call_count = 0

    def do_GET(self):
        type(self).call_count += 1
        if type(self).call_count <= type(self).fail_until:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"error")
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(type(self).body)))
        self.end_headers()
        self.wfile.write(type(self).body)

    def log_message(self, format, *args):  # pragma: no cover - silence server logs
        return


@contextmanager
def run_server(handler_cls):
    with socketserver.TCPServer(("127.0.0.1", 0), handler_cls) as httpd:
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            port = httpd.server_address[1]
            yield f"http://127.0.0.1:{port}/file"
        finally:
            httpd.shutdown()
            thread.join()


def _run(args):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )


@pytest.mark.integration
def test_download_guard_success(tmp_path):
    FlakyHandler.body = b"demo-bytes"
    FlakyHandler.fail_until = 0
    FlakyHandler.call_count = 0
    digest = hashlib.sha256(FlakyHandler.body).hexdigest()
    with run_server(FlakyHandler) as url:
        output = tmp_path / "bundle.bin"
        metrics = tmp_path / "metrics.json"
        result = _run([
            "--download-url",
            url,
            "--output",
            str(output),
            "--metrics-file",
            str(metrics),
            "--sha256",
            digest,
            "--delay",
            "0.1",
        ])
    assert result.returncode == 0, result.stderr
    assert output.read_bytes() == FlakyHandler.body
    data = json.loads(metrics.read_text())
    assert data["status"] == "SUCCESS"
    assert data["attempts"] == 1
    assert data["downloaded_bytes"] == len(FlakyHandler.body)


@pytest.mark.integration
def test_download_guard_retries_then_succeeds(tmp_path):
    FlakyHandler.body = b"retry-bytes"
    FlakyHandler.fail_until = 1
    FlakyHandler.call_count = 0
    digest = hashlib.sha256(FlakyHandler.body).hexdigest()
    with run_server(FlakyHandler) as url:
        output = tmp_path / "bundle.bin"
        metrics = tmp_path / "metrics.json"
        result = _run([
            "--download-url",
            url,
            "--output",
            str(output),
            "--metrics-file",
            str(metrics),
            "--sha256",
            digest,
            "--retries",
            "3",
            "--delay",
            "0.1",
        ])
    assert result.returncode == 0, result.stderr
    data = json.loads(metrics.read_text())
    assert data["attempts"] == 2
    assert len(data["errors"]) == 1
    assert data["status"] == "SUCCESS"


@pytest.mark.integration
def test_download_guard_reports_failure(tmp_path):
    FlakyHandler.body = b"never"
    FlakyHandler.fail_until = 5
    FlakyHandler.call_count = 0
    with run_server(FlakyHandler) as url:
        output = tmp_path / "bundle.bin"
        metrics = tmp_path / "metrics.json"
        result = _run([
            "--download-url",
            url,
            "--output",
            str(output),
            "--metrics-file",
            str(metrics),
            "--retries",
            "2",
            "--delay",
            "0.05",
        ])
    assert result.returncode == 6
    data = json.loads(metrics.read_text())
    assert data["status"] == "FAILURE"
    assert len(data["errors"]) == 2