import functools
import hashlib
import os
import subprocess
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "release_artifact_verifier.py"


def _run(args, env=None):
    return subprocess.run(
        ["python3", str(SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=env,
    )


def _write_stub_cosign(directory: Path):
    script = directory / "cosign"
    script.write_text(
        """#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -lt 1 ]]; then
  echo "cosign stub: missing command" >&2
  exit 90
fi

if [[ "$1" != "verify-blob" ]]; then
  echo "cosign stub: unexpected command $1" >&2
  exit 91
fi
shift

KEY=""
SIG=""
TARGET=""
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --key)
      KEY="$2"
      shift 2
      ;;
    --signature)
      SIG="$2"
      shift 2
      ;;
    *)
      TARGET="$1"
      shift
      ;;
  esac
 done

if [[ -z "$TARGET" ]]; then
  echo "cosign stub: missing blob" >&2
  exit 92
fi
if [[ ! -f "$KEY" ]]; then
  echo "cosign stub: missing key" >&2
  exit 93
fi
if [[ ! -f "$SIG" ]]; then
  echo "cosign stub: missing signature" >&2
  exit 94
fi

if grep -q "FAIL" "$SIG"; then
  echo "cosign stub: forced failure" >&2
  exit 1
fi

echo "cosign stub: verification ok"
exit 0
"""
    )
    script.chmod(0o755)
    return script


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):  # pragma: no cover - noise suppression
        return


@pytest.fixture()
def http_server(tmp_path):
    handler = functools.partial(QuietHandler, directory=str(tmp_path))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    try:
        yield tmp_path, base_url
    finally:
        server.shutdown()
        thread.join()


@pytest.mark.integration
def test_release_verifier_success(http_server):
    directory, base_url = http_server
    artifact = directory / "artifact.zip"
    artifact.write_bytes(b"vectorguard release artifact")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    (directory / "artifact.sig").write_text("PASS")

    sha_file = directory / "artifact.sha256"
    sha_file.write_text(f"{digest}  artifact.zip\n")
    key_path = directory / "cosign.pub"
    key_path.write_text("public-key")

    stub_dir = directory / "stub"
    stub_dir.mkdir()
    _write_stub_cosign(stub_dir)

    env = os.environ.copy()
    env["PATH"] = f"{stub_dir}:{env.get('PATH', '')}"

    result = _run(
        [
            "--artifact-url",
            f"{base_url}/artifact.zip",
            "--signature-url",
            f"{base_url}/artifact.sig",
            "--expected-sha256",
            digest,
            "--public-key",
            str(key_path),
        ],
        env=env,
    )

    assert result.returncode == 0
    assert "release-verifier: validation complete" in result.stdout
    assert "cosign signature OK" in result.stdout


@pytest.mark.integration
def test_release_verifier_mismatch(http_server):
    directory, base_url = http_server
    artifact = directory / "artifact.zip"
    artifact.write_bytes(b"vectorguard release artifact")
    wrong_digest = hashlib.sha256(b"different").hexdigest()

    result = _run(
        [
            "--artifact-url",
            f"{base_url}/artifact.zip",
            "--expected-sha256",
            wrong_digest,
        ]
    )

    assert result.returncode == 3
    assert "SHA256 mismatch" in result.stderr


@pytest.mark.integration
def test_release_verifier_cosign_failure(http_server):
    directory, base_url = http_server
    artifact = directory / "artifact.zip"
    artifact.write_bytes(b"vectorguard release artifact")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    (directory / "artifact.sig").write_text("FAIL")

    key_path = directory / "cosign.pub"
    key_path.write_text("public-key")

    stub_dir = directory / "stub"
    stub_dir.mkdir()
    _write_stub_cosign(stub_dir)

    env = os.environ.copy()
    env["PATH"] = f"{stub_dir}:{env.get('PATH', '')}"

    result = _run(
        [
            "--artifact-url",
            f"{base_url}/artifact.zip",
            "--signature-url",
            f"{base_url}/artifact.sig",
            "--expected-sha256",
            digest,
            "--public-key",
            str(key_path),
        ],
        env=env,
    )

    assert result.returncode == 4
    assert "cosign verification failed" in result.stderr
