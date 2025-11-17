import hashlib
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "gumroad_upload_validator.py"


def _run_validator(args, env=None):
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


@pytest.mark.integration
def test_validator_accepts_matching_bundles(tmp_path):
    release = tmp_path / "release.zip"
    gumroad = tmp_path / "gumroad.zip"
    release.write_bytes(b"vectorscan bundle")
    gumroad.write_bytes(b"vectorscan bundle")
    expected = hashlib.sha256(release.read_bytes()).hexdigest()

    result = _run_validator([
        "--release-bundle",
        str(release),
        "--gumroad-bundle",
        str(gumroad),
        "--release-sha256",
        expected,
        "--gumroad-sha256",
        expected,
    ])

    assert result.returncode == 0
    assert "bundle digests match" in result.stdout


@pytest.mark.integration
def test_validator_rejects_mismatch(tmp_path):
    release = tmp_path / "release.zip"
    gumroad = tmp_path / "gumroad.zip"
    release.write_bytes(b"vectorscan bundle")
    gumroad.write_bytes(b"altered bundle")

    result = _run_validator([
        "--release-bundle",
        str(release),
        "--gumroad-bundle",
        str(gumroad),
    ])

    assert result.returncode == 3
    assert "bundles differ" in result.stderr


@pytest.mark.integration
def test_validator_cosign_success(tmp_path):
    release = tmp_path / "release.zip"
    gumroad = tmp_path / "gumroad.zip"
    release.write_bytes(b"vectorscan bundle")
    gumroad.write_bytes(b"vectorscan bundle")
    signature = tmp_path / "bundle.sig"
    signature.write_text("PASS")
    key_path = tmp_path / "cosign.pub"
    key_path.write_text("public-key")

    stub_dir = tmp_path / "stub"
    stub_dir.mkdir()
    _write_stub_cosign(stub_dir)

    env = os.environ.copy()
    env["PATH"] = f"{stub_dir}:{env.get('PATH', '')}"

    result = _run_validator([
        "--release-bundle",
        str(release),
        "--gumroad-bundle",
        str(gumroad),
        "--public-key",
        str(key_path),
        "--signature",
        str(signature),
    ], env=env)

    assert result.returncode == 0
    assert "cosign signature OK" in result.stdout


@pytest.mark.integration
def test_validator_cosign_failure(tmp_path):
    release = tmp_path / "release.zip"
    gumroad = tmp_path / "gumroad.zip"
    release.write_bytes(b"vectorscan bundle")
    gumroad.write_bytes(b"vectorscan bundle")
    signature = tmp_path / "bundle.sig"
    signature.write_text("FAIL")
    key_path = tmp_path / "cosign.pub"
    key_path.write_text("public-key")

    stub_dir = tmp_path / "stub"
    stub_dir.mkdir()
    _write_stub_cosign(stub_dir)

    env = os.environ.copy()
    env["PATH"] = f"{stub_dir}:{env.get('PATH', '')}"

    result = _run_validator([
        "--release-bundle",
        str(release),
        "--gumroad-bundle",
        str(gumroad),
        "--public-key",
        str(key_path),
        "--signature",
        str(signature),
    ], env=env)

    assert result.returncode == 4
    assert "cosign verification failed" in result.stderr