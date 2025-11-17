import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "signing_key_rotation.py"


def _write_stub_cosign(directory: Path) -> Path:
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

if [[ ! -f "$KEY" ]]; then
  echo "cosign stub: key missing" >&2
  exit 92
fi
if [[ ! -f "$SIG" ]]; then
  echo "cosign stub: signature missing" >&2
  exit 93
fi
if [[ ! -f "$TARGET" ]]; then
  echo "cosign stub: bundle missing" >&2
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


def _run_rotation(args, env=None):
    return subprocess.run(
        ["python3", str(SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=env,
    )


@pytest.mark.integration
def test_signing_key_rotation_success(tmp_path):
    bundle = tmp_path / "vectorscan-free.zip"
    bundle.write_bytes(b"bundle payload")

    new_key = tmp_path / "cosign-new.pub"
    new_key.write_text("new-key")
    new_signature = tmp_path / "bundle.sig"
    new_signature.write_text("PASS-NEW")

    old_key = tmp_path / "cosign-old.pub"
    old_key.write_text("old-key")
    old_signature = tmp_path / "bundle.sig.old"
    old_signature.write_text("PASS-OLD")

    log_path = tmp_path / "rotation_log.json"

    stub_dir = tmp_path / "stub"
    stub_dir.mkdir()
    _write_stub_cosign(stub_dir)

    env = os.environ.copy()
    env["PATH"] = f"{stub_dir}:{env.get('PATH', '')}"

    result = _run_rotation(
        [
            "--bundle",
            str(bundle),
            "--bundle-version",
            "1.2.3",
            "--new-key",
            str(new_key),
            "--new-signature",
            str(new_signature),
            "--old-key",
            str(old_key),
            "--old-signature",
            str(old_signature),
            "--rotation-log",
            str(log_path),
            "--note",
            "2025-Q1-rotation",
        ],
        env=env,
    )

    assert result.returncode == 0, result.stderr
    assert "rotation recorded" in result.stdout

    log = json.loads(log_path.read_text())
    assert len(log) == 1
    entry = log[0]
    assert entry["bundle_version"] == "1.2.3"
    assert entry["new_key_fingerprint"] is not None
    assert entry["old_key_fingerprint"] is not None
    assert entry["rotation_note"] == "2025-Q1-rotation"


@pytest.mark.integration
def test_signing_key_rotation_fails_when_new_key_invalid(tmp_path):
    bundle = tmp_path / "vectorscan-free.zip"
    bundle.write_bytes(b"bundle payload")

    new_key = tmp_path / "cosign-new.pub"
    new_key.write_text("new-key")
    new_signature = tmp_path / "bundle.sig"
    new_signature.write_text("FAIL-NEW")

    log_path = tmp_path / "rotation_log.json"

    stub_dir = tmp_path / "stub"
    stub_dir.mkdir()
    _write_stub_cosign(stub_dir)

    env = os.environ.copy()
    env["PATH"] = f"{stub_dir}:{env.get('PATH', '')}"

    result = _run_rotation(
        [
            "--bundle",
            str(bundle),
            "--bundle-version",
            "9.9.9",
            "--new-key",
            str(new_key),
            "--new-signature",
            str(new_signature),
            "--rotation-log",
            str(log_path),
        ],
        env=env,
    )

    assert result.returncode == 3
    assert "cosign verification failed" in result.stderr
    assert not log_path.exists()
