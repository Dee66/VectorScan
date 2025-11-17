import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "signing_key_revocation.py"


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
  echo "cosign stub: missing key" >&2
  exit 92
fi
if [[ ! -f "$SIG" ]]; then
  echo "cosign stub: missing signature" >&2
  exit 93
fi
if [[ ! -f "$TARGET" ]]; then
  echo "cosign stub: missing bundle" >&2
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


def _run_revocation(args, env=None):
    return subprocess.run(
        ["python3", str(SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=env,
    )


@pytest.mark.integration
def test_signing_key_revocation_success(tmp_path):
    bundle = tmp_path / "vectorscan-free.zip"
    bundle.write_bytes(b"bundle payload")

    revoked_key = tmp_path / "cosign-old.pub"
    revoked_key.write_text("old-key")
    replacement_key = tmp_path / "cosign-new.pub"
    replacement_key.write_text("new-key")
    replacement_sig = tmp_path / "bundle.sig"
    replacement_sig.write_text("PASS-NEW")

    log_path = tmp_path / "revocations.json"

    stub_dir = tmp_path / "stub"
    stub_dir.mkdir()
    _write_stub_cosign(stub_dir)

    env = os.environ.copy()
    env["PATH"] = f"{stub_dir}:{env.get('PATH', '')}"

    result = _run_revocation(
        [
            "--bundle",
            str(bundle),
            "--bundle-version",
            "1.2.4",
            "--revoked-key",
            str(revoked_key),
            "--replacement-key",
            str(replacement_key),
            "--replacement-signature",
            str(replacement_sig),
            "--revocation-reason",
            "compromise-incident-99",
            "--revocation-log",
            str(log_path),
            "--note",
            "pagerduty #123",
        ],
        env=env,
    )

    assert result.returncode == 0, result.stderr
    assert "revocation recorded" in result.stdout

    log = json.loads(log_path.read_text())
    assert len(log) == 1
    entry = log[0]
    assert entry["bundle_version"] == "1.2.4"
    assert entry["revoked_key_fingerprint"] is not None
    assert entry["replacement_key_fingerprint"] is not None
    assert entry["revocation_reason"] == "compromise-incident-99"
    assert entry["note"] == "pagerduty #123"


@pytest.mark.integration
def test_signing_key_revocation_fails_when_cosign_rejects(tmp_path):
    bundle = tmp_path / "vectorscan-free.zip"
    bundle.write_bytes(b"bundle payload")

    revoked_key = tmp_path / "cosign-old.pub"
    revoked_key.write_text("old-key")
    replacement_key = tmp_path / "cosign-new.pub"
    replacement_key.write_text("new-key")
    replacement_sig = tmp_path / "bundle.sig"
    replacement_sig.write_text("FAIL-NEW")

    stub_dir = tmp_path / "stub"
    stub_dir.mkdir()
    _write_stub_cosign(stub_dir)

    env = os.environ.copy()
    env["PATH"] = f"{stub_dir}:{env.get('PATH', '')}"

    result = _run_revocation(
        [
            "--bundle",
            str(bundle),
            "--bundle-version",
            "1.2.4",
            "--revoked-key",
            str(revoked_key),
            "--replacement-key",
            str(replacement_key),
            "--replacement-signature",
            str(replacement_sig),
            "--revocation-reason",
            "compromise",
        ],
        env=env,
    )

    assert result.returncode == 3
    assert "cosign verification failed" in result.stderr