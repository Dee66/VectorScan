import hashlib
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
VERIFY_SCRIPT = ROOT / "scripts" / "verify.sh"


def _run_verify(args, env=None):
    result = subprocess.run(
        ["bash", str(VERIFY_SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=env,
    )
    return result

def _write_stub_cosign(directory: Path):
    script = directory / "cosign"
    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        'if [[ "$#" -lt 1 ]]; then',
        '  echo "cosign stub: missing command" >&2',
        "  exit 99",
        "fi",
        "",
        'if [[ "$1" != "verify-blob" ]]; then',
        '  echo "cosign stub: unexpected command $1" >&2',
        "  exit 98",
        "fi",
        "shift",
        "",
        'KEY=""',
        'SIG=""',
        'TARGET=""',
        'while [[ "$#" -gt 0 ]]; do',
        '  case "$1" in',
        '    --key)',
        '      KEY="$2"',
        '      shift 2',
        '      ;;',
        '    --signature)',
        '      SIG="$2"',
        '      shift 2',
        '      ;;',
        '    *)',
        '      TARGET="$1"',
        '      shift',
        '      ;;',
        '  esac',
        'done',
        "",
        'if [[ -z "$TARGET" ]]; then',
        '  echo "cosign stub: missing target" >&2',
        "  exit 97",
        "fi",
        'if [[ ! -f "$KEY" ]]; then',
        '  echo "cosign stub: missing key" >&2',
        "  exit 96",
        "fi",
        'if [[ ! -f "$SIG" ]]; then',
        '  echo "cosign stub: missing signature" >&2',
        "  exit 95",
        "fi",
        'if [[ ! -f "$TARGET" ]]; then',
        '  echo "cosign stub: missing blob" >&2',
        "  exit 94",
        "fi",
        "",
        'if grep -q "FAIL" "$SIG"; then',
        '  echo "cosign stub: forced failure" >&2',
        "  exit 1",
        "fi",
        "",
        'echo "cosign stub: verification ok"',
        "exit 0",
    ]
    script.write_text("\n".join(lines) + "\n")
    script.chmod(0o755)
    return script


@pytest.mark.integration
def test_verify_sha256_only(tmp_path):
    bundle = tmp_path / "bundle.zip"
    bundle.write_bytes(b"vector-scan-test")
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()

    result = _run_verify(["-f", str(bundle), "-h", digest])

    assert result.returncode == 0
    assert "SHA256 OK" in result.stdout


@pytest.mark.integration
def test_verify_cosign_success(tmp_path):
    bundle = tmp_path / "bundle.zip"
    bundle.write_bytes(b"bundle-bytes")
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    signature = Path(f"{bundle}.sig")
    signature.write_text("PASS")
    key_path = tmp_path / "cosign.pub"
    key_path.write_text("public-key-placeholder")

    stub_dir = tmp_path / "stub"
    stub_dir.mkdir()
    _write_stub_cosign(stub_dir)

    env = os.environ.copy()
    env["PATH"] = f"{stub_dir}:{env.get('PATH', '')}"

    result = _run_verify(["-f", str(bundle), "-h", digest, "-k", str(key_path)], env=env)

    assert result.returncode == 0
    assert "Cosign signature OK" in result.stdout


@pytest.mark.integration
def test_verify_cosign_failure(tmp_path):
    bundle = tmp_path / "bundle.zip"
    bundle.write_bytes(b"bundle-bytes")
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    signature = Path(f"{bundle}.sig")
    signature.write_text("FAIL")
    key_path = tmp_path / "cosign.pub"
    key_path.write_text("public-key-placeholder")

    stub_dir = tmp_path / "stub"
    stub_dir.mkdir()
    _write_stub_cosign(stub_dir)

    env = os.environ.copy()
    env["PATH"] = f"{stub_dir}:{env.get('PATH', '')}"

    result = _run_verify(["-f", str(bundle), "-h", digest, "-k", str(key_path)], env=env)

    assert result.returncode == 4
    assert "Cosign signature verification FAILED" in result.stderr