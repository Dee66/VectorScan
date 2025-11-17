import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_gumroad_email.py"
EMAIL = ROOT / "docs" / "gumroad_delivery_email.md"


def _run(args):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )


@pytest.mark.integration
def test_email_checker_accepts_template():
    result = _run(["--email-file", str(EMAIL)])
    assert result.returncode == 0
    assert "verification instructions" in result.stdout


@pytest.mark.integration
def test_email_checker_detects_missing_sha256(tmp_path):
    broken = tmp_path / "email.md"
    text = EMAIL.read_text(encoding="utf-8").replace("sha256sum -c", "sha-sum")
    broken.write_text(text, encoding="utf-8")

    result = _run(["--email-file", str(broken)])
    assert result.returncode == 3
    assert "sha256" in result.stderr
