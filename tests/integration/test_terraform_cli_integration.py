import os
import sys
import json
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "tools" / "vectorscan" / "vectorscan.py"
PASS_PLAN = ROOT / "examples" / "aws-pgvector-rag" / "tfplan-pass.json"


def run(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def _parse_trailing_json(text: str):
    """Extract the trailing JSON object from mixed stdout+JSON output.
    Finds the last '{' and attempts to parse from there.
    """
    idx = text.rfind("{")
    assert idx != -1, f"no JSON object found in output: {text[:200]}..."
    return json.loads(text[idx:])


def test_terraform_tests_error_no_download(capsys, monkeypatch):
    # Monkeypatch run_terraform_tests to simulate an ERROR (e.g., no terraform and downloads disabled)
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    import tools.vectorscan.vectorscan as vs

    def fake_run_terraform_tests(override_bin, auto_download):
        return {
            "status": "ERROR",
            "message": "Terraform CLI not found and auto-download disabled.",
            "version": None,
            "binary": None,
            "source": None,
            "strategy": "base",
            "stdout": "",
            "stderr": "",
        }

    monkeypatch.setattr(vs, "run_terraform_tests", fake_run_terraform_tests)
    code = vs.main([str(PASS_PLAN), "--json", "--terraform-tests"])  # type: ignore
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["terraform_tests"]["status"] == "ERROR"
    assert data["status"] == "FAIL"
    assert code == 5


def test_terraform_tests_fail_integration(capsys, monkeypatch):
    # Monkeypatch run_terraform_tests to simulate a FAIL
    # Ensure repo root import works
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    import tools.vectorscan.vectorscan as vs

    def fake_run_terraform_tests(override_bin, auto_download):
        return {
            "status": "FAIL",
            "returncode": 1,
            "stdout": "",
            "stderr": "",
            "version": "1.8.0",
            "binary": "/fake/bin/terraform",
            "source": "system",
            "strategy": "modern",
        }

    monkeypatch.setattr(vs, "run_terraform_tests", fake_run_terraform_tests)
    code = vs.main([str(PASS_PLAN), "--json", "--terraform-tests"])  # type: ignore
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["terraform_tests"]["status"] == "FAIL"
    assert data["status"] == "FAIL"  # FAIL bubbles up when tests fail
    assert code == 4


def test_terraform_tests_skip_legacy(capsys, monkeypatch):
    # Monkeypatch run_terraform_tests to simulate a SKIP (legacy)
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    import tools.vectorscan.vectorscan as vs

    def fake_run_terraform_tests(override_bin, auto_download):
        return {
            "status": "SKIP",
            "message": "legacy terraform",
            "version": "1.0.0",
            "binary": "/fake/bin/terraform",
            "source": "system",
            "strategy": "legacy-skip",
        }

    monkeypatch.setattr(vs, "run_terraform_tests", fake_run_terraform_tests)
    code = vs.main([str(PASS_PLAN), "--json", "--terraform-tests"])  # type: ignore
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["terraform_tests"]["status"] == "SKIP"
    assert data["status"] == "PASS"
    assert code == 0
