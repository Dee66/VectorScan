import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from tests.helpers.plan_helpers import write_plan
from tools.vectorscan import vectorscan as vs


def _empty_plan():
    return {"planned_values": {"root_module": {"resources": []}}}


def _load_json_output(raw: str) -> dict:
    start = raw.find("{")
    assert start >= 0, "JSON payload missing"
    return json.loads(raw[start:])


def test_cli_includes_terraform_tests_payload(monkeypatch, tmp_path, capsys):
    plan_path = write_plan(tmp_path, _empty_plan())
    long_stdout = "x" * 4100

    def fake_run(override_bin, auto_download):
        assert override_bin is None
        assert auto_download is True
        return {
            "status": "PASS",
            "version": "1.5.7",
            "binary": "/usr/bin/terraform",
            "source": "system",
            "strategy": "modern",
            "stdout": long_stdout,
            "stderr": "terraform stderr sample",
            "message": "Terraform tests executed",
            "returncode": 0,
        }

    monkeypatch.setattr(vs, "run_terraform_tests", fake_run)

    capsys.readouterr()
    code = vs.main([str(plan_path), "--json", "--terraform-tests"])
    captured = capsys.readouterr()

    assert code == 0, captured.err
    payload = _load_json_output(captured.out)
    block = payload["terraform_tests"]
    assert block["status"] == "PASS"
    assert block["version"] == "1.5.7"
    assert block["source"] == "system"
    assert block["strategy"] == "modern"
    assert block["stdout"].endswith("... (truncated)")
    assert block["stderr"] == "terraform stderr sample"
    env_block = payload["environment"]
    assert env_block["terraform_version"] == "1.5.7"
    assert env_block["terraform_source"] == "system"


def test_cli_exit_code_5_when_terraform_tests_fail(monkeypatch, tmp_path, capsys):
    plan_path = write_plan(tmp_path, _empty_plan())

    def fake_run(_override_bin, _auto_download):
        return {
            "status": "FAIL",
            "version": "1.5.7",
            "binary": "/usr/bin/terraform",
            "source": "system",
            "strategy": "modern",
            "stdout": "failure logs",
            "stderr": "oops",
            "message": "tests failed",
            "returncode": 1,
        }

    monkeypatch.setattr(vs, "run_terraform_tests", fake_run)

    capsys.readouterr()
    code = vs.main([str(plan_path), "--json", "--terraform-tests"])
    captured = capsys.readouterr()

    assert code == vs.EXIT_TERRAFORM_FAIL
    data = _load_json_output(captured.out)
    assert data["status"] == "FAIL"
    assert data["terraform_tests"]["status"] == "FAIL"


def test_cli_exit_code_6_when_terraform_tests_error(monkeypatch, tmp_path, capsys):
    plan_path = write_plan(tmp_path, _empty_plan())

    def fake_run(_override_bin, _auto_download):
        return {
            "status": "ERROR",
            "version": "1.5.7",
            "binary": "/usr/bin/terraform",
            "source": "download",
            "strategy": "modern",
            "stdout": "",
            "stderr": "unable to run",
            "message": "execution error",
            "returncode": None,
        }

    monkeypatch.setattr(vs, "run_terraform_tests", fake_run)

    capsys.readouterr()
    code = vs.main([str(plan_path), "--json", "--terraform-tests"])
    captured = capsys.readouterr()

    assert code == vs.EXIT_TERRAFORM_ERROR
    data = _load_json_output(captured.out)
    assert data["status"] == "FAIL"
    assert data["terraform_tests"]["status"] == "ERROR"
