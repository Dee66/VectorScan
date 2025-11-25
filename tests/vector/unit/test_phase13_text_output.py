"""Phase 13 tests for human-readable remediation rendering."""

import json

from click.testing import CliRunner

from vectorscan.cli import cli  # pyright: ignore[reportMissingImports]


def test_cli_text_output_shows_placeholder(tmp_path):
    runner = CliRunner()
    plan = {
        "resources": [
            {
                "type": "vector_index",
                "public_access": True,
                "encryption_enabled": True,
                "allowed_cidrs": ["10.0.0.0/8"],
                "dimension": 64,
                "address": "idx.main",
            }
        ],
        "resource_count": 1,
        "providers": ["aws"],
    }
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")

    result = runner.invoke(cli, ["scan", str(plan_path), "--no-json-output"])
    assert result.exit_code == 0
    stdout = result.output

    assert "[P-VEC-001]" in stdout
    assert "Remediation: N/A" in stdout
    assert "Fix summary: Vector index allows public queries." in stdout
