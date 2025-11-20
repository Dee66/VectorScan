"""Phase 14 tests for severity summary rendering."""

import json

from click.testing import CliRunner

from vectorscan.cli import cli  # pyright: ignore[reportMissingImports]


def test_cli_text_output_includes_severity_summary(tmp_path):
    runner = CliRunner()
    plan = {
        "resources": [
            {
                "type": "vector_index",
                "public_access": True,
                "encryption_enabled": False,
                "allowed_cidrs": ["0.0.0.0/0"],
                "dimension": 64,
                "address": "idx.severity",
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

    assert "Summary:" in stdout
    assert "critical: 1" in stdout
    assert "medium: 1" in stdout
