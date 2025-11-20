"""Phase 15 tests for summary percentages and badge state."""

import json

from click.testing import CliRunner

from vectorscan.cli import cli  # pyright: ignore[reportMissingImports]


def test_cli_summary_includes_percentages_and_badge(tmp_path):
    runner = CliRunner()
    plan = {
        "resources": [
            {
                "type": "vector_index",
                "public_access": True,
                "encryption_enabled": True,
                "allowed_cidrs": ["10.0.0.0/8"],
                "dimension": 64,
                "address": "idx.crit",
            },
            {
                "type": "vector_index",
                "public_access": False,
                "encryption_enabled": True,
                "allowed_cidrs": ["10.0.0.0/8"],
                "dimension": 8,
                "address": "idx.low",
            },
        ],
        "resource_count": 2,
        "providers": ["aws"],
    }
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")

    result = runner.invoke(cli, ["scan", str(plan_path), "--no-json-output"])
    assert result.exit_code == 0
    stdout = result.output

    # Two issues total: one critical, one low → 50% each
    assert "critical: 1 (50%)" in stdout
    assert "low: 1 (50%)" in stdout
    assert "badge_eligible: false" in stdout
