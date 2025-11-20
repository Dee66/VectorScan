"""Integration test ensuring CLI surfaces remediation metadata."""

import json

from click.testing import CliRunner

from vectorscan.cli import cli  # pyright: ignore[reportMissingImports]


def test_cli_emits_fixpack_metadata(tmp_path):
    runner = CliRunner()
    plan = {
        "resources": [
            {
                "type": "vector_index",
                "public_access": True,
                "encryption_enabled": True,
                "allowed_cidrs": ["10.0.0.0/8"],
                "dimension": 64,
                "address": "idx.public",
            }
        ],
        "resource_count": 1,
        "providers": ["aws"],
    }
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")

    result = runner.invoke(cli, ["scan", str(plan_path), "--json-output"])
    assert result.exit_code == 0
    payload = json.loads(result.output)

    assert payload["issues"], "Expected at least one issue"
    metadata = payload["issues"][0].get("remediation_metadata")
    assert metadata is not None
    assert metadata["fixpack_id"] == "P-VEC-001"
    assert metadata["description"]
    assert "public_access" in metadata["terraform_patch"]
