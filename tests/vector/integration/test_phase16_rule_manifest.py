"""Phase 16 integration tests for rule manifest generation."""

import json

from click.testing import CliRunner

from vectorscan.cli import cli  # pyright: ignore[reportMissingImports]  # pylint: disable=import-error

EXPECTED_RULES = {
    "P-VEC-001": "critical",
    "P-VEC-002": "high",
    "P-VEC-003": "medium",
    "P-VEC-004": "low",
}


def test_rules_manifest_command_lists_all_rules():
    runner = CliRunner()
    result = runner.invoke(cli, ["rules", "--manifest"])
    assert result.exit_code == 0

    manifest = json.loads(result.output)
    manifest_by_id = {entry["id"]: entry for entry in manifest}

    for rule_id, severity in EXPECTED_RULES.items():
        assert rule_id in manifest_by_id
        entry = manifest_by_id[rule_id]
        assert entry["severity"] == severity
        assert entry["fixpack"] == f"fixpack:{rule_id}"
        assert entry["python_class"]
        assert entry["file_path"]