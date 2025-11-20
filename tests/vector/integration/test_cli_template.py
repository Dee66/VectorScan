import json

from click.testing import CliRunner

from vectorscan.cli import cli  # pyright: ignore[reportMissingImports]


def test_cli_runs_without_plan(tmp_path):
    runner = CliRunner()
    missing_plan = tmp_path / "plan.json"
    result = runner.invoke(cli, ["scan", str(missing_plan), "--json-output"])
    assert result.exit_code == 2
    payload = json.loads(result.output)
    assert payload["schema_validation_error"].startswith("Plan not found")
