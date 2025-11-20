from click.testing import CliRunner

from vectorscan.cli import cli


def test_cli_runs_without_plan(tmp_path):
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(tmp_path / "plan.json"), "--json-output"])
    assert result.exit_code == 0
