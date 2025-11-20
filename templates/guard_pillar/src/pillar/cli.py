"""Command line interface for the pillar template."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import click

from .engine.loader import PlanLoader
from .engine.evaluator import PillarEvaluator


@click.group()
def cli() -> None:
    """GuardSuite pillar CLI."""


@cli.command()
@click.argument("plan", required=False, type=click.Path(exists=False))
@click.option("--json-output", "json_output", is_flag=True, help="Emit JSON output")
@click.option("--stdin", is_flag=True, help="Read plan JSON from stdin")
@click.option("--quiet", is_flag=True, help="Suppress human readable output")
@click.option("--version", is_flag=True, help="Print version and exit")
def scan(plan: Optional[str], json_output: bool, stdin: bool, quiet: bool, version: bool) -> None:
    """Run the guard against a Terraform plan."""
    loader = PlanLoader()
    evaluator = PillarEvaluator(loader)

    if version:
        click.echo("PILLAR_NAME_REPLACE_ME 0.0.0")
        return

    plan_path = Path(plan) if plan else None
    payload = json.load(click.get_text_stream("stdin")) if stdin else None
    result = evaluator.evaluate(path=plan_path, stdin_payload=payload)

    if json_output or quiet:
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo(f"Scan completed for {result['pillar']} with {len(result['issues'])} issues")
