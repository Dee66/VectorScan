"""Canonical CLI scaffolding for VectorScan."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import click

from .evaluator import build_fatal_error_output, run_scan
from .renderer import render_human_readable, render_severity_summary

# TODO Phase 2: wire real evaluator
# TODO Phase 3: integrate rule registry
# TODO Phase 4: attach fixpack lookup


@click.group()
def cli() -> None:
    """VectorScan pillar CLI (stub)."""


@cli.command()
@click.argument("plan", required=False, type=click.Path(path_type=Path))
@click.option(
    "--json-output/--no-json-output",
    "json_output",
    default=True,
    help="Emit canonical JSON output",
)
@click.option("--stdin", is_flag=True, help="Read plan JSON from stdin")
@click.option("--quiet", is_flag=True, help="Suppress scan output")
def scan(plan: Optional[Path], json_output: bool, stdin: bool, quiet: bool) -> None:
    """Execute a placeholder scan that returns the canonical shape."""

    if plan and not plan.exists() and not stdin:
        result = build_fatal_error_output(f"Plan not found: {plan}")
        if not quiet and json_output:
            click.echo(json.dumps(result, indent=2))
        elif not quiet:
            click.echo(
                f"Scan failed for {result['pillar']}: {result['schema_validation_error']}"
            )
        raise click.exceptions.Exit(2)

    plan_dict, source_path, raw_size = _load_plan_payload(plan, stdin)
    result = run_scan(plan=plan_dict, source_path=source_path, raw_size=raw_size)
    # Issues may now include remediation_metadata alongside remediation_hint.

    if quiet:
        return

    if json_output:
        click.echo(json.dumps(result, indent=2))
    else:
        summary_text = render_severity_summary(result)
        issues_text = render_human_readable(result)
        click.echo(f"{summary_text}\n{issues_text}")


def _load_plan_payload(
    plan: Optional[Path],
    stdin: bool,
) -> Tuple[Dict[str, Any], Optional[Path], Optional[int]]:
    if stdin and plan is not None:
        raise click.UsageError("Provide a plan path or --stdin, but not both.")

    if stdin:
        text = click.get_text_stream("stdin").read()
        payload = json.loads(text) if text else {}
        size_hint = len(text.encode("utf-8")) if text else None
        return payload, None, size_hint

    if plan is not None:
        if not plan.exists():
            raise click.UsageError(f"Plan path {plan} does not exist")
        raw_bytes = plan.read_bytes()
        return json.loads(raw_bytes), plan, len(raw_bytes)

    return {}, None, None
