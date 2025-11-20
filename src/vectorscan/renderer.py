"""Rendering helpers for pillar output."""

from __future__ import annotations

from typing import Dict, Any

from rich.console import Console

console = Console()


def render_summary(result: Dict[str, Any]) -> None:
    issues = result.get("issues", [])
    console.print(f"[bold]Pillar:[/bold] {result['pillar']}")
    console.print(f"[bold]Issues:[/bold] {len(issues)}")
