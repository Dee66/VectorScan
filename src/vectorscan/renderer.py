"""Human-readable rendering helpers for VectorScan CLI output."""

from __future__ import annotations

from typing import Dict, List


def render_human_readable(output: Dict[str, object]) -> str:
    """Return a deterministic text block describing scan issues."""

    issues = output.get("issues") or []
    lines: List[str] = []

    title = f"Scan completed for {output.get('pillar', 'VectorScan')}"
    lines.append(title)
    lines.append("-")

    if not issues:
        lines.append("No issues detected.")
        return "\n".join(lines)

    for issue in issues:
        lines.extend(_render_issue_block(issue))

    return "\n".join(lines)


def _render_issue_block(issue: Dict[str, object]) -> List[str]:
    block: List[str] = []
    issue_id = issue.get("id", "UNKNOWN")
    title = issue.get("title", "")
    severity = issue.get("severity", "unknown")
    block.append(f"[{issue_id}] {title} ({severity})")
    resource = issue.get("resource_address") or "-"
    block.append(f"  Resource: {resource}")
    remediation_hint = issue.get("remediation_hint") or "N/A"
    block.append(f"  Remediation: {remediation_hint}")

    metadata = issue.get("remediation_metadata")
    if isinstance(metadata, dict):
        summary = metadata.get("description") or ""
        if summary:
            block.append(f"  Fix summary: {summary}")
        patch = metadata.get("terraform_patch")
        if patch:
            block.append("  Terraform patch:")
            block.extend(_indent_patch(patch))
    else:
        description = issue.get("description")
        if description:
            block.append(f"  Fix summary: {description}")
    return block


def _indent_patch(patch: object) -> List[str]:
    text = str(patch)
    lines = text.splitlines() or [text]
    return [f"    {line}" for line in lines]
