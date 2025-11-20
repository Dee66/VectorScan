"""Phase 17 regression for schema markdown generation."""

from vectorscan.tools import generate_docs  # pyright: ignore[reportMissingImports]


def test_generate_schema_md_contains_tables():
    output = generate_docs.generate_schema_md()

    assert "# VectorScan Output Schema" in output
    assert "## Top-Level Required Keys" in output
    assert "| `pillar` |" in output
    assert "## Issue Object Requirements" in output
    assert "| `id` |" in output
    assert "## Nested Structures" in output
