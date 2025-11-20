"""Phase 17 regression for spec markdown generation."""

from vectorscan.tools import generate_docs  # pyright: ignore[reportMissingImports]


def test_generate_spec_md_contains_sections():
    output = generate_docs.generate_spec_md()

    assert "VectorScan v2.0" in output
    assert "## 1. Purpose & Scope" in output
    assert "**Exit Codes**" in output
    assert "- `0`" in output
    assert "No issues" in output
