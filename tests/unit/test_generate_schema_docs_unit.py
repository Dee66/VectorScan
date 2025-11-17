from pathlib import Path

from scripts.generate_schema_docs import generate_schema_markdown


def test_generate_schema_docs_creates_markdown(tmp_path: Path) -> None:
    """The schema generator should render markdown with key fields and write it to disk."""
    output = tmp_path / "output_schema.md"
    content = generate_schema_markdown(output_path=output)

    assert "VectorScan Output Schema" in content
    assert "`status`" in content
    assert "`metrics.compliance_score`" in content
    assert output.exists()
    assert output.read_text(encoding="utf-8") == content
