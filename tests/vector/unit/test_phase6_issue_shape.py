"""Phase 6 tests for canonical issue factory."""

from src.vectorscan.rules.base import build_issue


def test_issue_factory_shape():
    issue = build_issue(
        "P-VEC-TEST",
        "medium",
        "Test",
        "Desc",
        "aws_resource.example",
        {"k": "v"},
    )
    assert set(issue.keys()) == {
        "id",
        "severity",
        "title",
        "description",
        "resource_address",
        "attributes",
        "remediation_hint",
        "remediation_difficulty",
    }
