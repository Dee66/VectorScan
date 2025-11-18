import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from tools.vectorscan.plan_smell import compute_smell_report


def _resource(address: str, resource_type: str, values: dict | None = None):
    return {
        "address": address,
        "type": resource_type,
        "name": address.split(".")[-1],
        "values": values or {},
    }


def test_smell_report_empty_plan_is_low():
    report = compute_smell_report(plan_metadata={}, resources=[], resource_changes=[])
    assert report["level"] == "low"
    assert report["summary"].startswith("No structural")
    assert report["smells"] == []


def test_smell_report_detects_module_depth_and_for_each():
    resources = [
        _resource("aws_s3_bucket.logs", "aws_s3_bucket"),
        _resource('module.a.module.b.module.c.aws_s3_bucket.logs["0"]', "aws_s3_bucket"),
    ]
    resources.extend(
        _resource(f"module.a.aws_s3_bucket.dynamic[{idx}]", "aws_s3_bucket") for idx in range(10)
    )
    metadata = {
        "resource_count": len(resources),
        "change_summary": {"adds": 0, "changes": 0, "destroys": 0},
    }
    report = compute_smell_report(plan_metadata=metadata, resources=resources, resource_changes=[])
    smell_ids = {smell["id"] for smell in report["smells"]}
    assert "module_depth" in smell_ids
    assert "for_each_bloat" in smell_ids
    assert report["level"] in {"moderate", "high"}


def test_smell_report_detects_missing_kms_and_large_iam():
    resources = [
        _resource("aws_rds_cluster.db", "aws_rds_cluster", {"storage_encrypted": False}),
        _resource("aws_opensearch_domain.search", "aws_opensearch_domain", {}),
    ]
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [f"s3:Action{i}" for i in range(60)],
                "Resource": "*",
            }
        ],
    }
    resource_changes = [
        {
            "type": "aws_iam_policy",
            "change": {
                "after": {
                    "policy": json.dumps(policy_doc),
                }
            },
        }
    ]
    report = compute_smell_report(
        plan_metadata={
            "resource_count": len(resources),
            "change_summary": {"adds": 0, "changes": 1, "destroys": 0},
        },
        resources=resources,
        resource_changes=resource_changes,
    )
    smell_ids = {smell["id"] for smell in report["smells"]}
    assert "missing_kms_key" in smell_ids
    assert "iam_policy_bulk" in smell_ids
    assert report["level"] == "high"


def test_smell_report_flags_large_change_volume():
    metadata = {"change_summary": {"adds": 20, "changes": 25, "destroys": 10}}
    report = compute_smell_report(plan_metadata=metadata, resources=[], resource_changes=[])
    smell_ids = {smell["id"] for smell in report["smells"]}
    assert "change_volume" in smell_ids
    evidence = next(
        smell["evidence"] for smell in report["smells"] if smell["id"] == "change_volume"
    )
    assert evidence["change_total"] == 55
    assert report["level"] == "high"
