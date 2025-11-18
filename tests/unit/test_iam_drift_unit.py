import json


def make_plan(resource_changes):
    return {"resource_changes": resource_changes}


def test_iam_drift_detects_risky_added_action():
    from vectorscan import build_iam_drift_report

    before_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}],
        }
    )
    after_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject", "s3:DeleteObject"], "Resource": "*"}
            ],
        }
    )
    rc = [
        {
            "type": "aws_iam_policy",
            "name": "agent_read",
            "change": {
                "actions": ["update"],
                "before": {"policy": before_policy},
                "after": {"policy": after_policy},
            },
        }
    ]
    report = build_iam_drift_report(make_plan(rc))
    assert report["status"] == "FAIL"
    assert report["counts"]["risky_changes"] == 1
    assert any("s3:DeleteObject" in a for item in report["items"] for a in item["risky_additions"])


def test_iam_drift_pass_when_no_risky_additions():
    from vectorscan import build_iam_drift_report

    after_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}],
        }
    )
    rc = [
        {
            "type": "aws_iam_policy",
            "name": "agent_read",
            "change": {"actions": ["update"], "before": None, "after": {"policy": after_policy}},
        }
    ]
    report = build_iam_drift_report(make_plan(rc))
    assert report["status"] == "PASS"
    assert report["counts"]["risky_changes"] == 0
