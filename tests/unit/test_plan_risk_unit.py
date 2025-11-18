from tools.vectorscan.plan_risk import compute_plan_risk_profile


def test_plan_risk_escalates_on_critical_violations():
    result = compute_plan_risk_profile(
        severity_summary={"critical": 1},
        metrics={"compliance_score": 95},
    )
    assert result["profile"] == "critical"
    assert any("Critical" in reason for reason in result["factors"])


def test_plan_risk_accounts_for_open_security_groups():
    result = compute_plan_risk_profile(
        severity_summary={},
        metrics={"open_sg_count": 2, "compliance_score": 100},
    )
    assert result["profile"] == "medium"
    assert any("Security group" in reason for reason in result["factors"])


def test_plan_risk_accounts_for_compliance_score_drop():
    result = compute_plan_risk_profile(
        severity_summary={"low": 0},
        metrics={"compliance_score": 55},
    )
    assert result["profile"] == "high"
    assert any("Compliance score" in reason for reason in result["factors"])


def test_plan_risk_accounts_for_iam_drift_failure():
    result = compute_plan_risk_profile(
        severity_summary={},
        metrics={"compliance_score": 90, "iam_drift": {"status": "FAIL"}},
    )
    assert result["profile"] == "high"
    assert any("IAM drift" in reason for reason in result["factors"])


def test_plan_risk_accounts_for_suspicious_defaults():
    result = compute_plan_risk_profile(
        severity_summary={},
        metrics={"compliance_score": 90},
        suspicious_defaults=["aws_db_instance.default_encryption"],
    )
    assert result["profile"] == "medium"
    assert any("Suspicious" in reason for reason in result["factors"])
