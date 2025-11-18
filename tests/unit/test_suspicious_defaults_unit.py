from tools.vectorscan.suspicious_defaults import detect_suspicious_defaults


def _resource(r_type, name, values, address=None):
    return {
        "type": r_type,
        "name": name,
        "address": address or f"{r_type}.{name}",
        "values": values,
    }


def test_detects_rds_encryption_default():
    plan = {}
    resources = [
        _resource(
            "aws_rds_cluster",
            "db",
            {"storage_encrypted": False},
        )
    ]
    findings = detect_suspicious_defaults(plan, resources)
    assert len(findings) == 1
    assert findings[0]["reason"].startswith("storage_encrypted")


def test_detects_security_group_open_ingress():
    plan = {}
    resources = [
        _resource(
            "aws_security_group",
            "sg",
            {"ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]},
        )
    ]
    findings = detect_suspicious_defaults(plan, resources)
    assert findings and "ingress" in findings[0]["reason"]


def test_detects_opensearch_encryption_and_node_to_node():
    plan = {}
    resources = [
        _resource(
            "aws_opensearch_domain",
            "search",
            {
                "encrypt_at_rest": {"enabled": False},
                "node_to_node_encryption": False,
            },
        )
    ]
    findings = detect_suspicious_defaults(plan, resources)
    reasons = {item["reason"] for item in findings}
    assert "encrypt_at_rest disabled (defaults to false)" in reasons
    assert "node-to-node encryption disabled" in reasons


def test_detects_s3_public_configuration():
    plan = {}
    resources = [
        _resource(
            "aws_s3_bucket",
            "bucket",
            {
                "acl": "public-read",
            },
        )
    ]
    findings = detect_suspicious_defaults(plan, resources)
    assert any("ACL" in f["reason"] for f in findings)
    assert any("Public access block" in f["reason"] for f in findings)


def test_resource_changes_are_evaluated():
    plan = {
        "resource_changes": [
            {
                "type": "aws_elasticsearch_domain",
                "name": "legacy",
                "change": {
                    "after": {
                        "encrypt_at_rest": {"enabled": False}
                    }
                },
            }
        ]
    }
    findings = detect_suspicious_defaults(plan, [])
    assert findings
    assert findings[0]["address"] == "aws_elasticsearch_domain.legacy"


def test_detects_public_subnet_mapping_public_ips():
    plan = {}
    resources = [
        _resource(
            "aws_subnet",
            "public",
            {"map_public_ip_on_launch": True},
        )
    ]
    findings = detect_suspicious_defaults(plan, resources)
    assert any("public IPs" in item["reason"] for item in findings)


def test_detects_iam_inline_wildcard_actions():
    plan = {}
    resources = [
        _resource(
            "aws_iam_role_policy",
            "inline",
            {
                "policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}'
            },
        )
    ]
    findings = detect_suspicious_defaults(plan, resources)
    assert len(findings) == 1
    assert "IAM inline policy" in findings[0]["reason"]
