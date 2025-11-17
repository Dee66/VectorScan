from tools.vectorscan import vectorscan as vs
from tools.vectorscan.policies import get_policies, get_policy


def test_policy_registry_contains_builtin_ids() -> None:
    policy_ids = {policy.metadata.policy_id for policy in get_policies()}
    assert policy_ids == {"P-SEC-001", "P-FIN-001"}


def test_encryption_policy_matches_wrapper() -> None:
    resources = [
        {
            "type": "aws_db_instance",
            "name": "db1",
            "values": {"storage_encrypted": False, "kms_key_id": None},
        }
    ]
    policy = get_policy("P-SEC-001")
    plugin_result = policy.evaluate(resources)
    legacy_result = vs.check_encryption(resources)
    assert plugin_result == legacy_result
    assert plugin_result and "P-SEC-001" in plugin_result[0]


def test_tagging_policy_matches_wrapper() -> None:
    resources = [
        {
            "type": "aws_s3_bucket",
            "name": "bucket1",
            "values": {"tags": {"CostCenter": "", "Project": "Vector"}},
        }
    ]
    policy = get_policy("P-FIN-001")
    plugin_result = policy.evaluate(resources)
    legacy_result = vs.check_tags(resources)
    assert plugin_result == legacy_result
    assert plugin_result and "missing/empty tag 'CostCenter'" in plugin_result[0]
