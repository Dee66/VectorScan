from __future__ import annotations

from typing import Any, Dict, List, Sequence

 

_BASE_RULE_CATALOG: Sequence[Dict[str, Any]] = (
    {
        "id": "PILLAR-AWS-001",
        "severity": "critical",
        "title": "RDS clusters must enable storage encryption",
        "description": "Tier-1 data stores require storage_encrypted=true with a customer-managed KMS key.",
        "resource_type": "aws_rds_cluster",
        "attributes": {
            "category": "database",
            "service": "rds",
            "resource_selector": "aws_rds_cluster.*",
        },
        "remediation_hint": "",
        "remediation_difficulty": "high",
        "match": {
            "resource_type": "aws_rds_cluster",
            "required_attribute": "storage_encrypted",
            "attributes": {
                "storage_encrypted": False,
            },
            "flags": {},
        },
    },
    {
        "id": "PILLAR-AWS-002",
        "severity": "high",
        "title": "RDS clusters require CostCenter + Project tags",
        "description": "FinOps policy mandates CostCenter and Project tags on production Aurora clusters.",
        "resource_type": "aws_rds_cluster",
        "attributes": {
            "category": "finops",
            "service": "rds",
            "resource_selector": "aws_rds_cluster.*",
        },
        "remediation_hint": "",
        "remediation_difficulty": "medium",
        "match": {
            "resource_type": "aws_rds_cluster",
            "required_attribute": "tags",
            "attributes": {},
            "flags": {
                "has_missing_tags": True,
            },
        },
    },
    {
        "id": "PILLAR-AWS-003",
        "severity": "high",
        "title": "Security groups must block 0.0.0.0/0 ingress",
        "description": "Open ingress creates unmanaged exposure; restrict to CIDRs owned by the workload.",
        "resource_type": "aws_security_group",
        "attributes": {
            "category": "network",
            "service": "ec2",
            "resource_selector": "aws_security_group.*",
        },
        "remediation_hint": "",
        "remediation_difficulty": "medium",
        "match": {
            "resource_type": "aws_security_group",
            "required_attribute": "ingress",
            "attributes": {},
            "flags": {
                "allows_0_0_0_0": True,
            },
        },
    },
    {
        "id": "PILLAR-AWS-004",
        "severity": "critical",
        "title": "IAM policies may not grant wildcard admin",
        "description": "Production roles must avoid Action='*' grants across all resources.",
        "resource_type": "aws_iam_policy",
        "attributes": {
            "category": "identity",
            "service": "iam",
            "resource_selector": "aws_iam_*",
        },
        "remediation_hint": "",
        "remediation_difficulty": "high",
        "match": {
            "resource_type": "aws_iam_policy",
            "required_attribute": "policy",
            "attributes": {},
            "flags": {
                "iam_policy_wildcard": True,
            },
        },
    },
    {
        "id": "PILLAR-AWS-005",
        "severity": "high",
        "title": "S3 buckets must enforce encryption at rest",
        "description": "Buckets containing build outputs or models must define SSE or KMS defaults.",
        "resource_type": "aws_s3_bucket",
        "attributes": {
            "category": "storage",
            "service": "s3",
            "resource_selector": "aws_s3_bucket.*",
        },
        "remediation_hint": "",
        "remediation_difficulty": "medium",
        "match": {
            "resource_type": "aws_s3_bucket",
            "required_attribute": None,
            "attributes": {},
            "flags": {
                "s3_encryption_disabled": True,
            },
        },
    },
    {
        "id": "PILLAR-AWS-006",
        "severity": "medium",
        "title": "S3 buckets must enable versioning",
        "description": "Versioning preserves recovery points for drifted objects and vector manifests.",
        "resource_type": "aws_s3_bucket",
        "attributes": {
            "category": "resilience",
            "service": "s3",
            "resource_selector": "aws_s3_bucket.*",
        },
        "remediation_hint": "",
        "remediation_difficulty": "medium",
        "match": {
            "resource_type": "aws_s3_bucket",
            "required_attribute": None,
            "attributes": {},
            "flags": {
                "s3_versioning_disabled": True,
            },
        },
    },
    {
        "id": "PILLAR-AWS-007",
        "severity": "high",
        "title": "EBS volumes require encryption",
        "description": "Store embeddings and checkpoints on encrypted block devices.",
        "resource_type": "aws_ebs_volume",
        "attributes": {
            "category": "storage",
            "service": "ebs",
            "resource_selector": "aws_ebs_volume.*",
        },
        "remediation_hint": "",
        "remediation_difficulty": "medium",
        "match": {
            "resource_type": "aws_ebs_volume",
            "required_attribute": "encrypted",
            "attributes": {
                "encrypted": False,
            },
            "flags": {},
        },
    },
    {
        "id": "PILLAR-AWS-008",
        "severity": "medium",
        "title": "CloudTrail must be multi-region",
        "description": "Audit trails must capture events from every region that VectorScan resources use.",
        "resource_type": "aws_cloudtrail",
        "attributes": {
            "category": "audit",
            "service": "cloudtrail",
            "resource_selector": "aws_cloudtrail.*",
        },
        "remediation_hint": "",
        "remediation_difficulty": "low",
        "match": {
            "resource_type": "aws_cloudtrail",
            "required_attribute": "is_multi_region_trail",
            "attributes": {
                "is_multi_region_trail": False,
            },
            "flags": {},
        },
    },
    {
        "id": "PILLAR-AWS-009",
        "severity": "medium",
        "title": "CloudTrail log file validation required",
        "description": "Log file validation prevents tampering across compliance reviews.",
        "resource_type": "aws_cloudtrail",
        "attributes": {
            "category": "audit",
            "service": "cloudtrail",
            "resource_selector": "aws_cloudtrail.*",
        },
        "remediation_hint": "",
        "remediation_difficulty": "low",
        "match": {
            "resource_type": "aws_cloudtrail",
            "required_attribute": "enable_log_file_validation",
            "attributes": {
                "enable_log_file_validation": False,
            },
            "flags": {},
        },
    },
    {
        "id": "PILLAR-AWS-010",
        "severity": "medium",
        "title": "DynamoDB tables must enable PITR",
        "description": "Point-in-time recovery keeps catalog state restorable for guardrails metadata.",
        "resource_type": "aws_dynamodb_table",
        "attributes": {
            "category": "resilience",
            "service": "dynamodb",
            "resource_selector": "aws_dynamodb_table.*",
        },
        "remediation_hint": "",
        "remediation_difficulty": "medium",
        "match": {
            "resource_type": "aws_dynamodb_table",
            "required_attribute": "point_in_time_recovery",
            "attributes": {
                "point_in_time_recovery": False,
            },
            "flags": {},
        },
    },
    {
        "id": "PILLAR-AWS-011",
        "severity": "medium",
        "title": "Lambda functions need KMS-backed environment vars",
        "description": "Secrets injected via environment variables must be encrypted with KMS.",
        "resource_type": "aws_lambda_function",
        "attributes": {
            "category": "serverless",
            "service": "lambda",
            "resource_selector": "aws_lambda_function.*",
        },
        "remediation_hint": "",
        "remediation_difficulty": "medium",
        "match": {
            "resource_type": "aws_lambda_function",
            "required_attribute": "kms_key_arn",
            "attributes": {
                "kms_key_arn": None,
            },
            "flags": {},
        },
    },
    {
        "id": "PILLAR-AWS-012",
        "severity": "high",
        "title": "EKS control plane logging required",
        "description": "Enable api, audit, authenticator, controllerManager, and scheduler logs for GuardDuty feeds.",
        "resource_type": "aws_eks_cluster",
        "attributes": {
            "category": "kubernetes",
            "service": "eks",
            "resource_selector": "aws_eks_cluster.*",
        },
        "remediation_hint": "",
        "remediation_difficulty": "high",
        "match": {
            "resource_type": "aws_eks_cluster",
            "required_attribute": "enabled_cluster_log_types",
            "attributes": {
                "enabled_cluster_log_types": [],
            },
            "flags": {},
        },
    },
    {
        "id": "PILLAR-AWS-013",
        "severity": "critical",
        "title": "GuardDuty must stay enabled",
        "description": "Managed accounts must enable GuardDuty detectors across every region.",
        "resource_type": "aws_guardduty_detector",
        "attributes": {
            "category": "threat-detection",
            "service": "guardduty",
            "resource_selector": "aws_guardduty_detector.*",
        },
        "remediation_hint": "",
        "remediation_difficulty": "medium",
        "match": {
            "resource_type": "aws_guardduty_detector",
            "required_attribute": "enable",
            "attributes": {
                "enable": False,
            },
            "flags": {},
        },
    },
    {
        "id": "PILLAR-AWS-014",
        "severity": "high",
        "title": "AWS Config recorder must be active",
        "description": "Configuration history is mandatory before running VectorScan remediation packs.",
        "resource_type": "aws_config_configuration_recorder",
        "attributes": {
            "category": "audit",
            "service": "config",
            "resource_selector": "aws_config_configuration_recorder.*",
        },
        "remediation_hint": "",
        "remediation_difficulty": "medium",
        "match": {
            "resource_type": "aws_config_configuration_recorder",
            "required_attribute": "recording_group",
            "attributes": {
                "recording_group": {},
            },
            "flags": {},
        },
    },
    {
        "id": "PILLAR-AWS-015",
        "severity": "medium",
        "title": "VPCs should emit flow logs",
        "description": "Flow logs feed the anomaly detectors that back GuardSuite recommendations.",
        "resource_type": "aws_flow_log",
        "attributes": {
            "category": "network",
            "service": "vpc",
            "resource_selector": "aws_flow_log.*",
        },
        "remediation_hint": "",
        "remediation_difficulty": "medium",
        "match": {
            "resource_type": "aws_flow_log",
            "required_attribute": "log_destination",
            "attributes": {
                "log_destination": None,
            },
            "flags": {},
        },
    },
    {
        "id": "PILLAR-AWS-016",
        "severity": "high",
        "title": "Redshift clusters must encrypt data",
        "description": "Analytics warehouses contain PII and require encryption + KMS wiring.",
        "resource_type": "aws_redshift_cluster",
        "attributes": {
            "category": "database",
            "service": "redshift",
            "resource_selector": "aws_redshift_cluster.*",
        },
        "remediation_hint": "",
        "remediation_difficulty": "high",
        "match": {
            "resource_type": "aws_redshift_cluster",
            "required_attribute": "encrypted",
            "attributes": {
                "encrypted": False,
            },
            "flags": {},
        },
    },
    {
        "id": "PILLAR-AWS-017",
        "severity": "high",
        "title": "ElastiCache clusters must enable encryption",
        "description": "Cache tiers store tokens that must remain encrypted in transit and at rest.",
        "resource_type": "aws_elasticache_replication_group",
        "attributes": {
            "category": "cache",
            "service": "elasticache",
            "resource_selector": "aws_elasticache_replication_group.*",
        },
        "remediation_hint": "",
        "remediation_difficulty": "medium",
        "match": {
            "resource_type": "aws_elasticache_replication_group",
            "required_attribute": "at_rest_encryption_enabled",
            "attributes": {
                "at_rest_encryption_enabled": False,
            },
            "flags": {},
        },
    },
    {
        "id": "PILLAR-AWS-018",
        "severity": "critical",
        "title": "Root accounts must not retain access keys",
        "description": "Delete root access keys to reduce blast radius.",
        "resource_type": "aws_iam_account_password_policy",
        "attributes": {
            "category": "identity",
            "service": "iam",
            "resource_selector": "aws_iam_account_password_policy",
        },
        "remediation_hint": "",
        "remediation_difficulty": "medium",
        "match": {
            "resource_type": "aws_iam_account_password_policy",
            "required_attribute": "require_uppercase_characters",
            "attributes": {
                "require_uppercase_characters": False,
            },
            "flags": {},
        },
    },
    {
        "id": "PILLAR-AWS-019",
        "severity": "medium",
        "title": "Backup vaults must specify KMS keys",
        "description": "Use customer-managed KMS keys for cross-account restore workflows.",
        "resource_type": "aws_backup_vault",
        "attributes": {
            "category": "resilience",
            "service": "backup",
            "resource_selector": "aws_backup_vault.*",
        },
        "remediation_hint": "",
        "remediation_difficulty": "medium",
        "match": {
            "resource_type": "aws_backup_vault",
            "required_attribute": "kms_key_arn",
            "attributes": {
                "kms_key_arn": None,
            },
            "flags": {},
        },
    },
    {
        "id": "PILLAR-AWS-020",
        "severity": "medium",
        "title": "SNS topics must enforce encryption",
        "description": "Notifications often forward secrets; require KMS-backed encryption.",
        "resource_type": "aws_sns_topic",
        "attributes": {
            "category": "messaging",
            "service": "sns",
            "resource_selector": "aws_sns_topic.*",
        },
        "remediation_hint": "",
        "remediation_difficulty": "medium",
        "match": {
            "resource_type": "aws_sns_topic",
            "required_attribute": "kms_master_key_id",
            "attributes": {
                "kms_master_key_id": None,
            },
            "flags": {},
        },
    },
    {
        "id": "PILLAR-AWS-021",
        "severity": "medium",
        "title": "SQS queues must encrypt payloads",
        "description": "Message queues contain request context and must reference a CMK.",
        "resource_type": "aws_sqs_queue",
        "attributes": {
            "category": "messaging",
            "service": "sqs",
            "resource_selector": "aws_sqs_queue.*",
        },
        "remediation_hint": "",
        "remediation_difficulty": "medium",
        "match": {
            "resource_type": "aws_sqs_queue",
            "required_attribute": "kms_master_key_id",
            "attributes": {
                "kms_master_key_id": None,
            },
            "flags": {},
        },
    },
    {
        "id": "PILLAR-AWS-022",
        "severity": "medium",
        "title": "KMS keys must rotate annually",
        "description": "Managed cryptographic material requires automatic rotation.",
        "resource_type": "aws_kms_key",
        "attributes": {
            "category": "security",
            "service": "kms",
            "resource_selector": "aws_kms_key.*",
        },
        "remediation_hint": "",
        "remediation_difficulty": "medium",
        "match": {
            "resource_type": "aws_kms_key",
            "required_attribute": "enable_key_rotation",
            "attributes": {
                "enable_key_rotation": False,
            },
            "flags": {},
        },
    },
    {
        "id": "PILLAR-AWS-023",
        "severity": "medium",
        "title": "RDS clusters should not be publicly accessible",
        "description": "Private data stores must launch inside isolated subnets.",
        "resource_type": "aws_rds_cluster",
        "attributes": {
            "category": "network",
            "service": "rds",
            "resource_selector": "aws_rds_cluster.*",
        },
        "remediation_hint": "",
        "remediation_difficulty": "high",
        "match": {
            "resource_type": "aws_rds_cluster",
            "required_attribute": "publicly_accessible",
            "attributes": {
                "publicly_accessible": True,
            },
            "flags": {},
        },
    },
    {
        "id": "PILLAR-AWS-024",
        "severity": "medium",
        "title": "ECS services should avoid public IP assignment",
        "description": "Service tasks behind ALBs must use private subnets and NAT egress.",
        "resource_type": "aws_ecs_service",
        "attributes": {
            "category": "containers",
            "service": "ecs",
            "resource_selector": "aws_ecs_service.*",
        },
        "remediation_hint": "",
        "remediation_difficulty": "medium",
        "match": {
            "resource_type": "aws_ecs_service",
            "required_attribute": "assign_public_ip",
            "attributes": {
                "assign_public_ip": True,
            },
            "flags": {},
        },
    },
)


def _attach_remediation(entry: Dict[str, Any]) -> Dict[str, Any]:
    enriched = dict(entry)
    metadata = enriched.get("remediation_metadata")
    enriched["remediation_metadata"] = dict(metadata) if isinstance(metadata, dict) else {}
    hint = enriched.get("remediation_hint")
    enriched["remediation_hint"] = hint.strip() if isinstance(hint, str) else ""
    return enriched



_RULE_CATALOG: Sequence[Dict[str, Any]] = tuple(
        _attach_remediation(entry) for entry in _BASE_RULE_CATALOG
)


def issue_catalog() -> List[Dict[str, Any]]:
    return [dict(entry) for entry in _RULE_CATALOG]


def get_rules() -> List[Dict[str, Any]]:
    return issue_catalog()
