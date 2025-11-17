"""Shared helpers/constants for VectorScan policies and metrics."""
from __future__ import annotations

from typing import Any, Set


TAGGABLE_TYPES: Set[str] = {
    "aws_db_instance",
    "aws_rds_cluster",
    "aws_eks_cluster",
    "aws_autoscaling_group",
    "aws_instance",
    "aws_s3_bucket",
    "aws_kms_key",
    "aws_security_group",
    "aws_vpc",
    "aws_subnet",
}

REQUIRED_TAGS = ("CostCenter", "Project")


def is_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and value.strip() != ""
