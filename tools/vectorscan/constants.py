"""Shared constants for the VectorScan CLI."""

from __future__ import annotations

import os
from pathlib import Path

ANSI_RESET = "\033[0m"
ANSI_GREEN = "\033[32m"
ANSI_RED = "\033[31m"
ANSI_YELLOW = "\033[33m"
ANSI_BOLD = "\033[1m"

SEVERITY_LEVELS = ("critical", "high", "medium", "low")
RISKY_ACTION_TERMS = (
    "*",
    ":*",
    "s3:DeleteObject",
    "s3:PutObject",
    "s3:PutBucketPolicy",
    "s3:DeleteBucketPolicy",
    "rds:*",
    "iam:*",
    "iam:PassRole",
    "iam:CreateUser",
    "iam:CreateAccessKey",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "kms:ScheduleKeyDeletion",
    "kms:DisableKey",
    "kms:DisableKeyRotation",
    "kms:PutKeyPolicy",
    "ec2:AuthorizeSecurityGroupIngress",
    "ec2:RevokeSecurityGroupEgress",
    "ec2:CreateSecurityGroup",
    "cloudtrail:StopLogging",
    "logs:DeleteLogGroup",
)

REMEDIATION_DOCS = {
    "P-SEC-001": [
        "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
        "https://vectorguard.dev/docs/policies/p-sec-001",
    ],
    "P-FIN-001": [
        "https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html",
        "https://vectorguard.dev/docs/policies/p-fin-001",
    ],
}

REQUIRED_TERRAFORM_VERSION = os.getenv("VSCAN_TERRAFORM_REQUIRED_VERSION", "1.13.5")
MIN_TERRAFORM_TESTS_VERSION = (1, 8, 0)

_TERRAFORM_CACHE_ENV = os.getenv("VSCAN_TERRAFORM_CACHE")
DEFAULT_TERRAFORM_CACHE = (
    Path(_TERRAFORM_CACHE_ENV).expanduser()
    if _TERRAFORM_CACHE_ENV
    else Path(__file__).resolve().parent / ".terraform-bin"
)
ROOT_DIR = Path(__file__).resolve().parents[2]

EXIT_SUCCESS = 0
EXIT_INVALID_INPUT = 2
EXIT_POLICY_FAIL = 3
EXIT_POLICY_LOAD_ERROR = 4
EXIT_TERRAFORM_FAIL = 5
EXIT_CONFIG_ERROR = 6
EXIT_TERRAFORM_ERROR = EXIT_CONFIG_ERROR
EXIT_PREVIEW_MODE = 10

__all__ = [
    "ANSI_RESET",
    "ANSI_GREEN",
    "ANSI_RED",
    "ANSI_YELLOW",
    "ANSI_BOLD",
    "SEVERITY_LEVELS",
    "RISKY_ACTION_TERMS",
    "REMEDIATION_DOCS",
    "REQUIRED_TERRAFORM_VERSION",
    "MIN_TERRAFORM_TESTS_VERSION",
    "DEFAULT_TERRAFORM_CACHE",
    "ROOT_DIR",
    "EXIT_SUCCESS",
    "EXIT_INVALID_INPUT",
    "EXIT_POLICY_FAIL",
    "EXIT_POLICY_LOAD_ERROR",
    "EXIT_TERRAFORM_FAIL",
    "EXIT_CONFIG_ERROR",
    "EXIT_TERRAFORM_ERROR",
    "EXIT_PREVIEW_MODE",
]
