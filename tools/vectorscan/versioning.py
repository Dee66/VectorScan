"""Centralized version metadata for VectorScan outputs."""

from __future__ import annotations

import os

from tools.vectorscan.policy_pack import policy_pack_hash

VECTORSCAN_VERSION = os.getenv("VSCAN_VERSION", "0.1.0")
POLICY_VERSION = os.getenv("VSCAN_POLICY_VERSION", "1.0.0")
OUTPUT_SCHEMA_VERSION = os.getenv("VSCAN_OUTPUT_SCHEMA_VERSION", "1.2.0")


def output_metadata() -> dict[str, str]:
    """Return a dict containing standard metadata fields for outputs."""
    return {
        "vectorscan_version": VECTORSCAN_VERSION,
        "policy_version": POLICY_VERSION,
        "schema_version": OUTPUT_SCHEMA_VERSION,
        "policy_pack_hash": policy_pack_hash(),
    }
