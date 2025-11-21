"""Utility script to emit the VectorScan rule manifest."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from vectorscan.rules import build_rule_manifest  # pyright: ignore[reportMissingImports]


def _docs_manifest_path() -> Path:
    root = Path(__file__).resolve().parents[3]
    return root / "docs" / "rule_manifest.json"


def generate_rule_manifest() -> Dict[str, Any]:
    """Return the canonical rule manifest payload."""

    return build_rule_manifest()


def main() -> None:
    manifest = generate_rule_manifest()
    output_path = _docs_manifest_path()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
