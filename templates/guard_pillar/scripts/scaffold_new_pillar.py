#!/usr/bin/env python3
"""Utility script to scaffold a new GuardSuite pillar from the template."""

from __future__ import annotations

import shutil
from pathlib import Path
import sys

TEMPLATE_ROOT = Path(__file__).resolve().parents[1]
PILLAR_SRC = TEMPLATE_ROOT / "src" / "pillar"


def scaffold(destination: Path) -> None:
    if destination.exists():
        raise SystemExit(f"Destination already exists: {destination}")
    shutil.copytree(PILLAR_SRC, destination)
    print(f"Scaffolded pillar template to {destination}")


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("Usage: scaffold_new_pillar.py <destination>")
    dest = Path(sys.argv[1]).resolve()
    scaffold(dest)


if __name__ == "__main__":
    main()
