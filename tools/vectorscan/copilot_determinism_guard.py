"""Verify VectorScan emits deterministic output for the Copilot checklist."""
from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class FixtureResult:
    fixture: Path
    matches: bool
    hash_one: str
    hash_two: str


def _run_cli(cli_path: Path, fixture: Path) -> tuple[str, int]:
    env = os.environ.copy()
    env.setdefault("VSCAN_OFFLINE", "1")
    env.setdefault("VSCAN_CLOCK_ISO", "2024-01-01T00:00:00Z")
    env.setdefault("VSCAN_CLOCK_EPOCH", "1704067200")
    env.setdefault("VSCAN_NO_COLOR", "1")
    cmd = [sys.executable, str(cli_path), str(fixture), "--json"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False, env=env)
    payload = f"{result.returncode}\n{result.stdout}"
    return payload, result.returncode


def verify_fixtures(
    fixtures: Sequence[Path],
    *,
    base_path: Path | None = None,
) -> List[FixtureResult]:
    repo = base_path or _REPO_ROOT
    cli_path = repo / "tools" / "vectorscan" / "vectorscan.py"
    results: List[FixtureResult] = []

    for fixture in fixtures:
        fixture_path = fixture if fixture.is_absolute() else repo / fixture
        if not fixture_path.exists():
            raise FileNotFoundError(f"Fixture not found: {fixture_path}")
        first_payload, _ = _run_cli(cli_path, fixture_path)
        second_payload, _ = _run_cli(cli_path, fixture_path)
        hash_one = hashlib.sha256(first_payload.encode("utf-8")).hexdigest()
        hash_two = hashlib.sha256(second_payload.encode("utf-8")).hexdigest()
        results.append(
            FixtureResult(
                fixture=fixture_path,
                matches=first_payload == second_payload,
                hash_one=hash_one,
                hash_two=hash_two,
            )
        )
    return results


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check deterministic CLI output.")
    parser.add_argument(
        "--fixtures",
        nargs="+",
        default=["tests/fixtures/tfplan_pass.json"],
        help="Fixtures to scan twice for determinism.",
    )
    parser.add_argument(
        "--base-path",
        type=Path,
        default=_REPO_ROOT,
        help="Optional repository root override.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    fixtures = [Path(item) for item in args.fixtures]
    results = verify_fixtures(fixtures, base_path=args.base_path.resolve())
    mismatched = [r for r in results if not r.matches]
    if mismatched:
        print("Determinism guard failed:")
        for res in mismatched:
            rel = res.fixture.relative_to(args.base_path)
            print(f" - {rel}: {res.hash_one} != {res.hash_two}")
        return 1

    for res in results:
        rel = res.fixture.relative_to(args.base_path)
        print(f"Deterministic output confirmed for {rel}")
    return 0


if __name__ == "__main__":  # pragma: no cover - script entry point
    raise SystemExit(main())
