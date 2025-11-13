#!/usr/bin/env python3
"""
Mutation testing harness.

Creates temporary mutated copies of selected policy files (simple textual transformations)
and runs opa unit tests to ensure at least one test fails for each mutation.

Mutations applied:
  - Replace '==' with '!=' (logical inversion)
  - Remove one deny rule condition line (first condition occurrence)

Reports surviving mutants (no test failures), which indicate gaps in test sensitivity.
"""
from __future__ import annotations

import shutil
import tempfile
import subprocess
import re
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICIES_DIR = ROOT / "policies"
TEST_DIR = ROOT / "tests/rego-tests"

TARGET_POLICIES = [
    POLICIES_DIR / "security" / "P-SEC-001-encryption.rego",
    POLICIES_DIR / "finops" / "P-FIN-001-mandatory-tagging.rego",
    POLICIES_DIR / "finops" / "P-FIN-002-scaling-limits.rego",
    POLICIES_DIR / "audit" / "P-AUD-001-immutable-logging.rego",
]


def run_opa_tests(policy_path: Path, tmp_root: Path) -> int:
    # Run tests against mutated policy + original others
    cmd = ["opa", "test", str(tmp_root / "policies"), str(ROOT / "tools" / "vectorscan"), str(TEST_DIR), "-v"]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    # Return code 0 means all tests passed (bad for mutation), non-zero means failure (good: mutant killed)
    if proc.returncode == 0:
        print(f"SURVIVED: {policy_path.name}\nOutput:\n{proc.stdout[:400]}")
    else:
        print(f"KILLED: {policy_path.name} (rc={proc.returncode})")
    return proc.returncode


def mutate_content(content: str, policy_name: str) -> list[tuple[str, str]]:
    mutants: list[tuple[str, str]] = []
    # 1) Flip '==' to '!=' (first occurrence)
    flipped = re.sub(r"==", "!=", content, count=1)
    if flipped != content:
        mutants.append(("flip_equals", flipped))

    # 2) Remove first condition referencing resource values (heuristic)
    lines = content.splitlines()
    removed_once = False
    for i, ln in enumerate(lines):
        if not removed_once and ln.strip().startswith("resource"):
            lines[i] = "# MUTATION_REMOVED " + ln
            removed_once = True
    if removed_once:
        mutants.append(("remove_condition", "\n".join(lines)))

    # 3) Flip >= and <= to > and < (first occurrence each)
    flip_ge = re.sub(r">=", ">", content, count=1)
    if flip_ge != content:
        mutants.append(("flip_ge", flip_ge))
    flip_le = re.sub(r"<=", "<", content, count=1)
    if flip_le != content:
        mutants.append(("flip_le", flip_le))

    # 4) Rename deny rule to allow (first rule head)
    deny_to_allow = re.sub(r"^(\s*)deny(\b|\[)", r"\1allow\2", content, count=1, flags=re.MULTILINE)
    if deny_to_allow != content:
        mutants.append(("deny_to_allow", deny_to_allow))

    # 5) Numeric threshold tweak (+1) for scaling-limits policy
    if "P-FIN-002-scaling-limits.rego" in policy_name:
        def plus_one(m: re.Match) -> str:
            return str(int(m.group(0)) + 1)
        tweaked = re.sub(r"\b(\d{1,3})\b", plus_one, content, count=1)
        if tweaked != content:
            mutants.append(("threshold_plus_one", tweaked))

    return mutants


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=str(ROOT / "coverage" / "mutation_summary.json"), help="Path to write mutation summary JSON")
    args = parser.parse_args()
    tmp = Path(tempfile.mkdtemp(prefix="mutation_") )
    try:
        # Copy full policies dir for isolation
        shutil.copytree(POLICIES_DIR, tmp / "policies")
        survivors = []
        total = 0
        killed = 0
        for policy in TARGET_POLICIES:
            original = policy.read_text()
            for mut_name, mutated in mutate_content(original, policy.name):
                mut_path = tmp / "policies" / policy.relative_to(POLICIES_DIR)
                mut_path.write_text(mutated)
                rc = run_opa_tests(policy, tmp)
                total += 1
                if rc == 0:  # all tests passed => survived
                    survivors.append(f"{policy.name}:{mut_name}")
                else:
                    killed += 1
                # restore original for next mutation
                mut_path.write_text(original)
        summary = {
            "total_mutants": total,
            "killed": killed,
            "survived": len(survivors),
            "kill_ratio": (killed / total) if total else 0.0,
            "survivors": survivors,
        }
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"Mutation summary written to {out_path}")
        if survivors:
            print("\nSurviving mutants (improve tests to kill):")
            for s in survivors:
                print(" -", s)
            return 1
        print("\nAll mutants killed. Test sensitivity adequate for applied mutations.")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
