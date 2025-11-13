#!/usr/bin/env python3
"""
Create a clean release zip for vectorguard.

Outputs dist/vectorguard-v<version>.zip with required assets.

Features:
- Verifies clean git working tree (unless --no-git-check is passed)
- Includes key project assets; excludes caches, tests, CI, and secrets
- Reproducible file order

Usage:
  python3 scripts/create_release_bundle.py --version 1.0.0

"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
import hashlib

REPO_ROOT = Path(__file__).resolve().parents[1]
PKG_ROOT = REPO_ROOT  # vectorguard project directory

INCLUDE_DIRS = [
    "policies",
    "modules",
    "examples",
    "scripts",
    "docs",
    "tools",
    "data",
]

INCLUDE_FILES = [
    "README.md",
    "LICENSE",
    "DISCLAIMER.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "QUICKSTART.md",
]

EXCLUDE_DIRS = {
    ".git",
    ".github",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "coverage",
    "tests",  # exclude internal tests from customer bundle
    "benchmarks",
}

EXCLUDE_FILE_PATTERNS = {
    "*.pyc",
    "*.pyo",
    "*.DS_Store",
    "*.log",
}


def is_clean_git_tree(repo_path: Path) -> bool:
    try:
        out = subprocess.check_output(["git", "status", "--porcelain"], cwd=repo_path)
    except Exception:
        # If git is unavailable, be conservative and say not clean.
        return False
    return out.strip() == b""


def should_exclude(path: Path) -> bool:
    parts = set(path.parts)
    if parts & EXCLUDE_DIRS:
        return True
    name = path.name
    for pat in EXCLUDE_FILE_PATTERNS:
        if Path(name).match(pat):
            return True
    return False


def add_path(z: ZipFile, base_dir: Path, rel_path: Path) -> None:
    abs_path = base_dir / rel_path
    if abs_path.is_dir():
        for p in sorted(abs_path.rglob("*")):
            if p.is_dir():
                continue
            rp = p.relative_to(base_dir)
            if should_exclude(rp):
                continue
            z.write(p, arcname=rp.as_posix())
    else:
        if not should_exclude(rel_path):
            z.write(abs_path, arcname=rel_path.as_posix())


def write_sha256(path: Path) -> Path:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    out = path.with_suffix(path.suffix + ".sha256")
    out.write_text(f"{h.hexdigest()}  {path.name}\n", encoding="utf-8")
    return out


def gpg_sign(zip_path: Path) -> Path | None:
    """Attempt a detached ASCII-armored signature using gpg.

    Returns the signature path or None if signing failed/unavailable.
    """
    try:
        subprocess.run([
            "gpg", "--batch", "--yes", "--armor", "--detach-sign", str(zip_path)
        ], check=True)
    except Exception as e:  # noqa: BLE001
        print(f"Warning: GPG signing skipped ({e})", file=sys.stderr)
        return None
    sig = zip_path.with_suffix(zip_path.suffix + ".asc")
    if not sig.exists():
        print("Warning: Expected signature file not found after gpg run.", file=sys.stderr)
        return None
    return sig


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Create release bundle zip")
    ap.add_argument("--version", required=True, help="Version string, e.g., 1.0.0")
    ap.add_argument("--no-git-check", action="store_true", help="Skip clean git state check")
    ap.add_argument("--gpg-sign", action="store_true", help="Attempt to create a detached GPG signature (.asc)")
    ap.add_argument("--strict", action="store_true", help="Fail the build if requested signing cannot be completed")
    args = ap.parse_args(argv)

    if not args.no_git_check:
        if not is_clean_git_tree(REPO_ROOT):
            print("Error: Git working tree is not clean. Commit or stash changes, or pass --no-git-check.", file=sys.stderr)
            return 1

    dist_dir = REPO_ROOT / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)

    zip_name = f"vectorguard-v{args.version}.zip"
    zip_path = dist_dir / zip_name

    # Build determinstically: sort inputs
    with ZipFile(zip_path, "w", compression=ZIP_DEFLATED) as z:
        # Add top-level files
        for f in sorted(INCLUDE_FILES):
            p = PKG_ROOT / f
            if p.exists():
                add_path(z, PKG_ROOT, Path(f))

        # Add directories
        for d in sorted(INCLUDE_DIRS):
            p = PKG_ROOT / d
            if p.exists():
                add_path(z, PKG_ROOT, Path(d))

    # Basic size sanity check
    size = zip_path.stat().st_size
    if size < 50_000:  # 50KB minimum sanity
        print(f"Warning: Archive is small ({size} bytes). Verify contents.", file=sys.stderr)

    # Write checksum manifest
    sha_path = write_sha256(zip_path)

    print(zip_path)
    print(sha_path)

    if args.gpg_sign:
        sig_path = gpg_sign(zip_path)
        if sig_path:
            print(sig_path)
        else:
            print("(No .asc signature produced)")
            if args.strict:
                print("Error: --gpg-sign requested but signature not produced; failing due to --strict.", file=sys.stderr)
                return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
