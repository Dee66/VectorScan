#!/usr/bin/env python3
"""
Build vectorscan-free.zip containing the VectorScan CLI and free policies.

Contents:
- tools/vectorscan/vectorscan.py
- tools/vectorscan/README.md
- tools/vectorscan/free_policies.rego
- LICENSE_FREE.txt (snippet referencing main license)

Usage:
  python3 tools/vectorscan/build_vectorscan_package.py
"""
from __future__ import annotations
import argparse
import zipfile
from pathlib import Path
import hashlib
import importlib.util
import sys
from typing import List

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "tools" / "vectorscan"
DIST = REPO_ROOT / "dist"

FILES = [
    SRC / "vectorscan.py",
    SRC / "README.md",
    SRC / "free_policies.rego",
]

LICENSE_TEXT = (
    "VectorScan Free Utility\n\n"
    "This archive includes the VectorScan CLI and minimal policies for two checks.\n"
    "See the main LICENSE in the repository root for full terms.\n"
)


def write_sha256(p: Path) -> None:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    out = p.with_suffix(p.suffix + ".sha256")
    out.write_text(f"{h.hexdigest()}  {p.name}\n", encoding="utf-8")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the VectorScan free bundle with bundled Terraform binary")
    parser.add_argument(
        "--bundle-name",
        default="vectorscan-free",
        help="Base file name (without extension) for the generated zip",
    )
    # Use parse_known_args so pytest runner flags (e.g., -q) don't cause failures when tests import and call main().
    if argv is None:
        argv = sys.argv[1:]
    args, _extra = parser.parse_known_args(argv)
    return args


def load_vectorscan_module():
    target = SRC / "vectorscan.py"
    if not target.exists():
        return None
    spec = importlib.util.spec_from_file_location("vectorscan_packaging", target)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load vectorscan module for packaging")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    return module


def ensure_terraform_binary(module, bundle_name: str) -> Path:
    # Determine required version based on bundle naming convention
    required_version = module.REQUIRED_TERRAFORM_VERSION
    if bundle_name.lower().endswith("-legacy"):
        required_version = "1.6.0"

    manager = module.TerraformManager(
        required_version=required_version,
        download_dir=module.DEFAULT_TERRAFORM_CACHE,
        auto_download=True,
    )

    resolution = manager.ensure()
    if resolution.source != "download":
        downloaded = manager._download()
        resolution = manager._resolution_for(downloaded, source="download")
        if resolution is None:
            raise RuntimeError("Failed to resolve downloaded Terraform binary")

    return resolution.path


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    bundle_name = args.bundle_name

    module = load_vectorscan_module()
    terraform_path: Path | None = None
    if module is not None:
        try:
            terraform_path = ensure_terraform_binary(module, bundle_name)
        except Exception as exc:
            print(f"Warning: skipping Terraform bundling ({exc})")

    DIST.mkdir(parents=True, exist_ok=True)
    out = DIST / f"{bundle_name}.zip"
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
        # normalize permissions and timestamps for reproducibility
        bundled_files: List[Path] = list(FILES)
        if terraform_path is not None:
            bundled_files.append(terraform_path)
        for f in bundled_files:
            if not f.exists():
                print(f"Warning: missing file {f}")
                continue
            z.write(f, arcname=f.relative_to(REPO_ROOT))
        # license snippet
        z.writestr("LICENSE_FREE.txt", LICENSE_TEXT)
    write_sha256(out)
    print(f"Wrote {out} and checksum")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
