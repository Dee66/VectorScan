"""Utilities for describing the bundled policy pack."""

from __future__ import annotations

import hashlib
import os
from functools import lru_cache
from pathlib import Path
from typing import Iterable, List

_POLICY_DIR = Path(__file__).resolve().parent
_DEFAULT_POLICY_FILES = (_POLICY_DIR / "free_policies.rego",)

_ENV_PATHS = "VSCAN_POLICY_PACK_FILES"
_ENV_HASH = "VSCAN_POLICY_PACK_HASH"


class PolicyPackError(RuntimeError):
    """Raised when the VectorScan policy pack cannot be located or read."""

    pass


def _expand_policy_files(value: str | None) -> list[Path]:
    if not value:
        return []
    files: list[Path] = []
    for token in value.split(os.pathsep):
        candidate = token.strip()
        if not candidate:
            continue
        path = Path(candidate).expanduser()
        if path.is_dir():
            files.extend(sorted(path.rglob("*.rego")))
        else:
            files.append(path)
    return files


def _policy_file_candidates() -> list[Path]:
    env_value = os.getenv(_ENV_PATHS)
    overrides = _expand_policy_files(env_value)
    if env_value:
        return overrides
    return list(_DEFAULT_POLICY_FILES)


def _validate_policy_files(files: list[Path]) -> List[Path]:
    if not files:
        raise PolicyPackError(
            "No policy files found. Ensure free_policies.rego exists or set VSCAN_POLICY_PACK_FILES to valid .rego paths."
        )
    resolved: List[Path] = []
    seen: set[Path] = set()
    for raw in files:
        path = raw.expanduser().resolve()
        if path in seen:
            continue
        seen.add(path)
        if not path.exists():
            raise PolicyPackError(f"Policy file not found: {path}")
        if not path.is_file():
            raise PolicyPackError(f"Policy path is not a file: {path}")
        resolved.append(path)
    if not resolved:
        raise PolicyPackError(
            "Policy pack did not include any .rego files. Check VSCAN_POLICY_PACK_FILES or ensure bundled policies are present."
        )
    return resolved


def _hash_policy_files(files: Iterable[Path]) -> str:
    digest = hashlib.sha256()
    count = 0
    for path in sorted({p.resolve() for p in files}):
        try:
            data = path.read_bytes()
        except FileNotFoundError as exc:
            raise PolicyPackError(f"Policy file missing: {path}") from exc
        except OSError as exc:  # pragma: no cover - extremely rare
            raise PolicyPackError(f"Unable to read policy file {path}: {exc}") from exc
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(data)
        count += 1
    if count == 0:
        raise PolicyPackError("Policy pack contained zero readable files")
    return digest.hexdigest()


@lru_cache(maxsize=1)
def policy_pack_hash() -> str:
    override = os.getenv(_ENV_HASH)
    if override:
        return override.strip()
    files = _validate_policy_files(_policy_file_candidates())
    return _hash_policy_files(files)


__all__ = [
    "PolicyPackError",
    "policy_pack_hash",
]
