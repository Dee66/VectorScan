"""Runtime helpers enforcing the supported Python version range."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Tuple

MIN_SUPPORTED = (3, 9)
MAX_SUPPORTED = (3, 12)


@dataclass(frozen=True)
class PythonVersion:
    major: int
    minor: int
    micro: int

    def as_tuple(self) -> Tuple[int, int, int]:
        return (self.major, self.minor, self.micro)

    def label(self) -> str:
        return f"{self.major}.{self.minor}.{self.micro}"


class UnsupportedPythonVersion(RuntimeError):
    """Raised when the runtime Python version is outside the supported range."""


def _current_version() -> PythonVersion:
    info = sys.version_info
    return PythonVersion(info.major, info.minor, info.micro)


def _coerce_version(version: Tuple[int, int, int] | PythonVersion | None) -> PythonVersion:
    if version is None:
        return _current_version()
    if isinstance(version, PythonVersion):
        return version
    major, minor, micro = version
    return PythonVersion(int(major), int(minor), int(micro))


def supported_range_label() -> str:
    return f"{MIN_SUPPORTED[0]}.{MIN_SUPPORTED[1]}–{MAX_SUPPORTED[0]}.{MAX_SUPPORTED[1]}"


def is_supported_python(version: Tuple[int, int, int] | PythonVersion | None = None) -> bool:
    v = _coerce_version(version)
    lower = (v.major, v.minor) >= MIN_SUPPORTED
    upper = (v.major, v.minor) <= MAX_SUPPORTED
    return lower and upper


def ensure_supported_python(version: Tuple[int, int, int] | PythonVersion | None = None) -> None:
    if is_supported_python(version):
        return
    detected = _coerce_version(version)
    raise UnsupportedPythonVersion(
        "VectorScan requires Python "
        f"{supported_range_label()} but detected {detected.label()}"
    )


__all__ = [
    "MIN_SUPPORTED",
    "MAX_SUPPORTED",
    "PythonVersion",
    "UnsupportedPythonVersion",
    "supported_range_label",
    "is_supported_python",
    "ensure_supported_python",
]
