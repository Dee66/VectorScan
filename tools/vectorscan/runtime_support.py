"""Runtime compatibility helpers for managing supported Python versions."""

from __future__ import annotations

import sys
from typing import Iterable, Tuple

MIN_VERSION: Tuple[int, int] = (3, 9)
MAX_VERSION: Tuple[int, int] = (3, 12)


class UnsupportedPythonError(RuntimeError):
    """Raised when VectorScan runs under an unsupported Python interpreter."""

    def __init__(self, detected: Tuple[int, int]):
        super().__init__(
            "VectorScan supports Python %d.%d through %d.%d (detected %d.%d)."
            % (
                MIN_VERSION[0],
                MIN_VERSION[1],
                MAX_VERSION[0],
                MAX_VERSION[1],
                detected[0],
                detected[1],
            )
        )
        self.detected = detected


def _coerce_version_tuple(version: Iterable[int] | None) -> Tuple[int, int]:
    if version is None:
        info = sys.version_info
        return info.major, info.minor
    values = list(version)
    if len(values) < 2:
        raise ValueError("version tuple must include major and minor components")
    return int(values[0]), int(values[1])


def is_supported_python(version: Iterable[int] | None = None) -> bool:
    major_minor = _coerce_version_tuple(version)
    return MIN_VERSION <= major_minor <= MAX_VERSION


def ensure_supported_python(version: Iterable[int] | None = None) -> None:
    major_minor = _coerce_version_tuple(version)
    if not is_supported_python(major_minor):
        raise UnsupportedPythonError(major_minor)


__all__ = [
    "MIN_VERSION",
    "MAX_VERSION",
    "UnsupportedPythonError",
    "is_supported_python",
    "ensure_supported_python",
]
