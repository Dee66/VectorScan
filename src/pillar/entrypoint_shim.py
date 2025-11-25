from __future__ import annotations

import importlib
import sys
from functools import lru_cache
from typing import Callable, Optional

from src.pillar.compat import error_text

__all__ = [
    "emit_strict_mode_banner",
]


def _fallback_print(payload: str) -> None:
    stream = sys.stderr
    stream.write(f"{payload}\n")
    stream.flush()


@lru_cache(maxsize=1)
def _legacy_safe_print() -> Optional[Callable[..., None]]:
    try:
        module = importlib.import_module("tools.vectorscan.vectorscan")
    except ModuleNotFoundError:
        return None
    printer = getattr(module, "_safe_print", None)
    return printer if callable(printer) else None


def emit_strict_mode_banner(detail: str, include_unexpected: bool = False) -> None:
    message = error_text.strict_mode(detail)
    printer = _legacy_safe_print()
    if printer is None:
        _fallback_print(message)
    else:
        printer(message, stream=sys.stderr)
    if include_unexpected:
        unexpected_message = "Unexpected scan failure"
        if printer is None:
            _fallback_print(unexpected_message)
        else:
            printer(unexpected_message, stream=sys.stderr)
    # Always add a trailing blank line to match legacy banner formatting.
    if printer is None:
        _fallback_print("")
    else:
        printer("", stream=sys.stderr)
