from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
from typing import Tuple
from urllib import error, request

from tools.vectorscan.environment import _now
from tools.vectorscan.tempfiles import secure_temp_file

__all__ = ["write_local_capture", "maybe_post"]


def write_local_capture(payload: dict) -> Path:
    """Persist the lead payload to the primary captures directory with a hashed filename.

    Falls back to the OS temp directory if the primary location cannot be written.
    """

    stamp = _now()
    payload_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()[:10]
    prefix = f"lead_{stamp}_{payload_hash}_"
    primary = Path(__file__).parent / "captures"
    fallback = Path(tempfile.gettempdir()) / "vectorscan-captures"
    errors: list[str] = []

    for directory in (primary, fallback):
        try:
            target = secure_temp_file(prefix=prefix, suffix=".json", directory=directory)
            target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            return target
        except OSError as exc:
            errors.append(f"{directory}: {exc}")
            continue

    raise OSError("Failed to write lead capture: " + "; ".join(errors))


def maybe_post(endpoint: str, payload: dict, timeout: int = 5) -> Tuple[bool, str]:
    """Send the lead payload to the provided endpoint, returning success flag and message."""

    try:
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(endpoint, data=data, headers={"Content-Type": "application/json"}, method="POST")
        with request.urlopen(req, timeout=timeout) as resp:
            code = getattr(resp, "status", 200)
            return (200 <= code < 300), f"HTTP {code}"
    except (error.URLError, ValueError, OSError, Exception) as exc:
        return False, str(exc)
