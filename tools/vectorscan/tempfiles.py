"""Secure tempfile helpers shared across VectorScan utilities."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Optional


def secure_temp_file(
    *,
    prefix: str = "vectorscan-",
    suffix: str = "",
    directory: Optional[Path | str] = None,
) -> Path:
    """Create a secure temporary file and return its Path.

    This wraps :func:`tempfile.mkstemp` to avoid predictable filenames and ensures the
    containing directory exists before creation. The file descriptor returned by
    ``mkstemp`` is immediately closed so callers can manage the file via pathlib.
    """

    dir_path = Path(directory) if directory else Path(tempfile.gettempdir())
    dir_path.mkdir(parents=True, exist_ok=True)
    fd, path_str = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=str(dir_path))
    os.close(fd)
    return Path(path_str)


def secure_temp_dir(*, prefix: str = "vectorscan-", directory: Optional[Path | str] = None) -> Path:
    """Create a secure temporary directory and return it as a Path."""

    base_dir = Path(directory) if directory else None
    tmp_path = tempfile.mkdtemp(prefix=prefix, dir=str(base_dir) if base_dir else None)
    return Path(tmp_path)
