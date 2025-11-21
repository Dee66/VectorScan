from __future__ import annotations

import io

import pytest

from vectorscan import renderer  # pyright: ignore[reportMissingImports]


def test_safe_print_handles_unicode(monkeypatch: pytest.MonkeyPatch) -> None:
    sink = io.BytesIO()

    class _DummyStdout:
        def __init__(self) -> None:
            self.buffer = sink

        def flush(self) -> None:  # pragma: no cover - parity with TextIO
            pass

    monkeypatch.setattr(renderer.sys, "stdout", _DummyStdout())

    renderer._safe_print("hello 🚀", stream=None)  # pylint: disable=protected-access
    assert sink.getvalue() == "hello 🚀\n".encode("utf-8")
