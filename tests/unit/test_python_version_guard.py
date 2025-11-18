import importlib

import pytest

from tools.vectorscan.constants import EXIT_CONFIG_ERROR
from tools.vectorscan.python_compat import UnsupportedPythonVersion


def test_vectorscan_import_exits_on_unsupported_python(monkeypatch):
    import tools.vectorscan.vectorscan as vectorscan_module

    def boom():
        raise UnsupportedPythonVersion("VectorScan requires Python 3.9–3.12 but detected 3.8")

    with monkeypatch.context() as ctx:
        ctx.setattr(
            "tools.vectorscan.python_compat.ensure_supported_python",
            boom,
        )

        with pytest.raises(SystemExit) as excinfo:
            importlib.reload(vectorscan_module)

        assert excinfo.value.code == EXIT_CONFIG_ERROR

    importlib.reload(vectorscan_module)
