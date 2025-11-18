from tools.vectorscan.python_compat import (
    MAX_SUPPORTED,
    MIN_SUPPORTED,
    PythonVersion,
    UnsupportedPythonVersion,
    ensure_supported_python,
    is_supported_python,
    supported_range_label,
)


def test_supported_range_label_matches_constants():
    label = supported_range_label()
    assert str(MIN_SUPPORTED[0]) in label
    assert str(MAX_SUPPORTED[0]) in label


def test_is_supported_python_accepts_versions_within_range():
    assert is_supported_python((MIN_SUPPORTED[0], MIN_SUPPORTED[1], 0))
    assert is_supported_python((MAX_SUPPORTED[0], MAX_SUPPORTED[1], 99))


def test_is_supported_python_rejects_out_of_range_versions():
    assert not is_supported_python((MIN_SUPPORTED[0] - 1, 12, 0))
    assert not is_supported_python((MAX_SUPPORTED[0] + 1, 0, 0))


def test_ensure_supported_python_raises_with_helpful_message():
    try:
        ensure_supported_python((MIN_SUPPORTED[0] - 1, 12, 0))
    except UnsupportedPythonVersion as exc:
        message = str(exc)
        assert "VectorScan requires Python" in message
        assert supported_range_label() in message
    else:  # pragma: no cover - defensive
        raise AssertionError("Unsupported version did not raise")


def test_ensure_supported_python_accepts_python_version_objects():
    version = PythonVersion(MIN_SUPPORTED[0], MIN_SUPPORTED[1], 5)
    ensure_supported_python(version)
