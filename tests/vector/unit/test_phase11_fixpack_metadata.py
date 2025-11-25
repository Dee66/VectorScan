"""Phase 11 tests for fixpack metadata parsing."""

from src.vectorscan.fixpack import get_fixpack_metadata


def test_fixpack_metadata_returns_none():
    assert get_fixpack_metadata("P-VEC-001") is None
    assert get_fixpack_metadata("P-VEC-999") is None
