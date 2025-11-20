"""Phase 10 tests for fixpack hint existence."""

from src.vectorscan.fixpack.loader import get_fixpack_hint


def test_fixpack_loader_finds_files():
    assert get_fixpack_hint("P-VEC-001") == "fixpack:P-VEC-001"
    assert get_fixpack_hint("P-VEC-004") == "fixpack:P-VEC-004"
