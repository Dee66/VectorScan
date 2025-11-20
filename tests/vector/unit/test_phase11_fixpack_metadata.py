"""Phase 11 tests for fixpack metadata parsing."""

from src.vectorscan.fixpack.loader import get_fixpack_metadata


def test_fixpack_metadata_loaded():
    metadata = get_fixpack_metadata("P-VEC-001")
    assert metadata is not None
    assert metadata["fixpack_id"] == "P-VEC-001"
    assert metadata["description"] == "Disable public access on vector index."
    assert "public_access = false" in metadata["terraform_patch"]


def test_missing_fixpack_returns_none():
    assert get_fixpack_metadata("P-VEC-999") is None
