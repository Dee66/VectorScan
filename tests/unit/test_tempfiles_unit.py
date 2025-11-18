from __future__ import annotations

from tools.vectorscan import tempfiles


def test_secure_temp_file_creates_unique_files(tmp_path):
    first = tempfiles.secure_temp_file(prefix="unit-", suffix=".json", directory=tmp_path)
    second = tempfiles.secure_temp_file(prefix="unit-", suffix=".json", directory=tmp_path)

    assert first.parent == tmp_path
    assert second.parent == tmp_path
    assert first != second
    assert first.exists()
    assert second.exists()


def test_secure_temp_dir_lives_under_directory(tmp_path):
    nested_root = tmp_path / "nested"
    nested_root.mkdir()

    dir_path = tempfiles.secure_temp_dir(prefix="dir-", directory=nested_root)
    assert dir_path.is_dir()
    assert dir_path.parent == nested_root
