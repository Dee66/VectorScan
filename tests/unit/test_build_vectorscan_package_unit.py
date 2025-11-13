from hypothesis import given, strategies as st

# Property-based test: write_sha256 with random file content
@given(content=st.binary(min_size=0, max_size=1024))
def test_write_sha256_property(content):
    import tempfile
    from pathlib import Path
    from build_vectorscan_package import write_sha256
    with tempfile.TemporaryDirectory() as tmpdirname:
        tmp_path = Path(tmpdirname)
        f = tmp_path / "rand.txt"
        f.write_bytes(content)
        write_sha256(f)
        sha = f.with_suffix(f.suffix + ".sha256")
        assert sha.exists()
        with open(sha, encoding="utf-8") as s:
            line = s.read()
            assert "rand.txt" in line

# Combinatorial test: multiple files in main
def test_main_multiple_files(monkeypatch, tmp_path):
    from build_vectorscan_package import main
    monkeypatch.setattr("build_vectorscan_package.DIST", tmp_path)
    files = []
    for i in range(5):
        f = tmp_path / f"file{i}.txt"
        f.write_text(f"content {i}", encoding="utf-8")
        files.append(f)
    monkeypatch.setattr("build_vectorscan_package.FILES", files)
    monkeypatch.setattr("build_vectorscan_package.SRC", tmp_path)
    monkeypatch.setattr("build_vectorscan_package.REPO_ROOT", tmp_path)
    main()
    zf = tmp_path / "vectorscan-free.zip"
    assert zf.exists()
    import zipfile
    with zipfile.ZipFile(zf, "r") as z:
        for i in range(5):
            assert f"file{i}.txt" in z.namelist()

# Negative test: write_sha256 with directory
def test_write_sha256_directory(tmp_path):
    from build_vectorscan_package import write_sha256
    d = tmp_path / "adir"
    d.mkdir()
    import pytest
    with pytest.raises(Exception):
        write_sha256(d)

# Stress test: write_sha256 on many files
def test_write_sha256_many_files(tmp_path):
    from build_vectorscan_package import write_sha256
    files = []
    for i in range(100):
        f = tmp_path / f"f{i}.txt"
        f.write_text(f"data {i}")
        files.append(f)
    for f in files:
        write_sha256(f)
        sha = f.with_suffix(f.suffix + ".sha256")
        assert sha.exists()
# --- Additional test expansions for uncovered logic and error handling ---
import pytest

def test_write_sha256_overwrite(tmp_path):
    f = tmp_path / "foo.txt"
    f.write_text("hello world", encoding="utf-8")
    write_sha256(f)
    # Overwrite and re-run
    f.write_text("new content", encoding="utf-8")
    write_sha256(f)
    sha = f.with_suffix(f.suffix + ".sha256")
    assert sha.exists()
    with open(sha, encoding="utf-8") as s:
        line = s.read()
        assert "foo.txt" in line

def test_main_empty_files(monkeypatch, tmp_path):
    monkeypatch.setattr("build_vectorscan_package.DIST", tmp_path)
    monkeypatch.setattr("build_vectorscan_package.FILES", [])
    monkeypatch.setattr("build_vectorscan_package.SRC", tmp_path)
    monkeypatch.setattr("build_vectorscan_package.REPO_ROOT", tmp_path)
    main()
    zf = tmp_path / "vectorscan-free.zip"
    assert zf.exists()
    import zipfile
    with zipfile.ZipFile(zf, "r") as z:
        assert "LICENSE_FREE.txt" in z.namelist()
from build_vectorscan_package import write_sha256, main


# Parameterized and edge case tests for write_sha256
import pytest
import os
@pytest.mark.parametrize("content", [b"hello world", b"", b"1234567890"*1000, b"edgecase", b"another test", b"\x00\x01\x02"])
def test_write_sha256_cases(tmp_path, content):
    f = tmp_path / "foo.txt"
    f.write_bytes(content)
    write_sha256(f)
    sha = f.with_suffix(f.suffix + ".sha256")
    assert sha.exists()
    with open(sha, encoding="utf-8") as s:
        line = s.read()
        assert "foo.txt" in line

# Edge: non-existent file
def test_write_sha256_nonexistent(tmp_path):
    f = tmp_path / "nope.txt"
    with pytest.raises(FileNotFoundError):
        write_sha256(f)


def test_main_success(monkeypatch, tmp_path):
    # Patch DIST and FILES to use tmp_path
    monkeypatch.setattr("build_vectorscan_package.DIST", tmp_path)
    test_file = tmp_path / "vectorscan.py"
    test_file.write_text("print('hi')", encoding="utf-8")
    monkeypatch.setattr("build_vectorscan_package.FILES", [test_file])
    monkeypatch.setattr("build_vectorscan_package.SRC", tmp_path)
    monkeypatch.setattr("build_vectorscan_package.REPO_ROOT", tmp_path)
    main()
    zf = tmp_path / "vectorscan-free.zip"
    assert zf.exists()
    import zipfile
    with zipfile.ZipFile(zf, "r") as z:
        assert "LICENSE_FREE.txt" in z.namelist()
        assert any("vectorscan.py" in n for n in z.namelist())

# Edge: test main with missing file
def test_main_missing_file(monkeypatch, tmp_path):
    monkeypatch.setattr("build_vectorscan_package.DIST", tmp_path)
    # FILES contains a file that does not exist
    missing = tmp_path / "notfound.py"
    monkeypatch.setattr("build_vectorscan_package.FILES", [missing])
    monkeypatch.setattr("build_vectorscan_package.SRC", tmp_path)
    monkeypatch.setattr("build_vectorscan_package.REPO_ROOT", tmp_path)
    # Should not raise, but print warning
    main()
    zf = tmp_path / "vectorscan-free.zip"
    assert zf.exists()
    import zipfile
    with zipfile.ZipFile(zf, "r") as z:
        assert "LICENSE_FREE.txt" in z.namelist()
