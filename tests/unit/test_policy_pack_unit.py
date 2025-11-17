import hashlib
import importlib
import os

import pytest


def test_policy_pack_hash_respects_env(tmp_path, monkeypatch):
    file_a = tmp_path / "alpha.rego"
    file_a.write_text("package alpha\nallow = true\n", encoding="utf-8")
    nested_dir = tmp_path / "policies"
    nested_dir.mkdir()
    file_b = nested_dir / "beta.rego"
    file_b.write_text("package beta\nallow = false\n", encoding="utf-8")

    target = os.pathsep.join([str(file_a), str(nested_dir)])
    monkeypatch.setenv("VSCAN_POLICY_PACK_FILES", target)
    monkeypatch.delenv("VSCAN_POLICY_PACK_HASH", raising=False)

    import tools.vectorscan.policy_pack as policy_pack

    importlib.reload(policy_pack)
    policy_pack.policy_pack_hash.cache_clear()
    result = policy_pack.policy_pack_hash()

    digest = hashlib.sha256()
    files = sorted({file_a.resolve(), file_b.resolve()})
    for path in files:
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())

    assert result == digest.hexdigest()


def test_policy_pack_hash_errors_when_files_missing(tmp_path, monkeypatch):
    missing = tmp_path / "missing.rego"
    monkeypatch.setenv("VSCAN_POLICY_PACK_FILES", str(missing))
    monkeypatch.delenv("VSCAN_POLICY_PACK_HASH", raising=False)

    import tools.vectorscan.policy_pack as policy_pack

    importlib.reload(policy_pack)
    policy_pack.policy_pack_hash.cache_clear()

    with pytest.raises(policy_pack.PolicyPackError):
        policy_pack.policy_pack_hash()


def test_policy_pack_hash_errors_when_env_has_no_rego(tmp_path, monkeypatch):
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    monkeypatch.setenv("VSCAN_POLICY_PACK_FILES", str(empty_dir))
    monkeypatch.delenv("VSCAN_POLICY_PACK_HASH", raising=False)

    import tools.vectorscan.policy_pack as policy_pack

    importlib.reload(policy_pack)
    policy_pack.policy_pack_hash.cache_clear()

    with pytest.raises(policy_pack.PolicyPackError):
        policy_pack.policy_pack_hash()
