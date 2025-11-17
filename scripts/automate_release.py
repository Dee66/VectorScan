#!/usr/bin/env python3
"""
Automate local release tasks for VectorScan.

What this script can do:
- Prompt for version and run the packaging script to produce the zip + .sha256
- Optionally attempt GPG signing via the packaging script (--gpg-sign, --strict)
- Optionally generate an SPDX SBOM with syft; will offer to install syft to ~/.local/bin
- Optionally verify the SHA256 manifest and/or a cosign signature if present
- Optionally update the docs/checklist.md progress indicator

This is a convenience orchestrator for local workflows; the canonical CI flow
is defined in .github/workflows/release-bundle.yml.

Usage (interactive quick mode):
    python3 scripts/automate_release.py

Usage (non-interactive example):
  python3 scripts/automate_release.py \
    --version 1.0.1 --gpg-sign --strict --sbom --install-syft \
    --verify-sha --verify-cosign \
    --cosign-issuer https://token.actions.githubusercontent.com \
    --cosign-identity "https://github.com/Dee66/VectorScan/.github/workflows/release-bundle.yml@refs/tags/v1.0.1"
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
import re
import json
import webbrowser


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
DIST_DIR = REPO_ROOT / "dist"


def which(cmd: str) -> str | None:
    return shutil.which(cmd)


def default_user_bin() -> Path:
    override = os.environ.get("VSCAN_USER_BIN")
    if override:
        return Path(override).expanduser()
    home_env = os.environ.get("HOME")
    if home_env:
        return Path(home_env).expanduser() / ".local" / "bin"
    # Fallback to a repo-local bin directory when HOME is unavailable
    return (REPO_ROOT / ".vectorscan-user-bin").resolve()


def run(cmd: list[str], cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess:
    print(f"$ {' '.join(cmd)}")
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=check)


def prompt(text: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    val = input(f"{text}{suffix}: ").strip()
    return val or (default or "")


def prompt_yn(question: str, default: bool = True) -> bool:
    d = "Y/n" if default else "y/N"
    while True:
        resp = input(f"{question} ({d}): ").strip().lower()
        if not resp:
            return default
        if resp in {"y", "yes"}:
            return True
        if resp in {"n", "no"}:
            return False
        print("Please answer 'y' or 'n'.")


def ensure_syft(bin_dir: Path | None = None, auto_install: bool = False) -> tuple[bool, Path | None]:
    """Ensure syft is available. Optionally install it to bin_dir (default ~/.local/bin).

    Returns (available, path_to_syft_or_None)
    """
    existing = which("syft")
    if existing:
        return True, Path(existing)

    if not auto_install:
        return False, None

    # Attempt user-space install
    target = bin_dir or default_user_bin()
    target.mkdir(parents=True, exist_ok=True)
    install_cmd = [
        "bash", "-lc",
        f"curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b {str(target)} v1.20.0"
    ]
    try:
        # Use a login shell to respect PATH expansions; also prepend target to PATH for this process
        os.environ["PATH"] = f"{target}:{os.environ.get('PATH','')}"
        print("Attempting to install syft to", target)
        run(install_cmd, cwd=REPO_ROOT)
    except subprocess.CalledProcessError as e:
        print(f"Warning: syft install failed: {e}")
        return False, None
    new_path = which("syft")
    return (new_path is not None), (Path(new_path) if new_path else None)


def generate_sbom(version: str) -> Path | None:
    available, syft_path = ensure_syft()
    if not available:
        if prompt_yn("syft not found. Install to ~/.local/bin now?", default=True):
            ok, syft_path = ensure_syft(auto_install=True)
            if not ok:
                print("Skipping SBOM generation (syft unavailable).")
                return None
        else:
            print("Skipping SBOM generation.")
            return None

    DIST_DIR.mkdir(parents=True, exist_ok=True)
    out = DIST_DIR / f"vectorscan-v{version}.sbom.spdx.json"
    # Use modern syft syntax ("scan" replaces deprecated "packages").
    # Add --quiet to suppress non-critical warnings like 'no explicit name/version provided'.
    cmd = ["syft", "--quiet", "scan", f"dir:{REPO_ROOT.name}", "-o", f"spdx-json={out}"]
    try:
        run(cmd, cwd=REPO_ROOT.parent)
    except subprocess.CalledProcessError as e:
        print(f"SBOM generation failed: {e}")
        return None
    try:
        # Patch SBOM document metadata with explicit name/version to avoid future warnings
        patch_sbom_metadata(out, app_name=REPO_ROOT.name, app_version=version)
    except Exception:
        # Non-fatal if patching fails
        pass
    return out


def patch_sbom_metadata(sbom_path: Path, app_name: str, app_version: str) -> None:
    """Ensure the SPDX SBOM has a meaningful document name and namespace.

    This helps tools infer identity and suppresses warnings about missing name/version.
    """
    data = json.loads(sbom_path.read_text(encoding="utf-8"))
    # Top-level SPDX JSON typically has 'name' and 'documentNamespace'.
    # Set a descriptive name if missing or generic.
    desired_name = f"{app_name} v{app_version}"
    if not isinstance(data.get("name"), str) or not data["name"].strip():
        data["name"] = desired_name
    # Construct a stable document namespace using repo slug when available
    slug = get_repo_slug() or "local/VectorScan"
    ns = f"https://github.com/{slug}/sbom/v{app_version}"
    if not isinstance(data.get("documentNamespace"), str) or not data["documentNamespace"].startswith("http"):
        data["documentNamespace"] = ns
    # Optionally add externalDocumentRefs or creationInfo tweaks (not required)
    sbom_path.write_text(json.dumps(data, indent=2, sort_keys=False), encoding="utf-8")


def verify_sha256(zip_path: Path) -> bool:
    manifest = zip_path.with_suffix(zip_path.suffix + ".sha256")
    if not manifest.exists():
        print(f"No checksum manifest found at {manifest}")
        return False
    # Use sha256sum -c if available, else do a Python check
    if which("sha256sum"):
        try:
            run(["sha256sum", "-c", manifest.name], cwd=manifest.parent)
            print("SHA256 verification: OK")
            return True
        except subprocess.CalledProcessError:
            print("SHA256 verification: FAILED")
            return False
    else:
        import hashlib
        expected_line = manifest.read_text(encoding="utf-8").strip()
        expected_hash, expected_name = expected_line.split(maxsplit=1)[0], expected_line.split(maxsplit=1)[1].strip()
        if expected_name.endswith(zip_path.name):
            h = hashlib.sha256(zip_path.read_bytes()).hexdigest()
            ok = h == expected_hash
            print(f"SHA256 verification: {'OK' if ok else 'FAILED'}")
            return ok
        print("Checksum manifest does not match zip filename")
        return False


def verify_cosign_signature(blob: Path, sig: Path, issuer: str, identity: str) -> bool:
    if not which("cosign"):
        print("cosign is not installed; skipping cosign verify.")
        return False
    cmd = [
        "cosign", "verify-blob",
        "--certificate-oidc-issuer", issuer,
        "--certificate-identity", identity,
        "--signature", str(sig),
        str(blob),
    ]
    try:
        run(cmd, cwd=REPO_ROOT)
        print("cosign verify-blob: OK")
        return True
    except subprocess.CalledProcessError as e:
        print(f"cosign verify-blob: FAILED ({e})")
        return False


def ensure_cosign(bin_dir: Path | None = None, auto_install: bool = False) -> tuple[bool, Path | None]:
    """Ensure cosign is available. Optionally install it to bin_dir (default ~/.local/bin)."""
    existing = which("cosign")
    if existing:
        return True, Path(existing)
    if not auto_install:
        return False, None
    target = bin_dir or default_user_bin()
    target.mkdir(parents=True, exist_ok=True)
    url = "https://github.com/sigstore/cosign/releases/download/v2.2.4/cosign-linux-amd64"
    dest = target / "cosign"
    try:
        run(["bash", "-lc", f"curl -sSL -o {dest} {url} && chmod +x {dest}"])
        os.environ["PATH"] = f"{target}:{os.environ.get('PATH','')}"
    except subprocess.CalledProcessError as e:
        print(f"Warning: cosign install failed: {e}")
        return False, None
    newp = which("cosign")
    return (newp is not None), (Path(newp) if newp else None)


def list_semver_tags() -> list[str]:
    """Return tags of the form vX.Y.Z sorted descending (latest first)."""
    try:
        out = subprocess.check_output(
            ["git", "tag", "--list", "v[0-9]*.[0-9]*.[0-9]*", "--sort=-v:refname"], cwd=REPO_ROOT
        )
        tags = [t.strip() for t in out.decode().splitlines() if t.strip()]
        return tags
    except Exception:
        return []


def parse_semver(v: str) -> tuple[int, int, int] | None:
    try:
        parts = v.split(".")
        if len(parts) != 3:
            return None
        return int(parts[0]), int(parts[1]), int(parts[2])
    except Exception:
        return None


def bump_version(v: str, kind: str = "patch") -> str:
    p = parse_semver(v)
    if not p:
        return v
    major, minor, patch = p
    if kind == "major":
        return f"{major+1}.0.0"
    if kind == "minor":
        return f"{major}.{minor+1}.0"
    return f"{major}.{minor}.{patch+1}"


def is_git_clean() -> bool:
    try:
        out = subprocess.check_output(["git", "status", "--porcelain"], cwd=REPO_ROOT)
        return out.strip() == b""
    except Exception:
        return False


def get_repo_slug() -> str | None:
    """Return the 'owner/repo' slug derived from 'origin' remote URL if available."""
    try:
        out = subprocess.check_output(["git", "remote", "get-url", "origin"], cwd=REPO_ROOT)
        url = out.decode().strip()
        # Patterns: git@github.com:Owner/Repo.git or https://github.com/Owner/Repo.git
        m = re.search(r"github\.com[:/](?P<slug>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?:\.git)?$", url)
        if m:
            return m.group("slug")
    except Exception:
        pass
    return None


def has_gpg_secret_key() -> bool:
    if not which("gpg"):
        return False
    try:
        out = subprocess.check_output(["gpg", "--list-secret-keys", "--with-colons"], cwd=REPO_ROOT)
        # Look for lines beginning with 'sec'
        return any(line.startswith("sec") for line in out.decode().splitlines())
    except Exception:
        return False


@dataclass
class Options:
    version: str
    no_git_check: bool
    gpg_sign: bool
    strict: bool
    sbom: bool
    install_syft: bool
    verify_sha: bool
    verify_cosign: bool
    cosign_issuer: str | None
    cosign_identity: str | None
    skip_checklist: bool
    increment: str
    make_tag: bool
    sign_tag: bool
    push: bool
    gh_release: bool
    open_browser: bool
    auto_commit: bool
    commit_message: str | None


def parse_args(argv: list[str]) -> tuple[Options, bool]:
    p = argparse.ArgumentParser(description="Automate local release flow")
    p.add_argument("--version", help="Version (e.g., 1.0.1)")
    p.add_argument("--no-git-check", action="store_true", help="Pass --no-git-check to packaging script")
    p.add_argument("--gpg-sign", action="store_true", help="Attempt GPG signing via packaging script")
    p.add_argument("--strict", action="store_true", help="Fail if signing requested but not produced")
    p.add_argument("--sbom", action="store_true", help="Generate SPDX SBOM with syft")
    p.add_argument("--no-sbom", action="store_true", help="Disable SBOM generation even in quick mode")
    p.add_argument("--install-syft", action="store_true", help="Auto-install syft to ~/.local/bin if missing")
    p.add_argument("--verify-sha", action="store_true", help="Verify the generated SHA256 manifest")
    p.add_argument("--verify-cosign", action="store_true", help="Verify cosign signature if .sig present")
    p.add_argument("--cosign-issuer", help="OIDC issuer for cosign verify-blob")
    p.add_argument("--cosign-identity", help="OIDC identity for cosign verify-blob")
    p.add_argument("--skip-checklist", action="store_true", help="Skip docs/checklist.md progress update")
    p.add_argument("--increment", choices=["major", "minor", "patch"], default="patch", help="Default bump when auto-deriving version from latest tag")
    p.add_argument("--make-tag", action="store_true", help="Create a git tag vX.Y.Z after packaging")
    p.add_argument("--sign-tag", action="store_true", help="Sign the tag with GPG (requires a secret key)")
    p.add_argument("--push", action="store_true", help="Push the created tag to origin")
    p.add_argument("--gh-release", action="store_true", help="Create a GitHub Release using 'gh' and attach artifacts (draft)")
    p.add_argument("--open-browser", action="store_true", help="Open the created release in a browser")
    p.add_argument("--auto-commit", action="store_true", help="If the working tree is dirty, automatically create a commit before packaging")
    p.add_argument("--commit-message", help="Commit message to use when --auto-commit is enabled (will prompt with a sensible default if omitted)")
    p.add_argument("--yes", action="store_true", help="Non-interactive; accept defaults and flags provided")
    args = p.parse_args(argv)

    interactive = not args.yes
    opts = Options(
        version=args.version or "",
        no_git_check=args.no_git_check,
        gpg_sign=args.gpg_sign,
        strict=args.strict,
        sbom=args.sbom,
        install_syft=args.install_syft,
        verify_sha=args.verify_sha,
        verify_cosign=args.verify_cosign,
        cosign_issuer=args.cosign_issuer,
        cosign_identity=args.cosign_identity,
        skip_checklist=args.skip_checklist,
        increment=args.increment,
        make_tag=args.make_tag,
        sign_tag=args.sign_tag,
        push=args.push,
        gh_release=args.gh_release,
        open_browser=args.open_browser,
        auto_commit=args.auto_commit,
        commit_message=args.commit_message,
    )
    return opts, interactive


def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]
    opts, interactive = parse_args(argv)

    # Load cached defaults if present and user didn't explicitly set the flags
    def flag_present(flag: str) -> bool:
        return flag in argv

    try:
        cfg_path = REPO_ROOT / ".release_config.json"
        if cfg_path.exists():
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            if not flag_present("--sbom") and isinstance(cfg.get("sbom"), bool):
                opts.sbom = cfg["sbom"]
            if not flag_present("--verify-sha") and isinstance(cfg.get("verify_sha"), bool):
                opts.verify_sha = cfg["verify_sha"]
            if not flag_present("--verify-cosign") and isinstance(cfg.get("verify_cosign"), bool):
                opts.verify_cosign = cfg["verify_cosign"]
            if not flag_present("--increment") and isinstance(cfg.get("increment"), str):
                opts.increment = cfg["increment"]
    except Exception:
        pass

    # Version resolution
    if not opts.version:
        tags = list_semver_tags()
        base = tags[0].lstrip("v") if tags else "0.0.0"
        default_v = bump_version(base, kind=opts.increment) if base else "0.1.0"
        # Auto-accept default version to minimize prompts; user can override with --version
        opts.version = default_v

    # Quick-mode defaults and minimal prompting
    user_passed_any_flags = any([
        opts.gpg_sign, opts.strict, opts.sbom, opts.install_syft,
        opts.verify_sha, opts.verify_cosign, opts.cosign_issuer is not None,
        opts.cosign_identity is not None, opts.no_git_check, opts.skip_checklist
    ])

    if interactive and not user_passed_any_flags:
        # Apply sensible defaults automatically to minimize prompts
        defaults = {
            'gpg_sign': False,
            'strict': False,
            'sbom': True,
            'install_syft': True,
            'verify_sha': True,
            'verify_cosign': True,
            'no_git_check': False,
            'skip_checklist': False,
            'make_tag': False,
            'sign_tag': False,
            'push': False,
            'gh_release': False,
            'open_browser': False,
            'auto_commit': True,
        }
        opts.gpg_sign = defaults['gpg_sign']
        opts.strict = defaults['strict']
        opts.sbom = defaults['sbom']
        opts.install_syft = defaults['install_syft']
        opts.verify_sha = defaults['verify_sha']
        opts.verify_cosign = defaults['verify_cosign']
        opts.no_git_check = defaults['no_git_check']
        opts.skip_checklist = defaults['skip_checklist']
        opts.make_tag = defaults['make_tag']
        opts.sign_tag = defaults['sign_tag']
        opts.push = defaults['push']
        opts.gh_release = defaults['gh_release']
        opts.open_browser = defaults['open_browser']
        opts.auto_commit = defaults['auto_commit']
    else:
        # Granular prompts only when the user has provided some flags and wants to refine
            if not opts.gpg_sign:
                opts.gpg_sign = prompt_yn("Attempt GPG signing?", default=False)
            if opts.gpg_sign and not opts.strict:
                opts.strict = prompt_yn("Fail if GPG signature not produced (strict)?", default=False)
            if not opts.sbom and not getattr(sys.modules[__name__], 'args', None):
                # Respect --no-sbom if provided
                opts.sbom = prompt_yn("Generate SPDX SBOM with syft?", default=True)
            if opts.sbom and not opts.install_syft:
                opts.install_syft = prompt_yn("Auto-install syft to ~/.local/bin if missing?", default=True)
            if not opts.verify_sha:
                opts.verify_sha = prompt_yn("Verify SHA256 manifest?", default=True)
            if not opts.verify_cosign:
                opts.verify_cosign = prompt_yn("Verify cosign signature if present?", default=False)
            if not opts.make_tag:
                opts.make_tag = prompt_yn("Create git tag vX.Y.Z after packaging?", default=False)
            if opts.make_tag and not opts.sign_tag:
                opts.sign_tag = prompt_yn("GPG-sign the tag (requires secret key)?", default=False)
            if opts.make_tag and not opts.push:
                opts.push = prompt_yn("Push the tag to origin?", default=False)
            if not opts.gh_release:
                opts.gh_release = prompt_yn("Create a GitHub Release (draft) with assets?", default=False)
            if opts.gh_release and not opts.open_browser:
                opts.open_browser = prompt_yn("Open the created release in your browser?", default=True)

    # If user requested GPG signing, ensure a key exists; assist if missing
    if opts.gpg_sign and not has_gpg_secret_key():
        msg = "GPG signing requested but no secret key found (or gpg missing)."
        if interactive:
            print(msg)
            if prompt_yn("Continue without GPG signing?", default=True):
                opts.gpg_sign = False
            else:
                print("Aborting. Please generate/import a GPG key and retry.")
                return 1
        else:
            print(msg + " Proceeding without GPG signing.")
            opts.gpg_sign = False

    # Honor explicit --no-sbom
    if '--no-sbom' in (argv or sys.argv[1:]):
        opts.sbom = False

    # If git tree is dirty: optionally auto-commit, otherwise offer to continue/abort
    if not opts.no_git_check and not is_git_clean():
        def attempt_commit():
            default_msg = f"chore: release prep v{opts.version} (automation, SBOM, docs)"
            msg = opts.commit_message
            if interactive and not msg:
                msg = prompt("Enter commit message", default=default_msg)
            msg = msg or default_msg
            try:
                run(["git", "add", "-A"], cwd=REPO_ROOT)
                run(["git", "commit", "-m", msg], cwd=REPO_ROOT, check=False)
            except Exception as e:
                print(f"Warning: commit attempt encountered an issue: {e}")
            return is_git_clean()

        if opts.auto_commit:
            clean_after = attempt_commit()
            if not clean_after:
                if interactive and prompt_yn("Working tree still not clean. Skip clean check and continue?", default=False):
                    opts.no_git_check = True
                elif interactive and prompt_yn("Attempt another commit (perhaps you staged new changes)?", default=False):
                    attempt_commit()
                    if not is_git_clean() and not opts.no_git_check:
                        if prompt_yn("Still dirty. Continue anyway?", default=False):
                            opts.no_git_check = True
                        else:
                            print("Aborting due to dirty working tree.")
                            return 1
                elif not interactive:
                    print("Warning: git tree not clean and --no-git-check not set. Proceeding may fail.")
                else:
                    print("Aborting due to dirty working tree.")
                    return 1
        else:
            if interactive:
                if prompt_yn("Git working tree is not clean. Continue without committing (skip clean check)?", default=False):
                    opts.no_git_check = True
                else:
                    if prompt_yn("Commit changes before continuing?", default=True):
                        if not attempt_commit() and not prompt_yn("Commit didn't clean everything. Continue anyway?", default=False):
                            print("Aborting due to dirty working tree.")
                            return 1
                    else:
                        print("Aborting due to dirty working tree.")
                        return 1
            else:
                print("Warning: git tree not clean and --no-git-check not set. Packaging may fail.")

    # 1) Build the release bundle
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    pkg_script = SCRIPTS_DIR / "create_release_bundle.py"
    if not pkg_script.exists():
        print(f"Error: packaging script not found at {pkg_script}")
        return 2
    cmd = [sys.executable, str(pkg_script), "--version", opts.version]
    if opts.no_git_check:
        cmd.append("--no-git-check")
    if opts.gpg_sign:
        cmd.append("--gpg-sign")
    if opts.strict:
        cmd.append("--strict")

    try:
        # Capture stdout to learn artifact paths
        print("Running packaging script...")
        out = subprocess.check_output(cmd, cwd=REPO_ROOT)
        print(out.decode())
    except subprocess.CalledProcessError as e:
        print("Packaging failed:")
        if e.stdout:
            print(e.stdout.decode())
        if e.stderr:
            print(e.stderr.decode(), file=sys.stderr)
        return e.returncode or 1

    zip_path = DIST_DIR / f"vectorguard-v{opts.version}.zip"
    sha_path = zip_path.with_suffix(".zip.sha256")
    sig_path = zip_path.with_suffix(".zip.asc")

    # 2) SBOM generation
    sbom_path: Path | None = None
    if opts.sbom:
        if opts.install_syft:
            # best-effort auto-install; generate_sbom() will prompt if needed when not interactive
            pass
        sbom_path = generate_sbom(opts.version)

    # 3) Verifications
    if opts.verify_sha and zip_path.exists():
        verify_sha256(zip_path)

    if opts.verify_cosign and sbom_path:
        # Correct signature path: just append .sig (previous logic duplicated .spdx)
        sbom_sig = sbom_path.with_suffix(sbom_path.suffix + ".sig")
        if sbom_sig.exists():
            issuer = opts.cosign_issuer or "https://token.actions.githubusercontent.com"
            repo_slug = get_repo_slug() or "Dee66/VectorScan"
            identity_default = f"https://github.com/{repo_slug}/.github/workflows/release-bundle.yml@refs/tags/v{opts.version}"
            identity = opts.cosign_identity or identity_default
            if not which("cosign"):
                if interactive and prompt_yn("cosign not found. Install to ~/.local/bin now?", default=True):
                    ensure_cosign(auto_install=True)
            verify_cosign_signature(sbom_path, sbom_sig, issuer, identity)
        else:
            print(f"No cosign signature found for SBOM at {sbom_sig}; skipping verify.")

    # 5) Tagging and pushing
    tag_ref = f"v{opts.version}"
    if opts.make_tag:
        # Check if tag exists
        try:
            run(["git", "rev-parse", "-q", "--verify", f"refs/tags/{tag_ref}"], cwd=REPO_ROOT)
            tag_exists = True
        except subprocess.CalledProcessError:
            tag_exists = False
        if tag_exists:
            print(f"Tag {tag_ref} already exists. Skipping tag creation.")
        else:
            tag_cmd = ["git", "tag"]
            if opts.sign_tag and has_gpg_secret_key():
                tag_cmd += ["-s", tag_ref, "-m", f"Release {tag_ref}"]
            else:
                tag_cmd += ["-a", tag_ref, "-m", f"Release {tag_ref}"]
            try:
                run(tag_cmd, cwd=REPO_ROOT)
                print(f"Created tag {tag_ref}")
            except subprocess.CalledProcessError as e:
                print(f"Failed to create tag {tag_ref}: {e}")
                # Continue without fatal error
        if opts.push:
            try:
                run(["git", "push", "origin", tag_ref], cwd=REPO_ROOT)
                print(f"Pushed tag {tag_ref} to origin")
            except subprocess.CalledProcessError as e:
                print(f"Failed to push tag {tag_ref}: {e}")

    # 6) GitHub release (draft)
    if opts.gh_release:
        if not which("gh"):
            print("GitHub CLI 'gh' not found; skipping release creation.")
        else:
            files = [str(zip_path)]
            if sha_path.exists():
                files.append(str(sha_path))
            if sbom_path and sbom_path.exists():
                files.append(str(sbom_path))
                sbom_sig = sbom_path.with_suffix(".spdx.json.sig")
                if sbom_sig.exists():
                    files.append(str(sbom_sig))
            title = f"vectorguard {tag_ref}"
            notes = "Automated release created by automate_release.py"
            cmd = ["gh", "release", "create", tag_ref, "--draft", "-t", title, "-n", notes] + files
            try:
                run(cmd, cwd=REPO_ROOT)
                print(f"Created draft GitHub Release {tag_ref}")
                if opts.open_browser:
                    try:
                        run(["gh", "release", "view", tag_ref, "--web"], cwd=REPO_ROOT)
                    except Exception:
                        # Fallback to webbrowser open on repo URL
                        slug = get_repo_slug()
                        if slug:
                            webbrowser.open(f"https://github.com/{slug}/releases/tag/{tag_ref}")
            except subprocess.CalledProcessError as e:
                print(f"Failed to create GitHub Release: {e}")

    # 4) Update checklist progress
    if not opts.skip_checklist:
        updater = SCRIPTS_DIR / "update_checklist_progress.py"
        if updater.exists():
            try:
                run([sys.executable, str(updater)], cwd=REPO_ROOT)
            except subprocess.CalledProcessError as e:
                print(f"Checklist update failed: {e}")
        else:
            print(f"Note: {updater} not found; skipping checklist update.")

    # Summary
    print("\nArtifacts:")
    if zip_path.exists():
        print(f" - {zip_path}")
    if sha_path.exists():
        print(f" - {sha_path}")
    if sig_path.exists():
        print(f" - {sig_path}")
    if sbom_path and sbom_path.exists():
        print(f" - {sbom_path}")
        sig = sbom_path.with_suffix(".spdx.json.sig")
        if sig.exists():
            print(f" - {sig}")

    print("\nDone.")
    # Persist lightweight config of last choices
    try:
        cfg = {
            "increment": opts.increment,
            "sbom": opts.sbom,
            "verify_sha": opts.verify_sha,
            "verify_cosign": opts.verify_cosign,
        }
        (REPO_ROOT / ".release_config.json").write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
