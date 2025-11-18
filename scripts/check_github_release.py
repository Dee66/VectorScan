"""Automate the GitHub checks for the VectorScan CLI release workflow."""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, Iterable, Sequence

API_BASE = "https://api.github.com/repos"
USER_AGENT = "VectorScanReleaseChecker/1.0"

REQUIRED_ASSET_SUFFIXES = [
    "vectorscan-free.zip",
    "vectorscan-free.zip.sha256",
    "vectorscan-free.zip.sig",
    "vectorscan-free.zip.crt",
]


class GithubQueryError(RuntimeError):
    pass


def fetch_json(url: str, token: str | None) -> Any:
    headers = {"Accept": "application/vnd.github.v3+json", "User-Agent": USER_AGENT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request) as response:
            payload = response.read().decode("utf-8")
            return json.loads(payload)
    except urllib.error.HTTPError as exc:
        raise GithubQueryError(f"GitHub API request failed ({exc.code}): {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise GithubQueryError(f"Could not reach GitHub API: {exc.reason}") from exc


def assert_release_assets(assets: Sequence[Dict[str, Any]]) -> Sequence[str]:
    present = {asset.get("name", "") for asset in assets}
    missing = [suffix for suffix in REQUIRED_ASSET_SUFFIXES if suffix not in present]
    return missing


def query_release(repo: str, token: str | None) -> Dict[str, Any]:
    url = f"{API_BASE}/{repo}/releases/latest"
    return fetch_json(url, token)


def query_workflow(repo: str, workflow: str, branch: str, token: str | None) -> Dict[str, Any]:
    url = f"{API_BASE}/{repo}/actions/workflows/{workflow}/runs?per_page=5&branch={branch}"
    return fetch_json(url, token)


def print_release_summary(release: Dict[str, Any]) -> None:
    print("GitHub release:")
    print(f"  tag: {release.get('tag_name')}")
    print(f"  name: {release.get('name')}")
    print(f"  published_at: {release.get('published_at')}")


def print_workflow_summary(runs: Sequence[Dict[str, Any]]) -> None:
    if not runs:
        print("No workflow runs found.")
        return
    latest = runs[0]
    print("Workflow run summary:")
    print(f"  id: {latest.get('id')}")
    print(f"  name: {latest.get('name')}")
    print(f"  status: {latest.get('status')}")
    print(f"  conclusion: {latest.get('conclusion')}")
    print(f"  html_url: {latest.get('html_url')}")


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the VectorScan GitHub release and workflow status."
    )
    parser.add_argument(
        "--repo", type=str, default="Dee66/VectorScan", help="GitHub repo to check."
    )
    parser.add_argument(
        "--workflow",
        type=str,
        default="vectorscan-distribution.yml",
        help="Workflow filename to inspect.",
    )
    parser.add_argument(
        "--branch", type=str, default="main", help="Branch to scope the workflow run query."
    )
    parser.add_argument("--token", type=str, help="GitHub token (or set GITHUB_TOKEN).")
    seq = tuple(argv) if argv is not None else None
    args = parser.parse_args(seq or None)

    token = args.token or os.getenv("GITHUB_TOKEN")
    success = True

    print("Checking GitHub release assets...")
    try:
        release = query_release(args.repo, token)
    except GithubQueryError as exc:
        print(f"Error querying release: {exc}")
        return 2

    print_release_summary(release)
    assets = release.get("assets", [])
    missing = assert_release_assets(assets)
    if missing:
        print(f"Missing release assets: {', '.join(missing)}")
        success = False
    else:
        print("All required release assets are present.")

    print("\nChecking workflow runs...")
    try:
        workflow_result = query_workflow(args.repo, args.workflow, args.branch, token)
    except GithubQueryError as exc:
        print(f"Error querying workflow: {exc}")
        return 3

    runs = workflow_result.get("workflow_runs", [])
    print_workflow_summary(runs)
    if runs:
        conclusion = runs[0].get("conclusion")
        if conclusion != "success":
            print(f"Latest workflow run conclusion is '{conclusion}', expected 'success'.")
            success = False
    else:
        success = False

    return 0 if success else 4


if __name__ == "__main__":
    raise SystemExit(main())
