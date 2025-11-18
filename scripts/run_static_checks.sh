#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

ruff check .
black --check .
isort --check-only --diff .
mypy .
