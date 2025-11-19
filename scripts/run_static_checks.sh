#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

python3 tools/vectorscan/copilot_scaffolder.py --dry-run
python3 tools/vectorscan/copilot_suite_generator.py --check
python3 tools/vectorscan/copilot_api_stubber.py --check
python3 tools/vectorscan/copilot_determinism_guard.py --fixtures tests/fixtures/tfplan_pass.json tests/fixtures/tfplan_fail.json
python3 tools/vectorscan/copilot_workflow_generator.py --check
ruff check .
black --check .
isort --check-only --diff .
mypy .
