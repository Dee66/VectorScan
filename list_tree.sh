#!/usr/bin/env bash
# list_tree.sh
# Purpose: List files and directories up to a configurable depth relative to the directory
#          where the script is EXECUTED FROM (PWD), not the repo root. Optionally accept a
#          target directory argument. Output written inside that target directory.
#
# Features:
#   - Skips hidden directories (starting with .) and any node_modules directories.
#   - Depth default = 3 (override via env MAX_DEPTH or --depth flag).
#   - Output filename default = tree.txt (override via --out flag).
#   - Safe for paths with spaces; uses set -euo pipefail for robustness.
#
# Usage:
#   ./list_tree.sh                 # operate on current directory
#   ./list_tree.sh path/to/dir     # operate on specified dir
#   ./list_tree.sh --depth 4 --out listing.txt ./src
#
# Env overrides:
#   MAX_DEPTH=4 ./list_tree.sh
#
set -euo pipefail

TARGET="."
OUTPUT="tree.txt"
MAX_DEPTH="${MAX_DEPTH:-3}"

print_help() {
    sed -n '1,/^set -euo pipefail$/p' "$0" | sed 's/^# \{0,1\}//' | grep -v '^#!/'
}

ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--depth)
            MAX_DEPTH="$2"; shift 2 ;;
        -o|--out)
            OUTPUT="$2"; shift 2 ;;
        -h|--help)
            print_help; exit 0 ;;
        --) shift; break ;;
        -*) echo "Unknown option: $1" >&2; exit 1 ;;
        *) ARGS+=("$1"); shift ;;
    esac
done

if [[ ${#ARGS[@]} -gt 0 ]]; then
    TARGET="${ARGS[0]}"
fi

if [[ ! -d "$TARGET" ]]; then
    echo "Target directory not found: $TARGET" >&2
    exit 1
fi

# Normalize target path
TARGET_ABS="$(cd "$TARGET" && pwd)"

cd "$TARGET_ABS"

# Build exclusion expression: prune hidden dirs & node_modules
# Explanation: \( -type d -name '.*' -prune -o -type d -name 'node_modules' -prune -o -print \)
find . -mindepth 1 -maxdepth "$MAX_DEPTH" \
    \( -type d -name '.*' -prune -o -type d -name 'node_modules' -prune -o -print \) \
    | sed 's|^./||' > "$OUTPUT"

echo "Output saved to $TARGET_ABS/$OUTPUT (depth=$MAX_DEPTH)"
