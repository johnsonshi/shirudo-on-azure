#!/usr/bin/env bash
# Install git hooks that run tools/check_leaks.py: on the staged files before
# every commit, and on the whole reachable history before every push.
set -euo pipefail
cd "$(dirname "$0")/.."
hooks=$(git rev-parse --git-path hooks)
mkdir -p "$hooks"
printf '#!/bin/sh\nexec python3 "$(git rev-parse --show-toplevel)/tools/check_leaks.py" --staged\n' >"$hooks/pre-commit"
printf '#!/bin/sh\nexec python3 "$(git rev-parse --show-toplevel)/tools/check_leaks.py"\n' >"$hooks/pre-push"
chmod +x "$hooks/pre-commit" "$hooks/pre-push"
echo "installed pre-commit and pre-push leak checks in $hooks"
