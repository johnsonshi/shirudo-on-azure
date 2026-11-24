#!/usr/bin/env bash
# Install git hooks that run tools/check_leaks.py: on the staged files before
# every commit, and on the whole reachable history before every push.
set -euo pipefail
cd "$(dirname "$0")/.."
hooks=$(git rev-parse --git-path hooks)
[[ -z "$(git config --get core.hooksPath)" ]] ||
	{ echo 'custom core.hooksPath: add the checks to your existing hook chain instead' >&2; exit 1; }
[[ "$(git rev-parse --git-dir)" == "$(git rev-parse --git-common-dir)" ]] ||
	{ echo 'install in a standalone clone; linked worktrees share hooks' >&2; exit 1; }
mkdir -p "$hooks"
for hook in pre-commit pre-push; do
	arg=""
	[[ "$hook" != pre-commit ]] || arg=" --staged"
	body="$(printf '#!/bin/sh\nexec python3 "$(git rev-parse --show-toplevel)/tools/check_leaks.py"%s\n' "$arg")"
	path="$hooks/$hook"
	if [[ -e "$path" || -L "$path" ]]; then
		[[ -f "$path" && ! -L "$path" && "$(cat "$path")" == "$body" ]] ||
			{ echo "existing $hook: nothing overwritten; chain the check manually" >&2; exit 1; }
	else
		( set -o noclobber; printf '%s\n' "$body" >"$path" )
	fi
	chmod +x "$path"
done
echo "installed pre-commit and pre-push leak checks in $hooks"
