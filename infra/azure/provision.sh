#!/usr/bin/env bash
# Historical entry point. With no arguments this now prints a plan, not a bill.
set -eu
case "${1:-}" in
	""|plan|create|rollback) exec python3 "$(dirname "$0")/lab.py" "$@" ;;
	*) echo 'usage: provision.sh [plan | create --spend | rollback --delete-owned]' >&2; exit 2 ;;
esac
