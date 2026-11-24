#!/usr/bin/env bash
# No source or destination directory arguments: only the fixed signed boot handoff.
set -eu
exec python3 "$(dirname "$0")/lab.py" relay "$@"
