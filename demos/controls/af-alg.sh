#!/bin/sh
exec python3 -I "$(dirname "$0")/present.py" cve-2026-31431-af-alg-block "$@"
