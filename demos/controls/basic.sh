#!/bin/sh
exec python3 -I "$(dirname "$0")/present.py" basic "$@"
