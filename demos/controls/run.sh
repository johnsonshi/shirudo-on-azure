#!/usr/bin/env bash
# Azure RBAC only. No SSH, resource creation, package installs or .env sourcing.
set -euo pipefail
exec python3 -I "$(dirname "$0")/azure.py" "$@"
