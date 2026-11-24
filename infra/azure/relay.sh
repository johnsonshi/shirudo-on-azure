#!/usr/bin/env bash
# Stream a directory from the operator VM to the target VM through this
# workstation (the operator holds no key for the target, by design).
#   relay.sh <operator-dir> <target-dir>
set -euo pipefail
source "$(dirname "$0")/env.sh"
src="${1:?operator dir}"; dst="${2:?target dir}"
on_target "rm -rf '$dst' && mkdir -p '$dst'"
on_operator "tar -C '$src' -cf - ." | on_target "tar -C '$dst' -xf -"
on_target "ls -la '$dst' | tail -n +2"
