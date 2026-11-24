#!/usr/bin/env bash
# Runs ON the operator VM. Builds shirudo's patched bpf-next kernel with the
# Azure fragment as Debian packages, using upstream's own build script:
#
#   1. copy testing/kernel/ to testing/kernel-azure/ in the shirudo checkout
#   2. append kernel/azure.conf to its x86-64 fragment
#   3. run build-kernel.sh, which fetches the pinned bpf-next commit, applies
#      shirudo's carried patches, verifies every fragment symbol in the final
#      .config and runs `make bindeb-pkg`
#
#   build-kernel.sh <path-to-azure.conf> [--config-only]
set -euo pipefail

AZURE_CONF="${1:?usage: build-kernel.sh <azure.conf> [--config-only]}"; shift
[[ $# == 0 || ( $# == 1 && "$1" == --config-only ) ]] || exit 2
SHIRUDO_DIR="$HOME/shirudo"
OUT="$HOME/build/azure-kernel"
here="$(cd "$(dirname "$0")/.." && pwd)"
[[ "$(git -C "$SHIRUDO_DIR" rev-parse HEAD)" == "$(cat "$here/patches/shirudo/BASE")" ]]
mkdir -p "$HOME/build"
mkdir -m 0700 "$OUT"  # A fresh build, never clean an arbitrary existing output.

work="$(mktemp -d "$SHIRUDO_DIR/testing/kernel-azure.XXXXXXXX")"
cp -a "$SHIRUDO_DIR/testing/kernel/." "$work/"
{
	echo
	echo "# ---- Azure (Hyper-V Gen2) additions from shirudo-on-azure ----"
	cat "$AZURE_CONF"
} >>"$work/kernel-ci.x86-64.conf"

"$work/build-kernel.sh" --arch x86-64 --llvm 23 --jobs "$(nproc)" --out "$OUT" "$@"

if [[ $# == 0 ]]; then
	shopt -s nullglob
	dirs=("$OUT"/pkgs/x86-64/*/)
	[[ ${#dirs[@]} == 1 && -s "${dirs[0]}BUILD-INFO" ]]
	ln -s "${dirs[0]}" "$OUT/latest"
	echo "kernel packages: $OUT/latest"
fi
