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
SHIRUDO_DIR="${SHIRUDO_DIR:-$HOME/shirudo}"
OUT="${KERNEL_OUT:-$HOME/build/azure-kernel}"

work="$SHIRUDO_DIR/testing/kernel-azure"
rm -rf "$work"
cp -a "$SHIRUDO_DIR/testing/kernel" "$work"
{
	echo
	echo "# ---- Azure (Hyper-V Gen2) additions from shirudo-on-azure ----"
	cat "$AZURE_CONF"
} >>"$work/kernel-ci.x86-64.conf"

mkdir -p "$OUT"
"$work/build-kernel.sh" --arch x86-64 --llvm 23 --jobs "$(nproc)" --out "$OUT" "$@"

if [[ " $* " != *" --config-only "* ]]; then
	pkgdir="$(ls -1dt "$OUT"/pkgs/x86-64/*/ | head -1)"
	echo "profile=azure (kernel-ci + azure.conf)" >>"$pkgdir/BUILD-INFO"
	ln -sfn "$pkgdir" "$OUT/latest"
	echo "kernel packages: $pkgdir"
fi
