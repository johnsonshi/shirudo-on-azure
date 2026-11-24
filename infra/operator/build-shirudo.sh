#!/usr/bin/env bash
# Runs ON the operator VM. Builds shirudo with this repository's patches as
# the two deb packages: shirudo-operator (the CLI, the shirudo-build signing
# helper and the image generators) and shirudo-target (the static target
# binary, its systemd units, shirudo-gen-initrd and the dracut module).
# Installs the operator package on this VM.
#
#   build-shirudo.sh [<kernel-btf>]
#
# <kernel-btf> is the BTF of the kernel the target boots (vmlinux-*.btf from
# kernel/build-kernel.sh). Without it the build uses the BTF of shirudo's
# pinned CI kernel, which carries the same signed-loader ABI.
set -euo pipefail

BTF="${1:-}"
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
SHIRUDO_DIR="${SHIRUDO_DIR:-$HOME/shirudo}"
OUT="${SHIRUDO_OUT:-$HOME/build/shirudo}"
BASE="$(cat "$HERE/patches/shirudo/BASE")"

log() { printf '[build-shirudo] %s\n' "$*" >&2; }
cd "$SHIRUDO_DIR"

log "checkout $BASE + $(ls "$HERE"/patches/shirudo/*.patch | wc -l) patch(es)"
git am --abort >/dev/null 2>&1 || true
git checkout -q -f -B azure "$BASE"
git -c user.name=shirudo-on-azure -c user.email=build@shirudo-on-azure.invalid \
	am -q "$HERE"/patches/shirudo/*.patch

rm -f vendor/linux/vmlinux.h
if [[ -n "$BTF" ]]; then
	export BPF_VMLINUX_BTF="$BTF"
	log "kernel BTF: $BTF"
else
	[[ -s artifacts/bpf-next-kernel-debs/vmlinux.btf ]] || VM=0 testing/vm/kernel-artifact.sh fetch
	log "kernel BTF: shirudo's pinned CI kernel"
fi

log "make -C packaging bindeb-pkg"
mkdir -p "$HOME/logs"
make -C packaging bindeb-pkg -j"$(nproc)" >"$HOME/logs/shirudo-packaging.log" 2>&1 ||
	{ tail -40 "$HOME/logs/shirudo-packaging.log"; log "packaging failed"; exit 1; }
mapfile -t debs < <(sed -n 's/^shirudo: wrote //p' "$HOME/logs/shirudo-packaging.log" | tr ' ' '\n' | grep '\.deb$')
[[ ${#debs[@]} -eq 2 ]] || { log "expected two debs, see ~/logs/shirudo-packaging.log"; exit 1; }

rm -rf "$OUT" && mkdir -p "$OUT"
cp "${debs[@]}" "$OUT/"
git rev-parse HEAD >"$OUT/COMMIT"
echo "${BTF:-ci-kernel}" >"$OUT/BTF"

log "installing the operator package here"
sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --reinstall "$OUT"/shirudo-operator_*.deb >/dev/null
# The binaries lock their memory; let the operator user run them.
sudo setcap cap_ipc_lock+ep /usr/bin/shirudo
sudo setcap cap_ipc_lock+ep /usr/libexec/shirudo/shirudo-build
shirudo version
ls -l "$OUT"
