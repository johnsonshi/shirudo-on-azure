#!/usr/bin/env bash
# Build the upstream operator and target (including `shirudo init`) for this kernel.
set -euo pipefail
[[ $# == 0 ]] || exit 2
here="$(cd "$(dirname "$0")/../.." && pwd)"
base="$(cat "$here/patches/shirudo/BASE")"
[[ "$base" =~ ^[a-f0-9]{40}$ && "$(git -C "$HOME/shirudo" rev-parse HEAD)" == "$base" ]]
shopt -s nullglob
btf=("$HOME"/build/azure-kernel/latest/vmlinux-*.btf)
[[ ${#btf[@]} == 1 && -s "${btf[0]}" ]] || { echo 'expected one Azure kernel BTF' >&2; exit 1; }
export BPF_VMLINUX_BTF="${btf[0]}"

out="$HOME/build/shirudo"
mkdir -m 0700 "$out"  # Do not overwrite packages from a previous build.
src="$out/src"
git -C "$HOME/shirudo" worktree add -q --no-checkout --detach "$src" "$base"
git -C "$src" sparse-checkout set --no-cone --stdin <"$here/infra/operator/runtime.paths"
git -C "$src" checkout -q --detach "$base"
git -C "$src" -c user.name=Shirudo -c user.email=shirudo@users.noreply.github.com \
	am "$here"/patches/shirudo/0001-*.patch "$here"/patches/shirudo/0002-*.patch
rm -f "$src/vendor/linux/vmlinux.h"

make -C "$src/packaging" -j"$(nproc)" bindeb-pkg \
	DEB_TARGET_PKG="$out/target.deb" DEB_OPERATOR_PKG="$out/operator.deb" \
	'PKG_MAINTAINER=Shirudo lab <shirudo@users.noreply.github.com>' >"$out/build.log" 2>&1 ||
	{ echo 'packaging failed; inspect ~/build/shirudo/build.log on the operator' >&2; exit 1; }
[[ "$(dpkg-deb -f "$out/target.deb" Package)" == shirudo-target ]]
[[ "$(dpkg-deb -f "$out/operator.deb" Package)" == shirudo-operator ]]
sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$out/operator.deb"
sudo setcap cap_ipc_lock+ep /usr/bin/shirudo
sudo setcap cap_ipc_lock+ep /usr/libexec/shirudo/shirudo-build
/usr/bin/shirudo version
